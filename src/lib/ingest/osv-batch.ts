/**
 * Shared OSV ingest streaming core.
 *
 * Single source of truth for the OSV opendir → parse → flush loop +
 * row-shaping + multi-VALUES INSERT logic. Imported by both the
 * scheduler-driven library version (src/lib/ingest/osv.ts) and the ops
 * CLI (scripts/ingest/osv.ts) so the two never drift.
 *
 * Streaming model: each parse chunk (~50 records) builds its own fresh
 * Buffers, flushes once, then drops it for GC and yields the event loop.
 * NEVER aggregate across chunks. Earlier attempts at "buffer 1000 records
 * then flush" starved Node's event loop during npm ingest — drizzle's
 * 1000-row INSERT serialization is CPU-bound and bunched all the work
 * into spike windows that blocked web SSR and Fly health checks.
 *
 * Each chunk does one multi-row INSERT per child table (vulns first
 * because everything else FK to cveId, then cvss/affected/refs/aliases
 * in parallel). Wire cost per statement is ~1-5ms over Fly internal
 * network — total ingest stays well under the per-source budget while
 * leaving the event loop responsive.
 *
 * In-buffer dedup is required because Postgres can't deduplicate within
 * a single statement — same (cveId, version, source) appearing twice in
 * one INSERT fails the conflict target. The five `*Seen` maps/sets are
 * keyed on each table's UNIQUE constraint; per-chunk scope means windows
 * are at most one chunk wide (cross-chunk dups resolved server-side via
 * ON CONFLICT DO NOTHING / DO UPDATE).
 *
 * Zip reading uses unzipper.Parse() — a sequential local-file-header
 * walker over the zip byte stream. Earlier we tried yauzl (v34) with
 * lazyEntries; the per-entry random-access seek + callback round-trip
 * gave ~16 records/sec on Fly shared CPU. unzipper's pure sequential
 * inflate is the right shape for the "iterate every entry of a bulk
 * dump" job; the npm zip's 220k entries are continguous in disk order.
 *
 * MAL-* entries (OpenSSF malicious-package reports) get filtered at
 * the zip layer — they never carry CVE aliases and bufferRecord would
 * skip them anyway; we save the inflate + parse + zod cost.
 */
import { sql } from "drizzle-orm";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import type { Pool } from "pg";
import pLimit from "p-limit";
import { createReadStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import unzipper from "unzipper";

import {
  vulnerabilities,
  cvssScores,
  packages,
  affected,
  refs,
  vulnAliases,
} from "@/db/schema";
import * as schema from "@/db/schema";
import {
  osvRecordSchema,
  pickCveAlias,
  normalizePypiName,
  refTypeFromOsv,
  severityFromScore,
  type OsvRecord,
} from "@/lib/osv";
import { baseScoreFromVector } from "@/lib/cvss";

// Inlined to avoid importing from scripts/ingest/_shared (which runs
// loadEnv() at module-load — fine in CLI, unwanted in server runtime).
function parseDate(s: string | undefined | null): Date | null {
  if (!s) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

export type IngestDb = NodePgDatabase<typeof schema>;
export type IngestPool = Pool;

// ─── Row shapes ──────────────────────────────────────────────────────────────

type VulnRow = {
  cveId: string;
  sourceId: string;
  summary: string | null;
  description: string | null;
  publishedAt: Date | null;
  modifiedAt: Date | null;
};
type CvssRow = {
  cveId: string;
  version: string;
  vector: string;
  baseScore: string | null;
  severity: string | null;
};
type AffectedRow = {
  cveId: string;
  packageId: number;
  ecosystem: string;
  rangesJson: unknown;
  versionsJson: unknown;
  sourceId: string;
};
type RefRow = { cveId: string; url: string; type: string | null };
type AliasRow = { cveId: string; alias: string; source: string };

export interface Buffers {
  vulns: VulnRow[];
  cvss: CvssRow[];
  affected: AffectedRow[];
  refs: RefRow[];
  aliases: AliasRow[];
  vulnSeen: Map<string, number>;
  cvssSeen: Set<string>;
  affectedSeen: Set<string>;
  refsSeen: Set<string>;
  // Aliases dedupe by alias alone — the table has a UNIQUE on alias
  // (uq_vuln_aliases_alias) that's stricter than the (cveId, alias) PK,
  // so an alias seen on any CVE in this buffer must not be inserted
  // again for any other.
  aliasSeen: Set<string>;
  recordsBuffered: number; // count of records that contributed
}

export function emptyBuffers(): Buffers {
  return {
    vulns: [],
    cvss: [],
    affected: [],
    refs: [],
    aliases: [],
    vulnSeen: new Map(),
    cvssSeen: new Set(),
    affectedSeen: new Set(),
    refsSeen: new Set(),
    aliasSeen: new Set(),
    recordsBuffered: 0,
  };
}

export interface UpsertCtx {
  eco: string; // canonical, e.g. "npm" / "Debian"
  ecoMatch: (recordEco: string) => boolean;
  pkgCache: Map<string, number>;
}

// ─── Shared constants ────────────────────────────────────────────────────────

// Parse and flush together: one chunk lifecycle is one flush. Keeping
// these small bounds peak event-loop occupancy per chunk so web SSR
// and Fly health checks don't get starved during ingest.
const PARSE_CHUNK = 50;
const PARSE_CONCURRENCY = 2;
const FLUSH_INSERT_BATCH = 1000; // rows per single INSERT statement (per child table)
const PKG_CACHE_HIGH_WATER = 50_000;
const RSS_LOG_EVERY_N_CHUNKS = 20;

function cvssVersionLabel(type: string): string {
  if (type === "CVSS_V2") return "2.0";
  if (type === "CVSS_V3") return "3.1"; // OSV doesn't distinguish 3.0 vs 3.1
  if (type === "CVSS_V4") return "4.0";
  return type;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

export async function getOrCreatePackageId(
  ctx: UpsertCtx,
  name: string,
  db: IngestDb,
  pool: IngestPool,
): Promise<number> {
  const normName = ctx.eco === "PyPI" ? normalizePypiName(name) : name;
  const cacheKey = `${ctx.eco}:${normName}`;
  const cached = ctx.pkgCache.get(cacheKey);
  if (cached) return cached;
  const inserted = await db
    .insert(packages)
    .values({ ecosystem: ctx.eco, name: normName })
    .onConflictDoNothing({ target: [packages.ecosystem, packages.name] })
    .returning({ id: packages.id });
  let id: number;
  if (inserted.length > 0) {
    id = inserted[0].id;
  } else {
    const { rows } = await pool.query(
      "SELECT id FROM packages WHERE ecosystem=$1 AND name=$2",
      [ctx.eco, normName],
    );
    id = rows[0].id as number;
  }
  ctx.pkgCache.set(cacheKey, id);
  return id;
}

export function maybeTrimPkgCache(ctx: UpsertCtx) {
  if (ctx.pkgCache.size > PKG_CACHE_HIGH_WATER) ctx.pkgCache.clear();
}

// ─── Record → buffer ─────────────────────────────────────────────────────────

/**
 * Adds a parsed OSV record's rows to the buffer.
 * Returns the resolved CVE id (so the caller can also push aliases
 * keyed on the same cveId), or null if the record has no CVE alias
 * we can map to.
 */
export async function bufferRecord(
  ctx: UpsertCtx,
  buf: Buffers,
  rec: OsvRecord,
  db: IngestDb,
  pool: IngestPool,
): Promise<string | null> {
  const cveId = pickCveAlias(rec);
  if (!cveId) return null;

  const publishedAt = parseDate(rec.published);
  const modifiedAt = parseDate(rec.modified);

  // If the same CVE appears twice in one buffer, later writes win for
  // non-null fields (matches the row-by-row COALESCE-on-conflict path).
  const existingIdx = buf.vulnSeen.get(cveId);
  const newVuln: VulnRow = {
    cveId,
    sourceId: rec.id,
    summary: rec.summary ?? null,
    description: rec.details ?? null,
    publishedAt,
    modifiedAt,
  };
  if (existingIdx !== undefined) {
    buf.vulns[existingIdx] = newVuln;
  } else {
    buf.vulnSeen.set(cveId, buf.vulns.length);
    buf.vulns.push(newVuln);
  }

  const allSeverities = [
    ...(rec.severity ?? []),
    ...((rec.affected ?? []).flatMap((a) => a.severity ?? [])),
  ];
  // (cveId, version) within this record — earlier vector wins to match
  // the row-by-row path's first-seen behaviour.
  const seenInRec = new Set<string>();
  for (const s of allSeverities) {
    const ver = cvssVersionLabel(s.type);
    const inRecKey = `${cveId}|${ver}`;
    if (seenInRec.has(inRecKey)) continue;
    seenInRec.add(inRecKey);
    const dedupeKey = `${cveId}|${ver}|osv`;
    if (buf.cvssSeen.has(dedupeKey)) continue;
    buf.cvssSeen.add(dedupeKey);
    const base = baseScoreFromVector(s.score);
    buf.cvss.push({
      cveId,
      version: ver,
      vector: s.score,
      baseScore: base !== null ? String(base) : null,
      severity: severityFromScore(base),
    });
  }

  for (const a of rec.affected ?? []) {
    if (!ctx.ecoMatch(a.package.ecosystem)) continue;
    const pkgId = await getOrCreatePackageId(ctx, a.package.name, db, pool);
    const dedupeKey = `${cveId}|${pkgId}|${rec.id}`;
    if (buf.affectedSeen.has(dedupeKey)) continue;
    buf.affectedSeen.add(dedupeKey);
    buf.affected.push({
      cveId,
      packageId: pkgId,
      ecosystem: ctx.eco,
      rangesJson: a.ranges ?? [],
      versionsJson: a.versions ?? null,
      sourceId: rec.id,
    });
  }

  for (const r of rec.references ?? []) {
    const dedupeKey = `${cveId}|${r.url}`;
    if (buf.refsSeen.has(dedupeKey)) continue;
    buf.refsSeen.add(dedupeKey);
    buf.refs.push({ cveId, url: r.url, type: refTypeFromOsv(r.type) });
  }
  buf.recordsBuffered++;
  return cveId;
}

/**
 * Push a non-CVE alias (GHSA-..., DSA-..., etc.) into the buffer.
 * Caller decides which aliases to push — typically every non-CVE
 * identifier from `aliases` / `upstream` / `related` / `id`.
 *
 * Dedup keyed on `alias` alone (matching the table's UNIQUE constraint),
 * so the same alias seen on a second CVE within one buffer is silently
 * dropped. OSV occasionally has cross-CVE alias conflicts; first-seen
 * wins, matching the row-by-row ON CONFLICT DO NOTHING path.
 */
export function pushAlias(
  buf: Buffers,
  cveId: string,
  alias: string,
  source: string,
) {
  if (buf.aliasSeen.has(alias)) return;
  buf.aliasSeen.add(alias);
  buf.aliases.push({ cveId, alias, source });
}

// ─── Flush buffers ───────────────────────────────────────────────────────────

async function flushVulns(rows: VulnRow[], db: IngestDb) {
  for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
    const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
    await db
      .insert(vulnerabilities)
      .values(slice)
      .onConflictDoUpdate({
        target: vulnerabilities.cveId,
        set: {
          sourceId: sql`EXCLUDED.source_id`,
          summary: sql`COALESCE(EXCLUDED.summary, ${vulnerabilities.summary})`,
          description: sql`COALESCE(EXCLUDED.description, ${vulnerabilities.description})`,
          publishedAt: sql`COALESCE(${vulnerabilities.publishedAt}, EXCLUDED.published_at)`,
          modifiedAt: sql`COALESCE(EXCLUDED.modified_at, ${vulnerabilities.modifiedAt})`,
        },
      });
  }
}

async function flushCvss(rows: CvssRow[], db: IngestDb) {
  for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
    const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
    await db
      .insert(cvssScores)
      .values(slice.map((r) => ({ ...r, source: "osv" })))
      .onConflictDoNothing({
        target: [cvssScores.cveId, cvssScores.version, cvssScores.source],
      });
  }
}

async function flushAffected(rows: AffectedRow[], db: IngestDb) {
  for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
    const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
    await db
      .insert(affected)
      .values(slice)
      .onConflictDoNothing({
        target: [affected.cveId, affected.packageId, affected.sourceId],
      });
  }
}

async function flushRefs(rows: RefRow[], db: IngestDb) {
  for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
    const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
    await db
      .insert(refs)
      .values(slice)
      .onConflictDoNothing({ target: [refs.cveId, refs.url] });
  }
}

async function flushAliases(rows: AliasRow[], db: IngestDb) {
  for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
    const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
    // The table has TWO unique constraints: (cveId, alias) PK +
    // (alias) UNIQUE. Conflict target is `alias` because the alias-only
    // collision is the broader one — a CVE/alias pair that exists is
    // also covered by the alias-uniqueness skip.
    await db
      .insert(vulnAliases)
      .values(slice)
      .onConflictDoNothing({ target: [vulnAliases.alias] });
  }
}

/**
 * Flushes all buffer rows. Vulnerabilities first (child tables FK to
 * cveId), then cvss / affected / refs / aliases in parallel.
 */
export async function flush(buf: Buffers, db: IngestDb) {
  if (buf.vulns.length) await flushVulns(buf.vulns, db);
  await Promise.all([
    buf.cvss.length ? flushCvss(buf.cvss, db) : Promise.resolve(),
    buf.affected.length ? flushAffected(buf.affected, db) : Promise.resolve(),
    buf.refs.length ? flushRefs(buf.refs, db) : Promise.resolve(),
    buf.aliases.length ? flushAliases(buf.aliases, db) : Promise.resolve(),
  ]);
}

// ─── Streaming driver ────────────────────────────────────────────────────────

/**
 * Extract every non-CVE identifier from `aliases` / `upstream` / `related`
 * plus the record id itself. Used by streamOsvDir to populate vulnAliases.
 */
function collectAliases(
  rec: { id?: string; aliases?: string[]; upstream?: string[]; related?: string[] },
  cveId: string,
): string[] {
  const out = new Set<string>();
  const isCve = (s: string) => /^CVE-\d{4}-\d+$/i.test(s);
  if (rec.id && !isCve(rec.id) && rec.id !== cveId) out.add(rec.id);
  for (const a of rec.aliases ?? []) if (a && !isCve(a) && a !== cveId) out.add(a);
  for (const u of rec.upstream ?? []) if (u && !isCve(u) && u !== cveId) out.add(u);
  for (const r of rec.related ?? []) if (r && !isCve(r) && r !== cveId) out.add(r);
  return [...out];
}

export interface StreamOsvOptions {
  ctx: UpsertCtx;
  /** Path to the OSV bulk-download zip file. */
  zipPath: string;
  db: IngestDb;
  pool: IngestPool;
  signal?: AbortSignal;
  /**
   * Called after each chunk completes its flush. Lets callers update
   * job.progress (library) or console-log (CLI). Stats are cumulative
   * across the run, not per-chunk.
   */
  onChunk?: (stats: { processed: number; imported: number; chunkIndex: number }) => void;
  /**
   * Maps a non-CVE identifier (GHSA-..., DSA-..., ALPINE-..., etc.) to
   * a short source tag. Injected so ecosystem-specific knowledge stays
   * at the call site and this module only handles row shapes + I/O.
   */
  classifyAlias: (alias: string) => string;
  /**
   * Optional progress logger. Defaults to noop. CLI uses console.log;
   * library uses console.log too (goes to fly logs).
   */
  log?: (msg: string) => void;
}

// ─── unzipper helpers ────────────────────────────────────────────────────────

/**
 * Match by basename so a directory prefix (e.g. "json/MAL-2024-1.json")
 * doesn't change behavior, and a path that happens to contain the
 * substring "MAL-" elsewhere (hypothetical "ANIMAL-foo.json") isn't
 * falsely dropped. OSV IDs always start at a path-segment boundary.
 *
 * MAL-* are OpenSSF malicious-package reports — they describe
 * malicious packages, not vulnerabilities, and never carry CVE
 * aliases. bufferRecord would skip them anyway; filtering here saves
 * the inflate + parse + zod cost (110k+ entries on npm).
 */
function skipByName(name: string): boolean {
  const basename = name.split("/").pop() ?? name;
  return basename.startsWith("MAL-");
}

/**
 * Drain an unzipper entry stream into a UTF-8 string. The entry must
 * be consumed (or autodrained) before the Parse stream emits the next
 * one — backpressure is built into the Transform.
 */
function readEntryToString(entry: unzipper.Entry): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    entry.on("data", (c: Buffer) => chunks.push(c));
    entry.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    entry.on("error", reject);
  });
}

/**
 * Streams entries directly out of an OSV bulk-download zip via
 * unzipper.Parse() (sequential local-file-header walker), parses each
 * *.json record, and writes via per-chunk multi-row INSERTs.
 *
 * One chunk = one Buffers allocation + one flush, dropped to GC and
 * setImmediate-yielded immediately after. Flat memory profile, keeps
 * the event loop responsive for web SSR and Fly health checks.
 *
 * MAL-* entries are filtered at the zip layer (basename startsWith
 * "MAL-") so we don't pay inflate + parse cost for records that
 * bufferRecord would skip anyway.
 *
 * Throws if `signal?.aborted` becomes true (checked every 500 entries
 * — chunk boundary is too coarse when 100k+ consecutive MAL-* entries
 * all hit the skip branch) or if the zip / fs layer surfaces an error.
 * Per-record errors (bad JSON, schema mismatch) are swallowed.
 */
export async function streamOsvZip(opts: StreamOsvOptions): Promise<{
  processed: number;
  imported: number;
}> {
  const { ctx, zipPath, db, pool, signal, onChunk, classifyAlias, log } = opts;
  const logFn = log ?? (() => {});

  let processed = 0;
  let imported = 0;
  let chunkIndex = 0;
  let totalSeen = 0;
  let skipped = 0;
  let loggedFirstEntryPath = false;
  type Pending = { name: string; content: string };
  let pending: Pending[] = [];

  const limit = pLimit(PARSE_CONCURRENCY);

  async function processChunk(items: Pending[]) {
    if (items.length === 0) return;
    if (signal?.aborted) throw new Error(`aborted: osv:${ctx.eco}`);

    const buf = emptyBuffers();
    await Promise.all(
      items.map((item) =>
        limit(async () => {
          try {
            const raw = JSON.parse(item.content);
            const parsed = osvRecordSchema.safeParse(raw);
            if (!parsed.success) return;
            const rec = parsed.data;
            const cveId = await bufferRecord(ctx, buf, rec, db, pool);
            if (!cveId) return;
            imported++;
            for (const alias of collectAliases(rec, cveId)) {
              pushAlias(buf, cveId, alias, classifyAlias(alias));
            }
          } catch {
            /* per-record errors swallowed; aggregate metrics via callback */
          } finally {
            processed++;
          }
        }),
      ),
    );
    if (buf.vulns.length || buf.aliases.length) {
      await flush(buf, db);
    }
    maybeTrimPkgCache(ctx);

    chunkIndex++;
    onChunk?.({ processed, imported, chunkIndex });

    if (chunkIndex % RSS_LOG_EVERY_N_CHUNKS === 0) {
      const rss = Math.round(process.memoryUsage().rss / 1024 / 1024);
      logFn(
        `[osv:${ctx.eco}] chunk=${chunkIndex} processed=${processed} imported=${imported} skipped=${skipped} rss=${rss}MB`,
      );
    }

    // Real event-loop yield. setImmediate runs after pending I/O
    // callbacks, so web SSR and health-check handlers get a turn.
    await new Promise((r) => setImmediate(r));
  }

  const fileStream = createReadStream(zipPath);
  const parseStream = unzipper.Parse({ forceStream: true });

  // pipeline() not pipe(): Node's stream .pipe() does not forward
  // error events from upstream to downstream. A read failure on
  // fileStream would leave parseStream orphaned and the for-await
  // would hang until orchestrator's 15-min timeout fired, masking the
  // real error as a "slow ingest" symptom.
  const pipelinePromise = pipeline(fileStream, parseStream);

  try {
    for await (const rawEntry of parseStream) {
      const entry = rawEntry as unzipper.Entry;
      totalSeen++;

      // Signal + setImmediate yield run on TOTAL entry count, NOT
      // chunk count. npm zip has 100k+ consecutive MAL-* entries that
      // all hit the skip branch — without this, an abort request
      // waits until the next non-skipped chunk lands, which could be
      // minutes away.
      if (totalSeen % 500 === 0) {
        if (signal?.aborted) throw new Error(`aborted: osv:${ctx.eco}`);
        await new Promise((r) => setImmediate(r));
      }

      if (entry.type !== "File") {
        await entry.autodrain().promise();
        skipped++;
        continue;
      }
      if (skipByName(entry.path)) {
        await entry.autodrain().promise();
        skipped++;
        continue;
      }
      if (!loggedFirstEntryPath) {
        loggedFirstEntryPath = true;
        logFn(`[osv:${ctx.eco}] entry-path-sample=${entry.path}`);
      }
      const content = await readEntryToString(entry);
      pending.push({ name: entry.path, content });
      if (pending.length >= PARSE_CHUNK) {
        const slice = pending;
        pending = [];
        await processChunk(slice);
      }
    }
    if (pending.length > 0) await processChunk(pending);
    await pipelinePromise; // surface any late pipeline error
  } catch (err) {
    // Destroy both streams so file handles release immediately.
    fileStream.destroy();
    parseStream.destroy();
    // pipelinePromise will reject with ERR_STREAM_PREMATURE_CLOSE now
    // that we destroyed the streams. Nothing is awaiting it on this
    // path; swallow to prevent an unhandled rejection that would
    // crash the Next.js process (Node 15+ default behavior).
    pipelinePromise.catch(() => {});
    throw err;
  }

  logFn(
    `[osv:${ctx.eco}] done totalSeen=${totalSeen} skipped=${skipped} processed=${processed} imported=${imported}`,
  );
  return { processed, imported };
}

