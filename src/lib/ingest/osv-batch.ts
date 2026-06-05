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
 * Future work: stream directly from the zip via yauzl/unzipper to drop
 * the `unzip → extract → opendir` chain. Non-trivial refactor; the
 * current shape is good enough for prod under the 1GB Fly VM.
 */
import { sql } from "drizzle-orm";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import type { Pool } from "pg";
import pLimit from "p-limit";
import yauzl from "yauzl";
import type { Entry, ZipFile } from "yauzl";

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

// ─── yauzl helpers ───────────────────────────────────────────────────────────

/**
 * Promisified yauzl.open.
 */
function openZip(path: string): Promise<ZipFile> {
  return new Promise((resolve, reject) => {
    yauzl.open(path, { lazyEntries: true }, (err, zip) => {
      if (err) return reject(err);
      if (!zip) return reject(new Error("yauzl returned no zip"));
      resolve(zip);
    });
  });
}

/**
 * Wraps a yauzl ZipFile (lazyEntries: true) as an async iterator that
 * yields one Entry at a time. `readEntry()` is called from exactly one
 * place — the `next()` advance below — so double-call hangs are
 * impossible by construction, not by discipline. Both success path
 * ("entry" event) and end path ("end" event) and error path ("error"
 * event) all resolve the same pending Promise; only consumer-side
 * `next()` triggers the next `readEntry()`.
 */
function entriesOf(zip: ZipFile): AsyncIterable<Entry> {
  type Pending = { kind: "entry"; entry: Entry } | { kind: "end" } | { kind: "err"; err: Error };
  let pendingResolver: ((p: Pending) => void) | null = null;
  let queued: Pending | null = null;

  function publish(p: Pending) {
    if (pendingResolver) {
      const r = pendingResolver;
      pendingResolver = null;
      r(p);
    } else {
      queued = p;
    }
  }

  zip.on("entry", (entry: Entry) => publish({ kind: "entry", entry }));
  zip.on("end", () => publish({ kind: "end" }));
  zip.on("error", (err: Error) => publish({ kind: "err", err }));

  return {
    [Symbol.asyncIterator]() {
      return {
        async next(): Promise<IteratorResult<Entry>> {
          // Pull next event. Trigger readEntry once per next() call —
          // single source of truth for the advance.
          const next = await new Promise<Pending>((resolve) => {
            if (queued) {
              const q = queued;
              queued = null;
              resolve(q);
              return;
            }
            pendingResolver = resolve;
            zip.readEntry();
          });
          if (next.kind === "end") return { done: true, value: undefined };
          if (next.kind === "err") throw next.err;
          return { done: false, value: next.entry };
        },
      };
    },
  };
}

/**
 * Drain a yauzl entry's read stream into a UTF-8 string. Each entry
 * stream must be fully consumed before the next entry can be requested
 * (yauzl is single-reader under lazyEntries).
 */
function readEntryContent(zip: ZipFile, entry: Entry): Promise<string> {
  return new Promise((resolve, reject) => {
    zip.openReadStream(entry, (err, stream) => {
      if (err) return reject(err);
      if (!stream) return reject(new Error(`openReadStream returned no stream for ${entry.fileName}`));
      const chunks: Buffer[] = [];
      stream.on("data", (c: Buffer) => chunks.push(c));
      stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      stream.on("error", reject);
    });
  });
}

function closeZip(zip: ZipFile): void {
  try {
    zip.close();
  } catch {
    /* ignore */
  }
}

/**
 * Streams entries directly out of an OSV bulk-download zip, parses
 * each *.json record, and writes via per-chunk multi-row INSERTs.
 *
 * One chunk = one Buffers allocation + one flush, dropped to GC and
 * setImmediate-yielded immediately after. Flat memory profile, keeps
 * the event loop responsive for web SSR and Fly health checks.
 *
 * No extraction to disk: yauzl decompresses each entry directly into
 * a memory buffer. Eliminates the 22-minute `unzip` stage that killed
 * npm ingest in v33.
 *
 * Throws if `signal?.aborted` becomes true at a chunk boundary or if
 * yauzl surfaces an error. Per-record errors (bad JSON, schema
 * mismatch) are swallowed.
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
      logFn(`[osv:${ctx.eco}] chunk=${chunkIndex} processed=${processed} imported=${imported} rss=${rss}MB`);
    }

    // Real event-loop yield. setImmediate runs after pending I/O
    // callbacks, so web SSR and health-check handlers get a turn.
    await new Promise((r) => setImmediate(r));
  }

  const zip = await openZip(zipPath);
  try {
    for await (const entry of entriesOf(zip)) {
      // Filter on fileName BEFORE opening a stream — we never want an
      // open stream we don't drain (yauzl is single-reader; an
      // abandoned stream wedges the iterator).
      if (!entry.fileName.endsWith(".json")) continue;
      const content = await readEntryContent(zip, entry);
      pending.push({ name: entry.fileName, content });
      if (pending.length >= PARSE_CHUNK) {
        const slice = pending;
        pending = [];
        await processChunk(slice);
      }
    }
    if (pending.length > 0) await processChunk(pending);
  } finally {
    closeZip(zip);
  }

  return { processed, imported };
}

