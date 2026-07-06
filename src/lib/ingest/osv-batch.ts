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
import pLimit from "p-limit";
import yauzl from "yauzl";

import {
  osvRecordSchema,
  pickCveAlias,
  normalizePypiName,
  refTypeFromOsv,
  severityFromScore,
  type OsvRecord,
} from "@/lib/osv";
import { baseScoreFromVector } from "@/lib/cvss";
import type {
  IngestSink,
  VulnRow,
  CvssRow,
  AffectedRow,
  RefRow,
  AliasRow,
} from "./sink";

export type { IngestSink } from "./sink";

// Inlined to avoid importing from scripts/ingest/_shared (which runs
// loadEnv() at module-load — fine in CLI, unwanted in server runtime).
function parseDate(s: string | undefined | null): Date | null {
  if (!s) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

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
// (per-INSERT batch size lives in the sink now — the sink owns any
// per-statement slicing needed by its backing store.)
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
  sink: IngestSink,
): Promise<number> {
  const normName = ctx.eco === "PyPI" ? normalizePypiName(name) : name;
  const cacheKey = `${ctx.eco}:${normName}`;
  const cached = ctx.pkgCache.get(cacheKey);
  if (cached) return cached;
  const id = await sink.getOrCreatePackageId(ctx.eco, normName);
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
  sink: IngestSink,
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
    const pkgId = await getOrCreatePackageId(ctx, a.package.name, sink);
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

/**
 * Flushes all buffer rows. Vulnerabilities first (child tables FK to
 * cveId), then cvss / affected / refs / aliases in parallel.
 *
 * The per-table upsert semantics + INSERT batching live in the sink
 * (sink-sqlite.ts for the SQLite/D1 build); this function only
 * sequences the write order.
 */
export async function flush(buf: Buffers, sink: IngestSink) {
  if (buf.vulns.length) await sink.flushVulns(buf.vulns);
  await Promise.all([
    buf.cvss.length ? sink.flushCvss(buf.cvss) : Promise.resolve(),
    buf.affected.length ? sink.flushAffected(buf.affected) : Promise.resolve(),
    buf.refs.length ? sink.flushRefs(buf.refs) : Promise.resolve(),
    buf.aliases.length ? sink.flushAliases(buf.aliases) : Promise.resolve(),
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
  /**
   * Write target. PgIngestSink (production) or SqliteIngestSink (the D1
   * migration build). The record→row shaping above is sink-agnostic.
   */
  sink: IngestSink;
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
  /**
   * Optional set of PRIMARY ids (OSV record ids = zip entry filename stems,
   * e.g. "GHSA-52v5-jr5w-gjxr") to ingest. When present, any zip entry whose
   * primary id is NOT in the set is skipped BEFORE inflate — this is how the
   * incremental build ingests only changed records. When absent, every entry
   * is processed (full-build behaviour, unchanged).
   */
  idFilter?: Set<string>;
}

// ─── yauzl helpers ───────────────────────────────────────────────────────────

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
 * Open a zip with yauzl in lazyEntries mode. The caller pulls one
 * entry at a time via readEntry() and we only inflate that entry's
 * payload when readEntryStream() is called. This is the critical
 * difference vs. unzipper.Parse(): unzipper is push-based and keeps
 * inflating into an unbounded internal buffer regardless of how fast
 * the consumer reads, which caused 1.5GB RSS on osv:npm (we observed
 * "chunk=20 processed=1000 rss=1481MB" in production at 2026-06-08).
 *
 * yauzl with lazyEntries is pull-based: zero inflate work happens
 * until we call readEntry(), so RSS stays bounded by whatever the
 * consumer has currently in flight.
 */
function openZip(zipPath: string): Promise<yauzl.ZipFile> {
  return new Promise((resolve, reject) => {
    yauzl.open(zipPath, { lazyEntries: true }, (err, zip) => {
      if (err || !zip) reject(err ?? new Error("yauzl.open returned no zip"));
      else resolve(zip);
    });
  });
}

/** Promise wrapper for one readEntry() pull. Resolves with the entry,
 *  or null when the central directory ends. */
function nextEntry(zip: yauzl.ZipFile): Promise<yauzl.Entry | null> {
  return new Promise((resolve, reject) => {
    const onEntry = (entry: yauzl.Entry) => {
      cleanup();
      resolve(entry);
    };
    const onEnd = () => {
      cleanup();
      resolve(null);
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const cleanup = () => {
      zip.removeListener("entry", onEntry);
      zip.removeListener("end", onEnd);
      zip.removeListener("error", onError);
    };
    zip.once("entry", onEntry);
    zip.once("end", onEnd);
    zip.once("error", onError);
    zip.readEntry();
  });
}

/** Read one entry's inflated payload to a UTF-8 string. The read
 *  stream is opened on demand — this is where the actual inflate
 *  work happens. */
function readEntryToString(zip: yauzl.ZipFile, entry: yauzl.Entry): Promise<string> {
  return new Promise((resolve, reject) => {
    zip.openReadStream(entry, (err, stream) => {
      if (err || !stream) {
        reject(err ?? new Error("openReadStream returned no stream"));
        return;
      }
      const chunks: Buffer[] = [];
      stream.on("data", (c: Buffer) => chunks.push(c));
      stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      stream.on("error", reject);
    });
  });
}

/** Directory entries in zip have names ending with "/". */
function isDirectoryEntry(entry: yauzl.Entry): boolean {
  return /\/$/.test(entry.fileName);
}

/**
 * Streams entries directly out of an OSV bulk-download zip via yauzl
 * in `lazyEntries: true` mode (pull-based central-directory walker),
 * parses each *.json record, and writes via per-chunk multi-row INSERTs.
 *
 * Pull-based critical: we call readEntry() once per consumed entry,
 * so zero inflate work happens ahead of the consumer. This is the
 * fix for the 1.5GB RSS we saw on osv:npm with unzipper.Parse(),
 * whose push-based Transform stream buffered inflated payloads
 * unboundedly when processChunk was awaiting INSERTs.
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
  const { ctx, zipPath, sink, signal, onChunk, classifyAlias, log, idFilter } = opts;
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
            const cveId = await bufferRecord(ctx, buf, rec, sink);
            if (!cveId) return;
            imported++;
            for (const alias of collectAliases(rec, cveId)) {
              pushAlias(buf, cveId, alias, classifyAlias(alias));
            }
          } catch {
            /* per-record errors swallowed; aggregate metrics via callback */
          } finally {
            processed++;
            // Yield after every record. JSON.parse + zod + bufferRecord is
            // ~10-40ms of synchronous CPU; without this yield, 50 records
            // back-to-back blocked the event loop for 1-3s and Fly's 5s
            // health check started failing mid-ingest (observed
            // 2026-06-08 02:42-02:45 UTC — proxy returned "no good
            // candidate" for every region). PARSE_CONCURRENCY=2 means
            // at most 2 records of work between yields → HTTP traffic
            // and health checks get a turn within ~80ms regardless of
            // chunk size.
            await new Promise((r) => setImmediate(r));
          }
        }),
      ),
    );
    if (buf.vulns.length || buf.aliases.length) {
      await flush(buf, sink);
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

  const zip = await openZip(zipPath);

  try {
    while (true) {
      const entry = await nextEntry(zip);
      if (entry === null) break;
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

      if (isDirectoryEntry(entry)) {
        skipped++;
        continue;
      }
      if (skipByName(entry.fileName)) {
        // With lazyEntries we never opened the entry's read stream,
        // so there's nothing to drain — the next readEntry() simply
        // walks past it in the central directory. This is the big
        // win over unzipper, which was inflating MAL-* payloads
        // (110k+ on npm) into its internal buffer regardless.
        skipped++;
        continue;
      }
      if (idFilter) {
        // entry.fileName is "<PRIMARY-ID>.json" (possibly path-prefixed).
        const base = entry.fileName.replace(/^.*\//, "").replace(/\.json$/i, "");
        if (!idFilter.has(base)) {
          skipped++;
          continue;
        }
      }
      if (!loggedFirstEntryPath) {
        loggedFirstEntryPath = true;
        logFn(`[osv:${ctx.eco}] entry-path-sample=${entry.fileName}`);
      }
      const content = await readEntryToString(zip, entry);
      pending.push({ name: entry.fileName, content });
      if (pending.length >= PARSE_CHUNK) {
        const slice = pending;
        pending = [];
        await processChunk(slice);
      }
    }
    if (pending.length > 0) await processChunk(pending);
  } finally {
    zip.close();
  }

  logFn(
    `[osv:${ctx.eco}] done totalSeen=${totalSeen} skipped=${skipped} processed=${processed} imported=${imported}`,
  );
  return { processed, imported };
}

