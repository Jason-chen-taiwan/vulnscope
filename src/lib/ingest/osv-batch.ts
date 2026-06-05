/**
 * Shared OSV ingest batch core.
 *
 * Single source of truth for the OSV row-shaping + multi-VALUES INSERT
 * logic. Imported by both the scheduler-driven library version
 * (src/lib/ingest/osv.ts) and the ops CLI (scripts/ingest/osv.ts) so the
 * two no longer drift.
 *
 * The two callers differ only in:
 *   - which pg pool / drizzle wrapper they pass in (web vs ingest)
 *   - whether they pipe in an AbortSignal for cooperative cancellation
 *   - what they do with progress / job tracking around the call
 *
 * Performance rationale: doing one INSERT per child row gave us ~2.2M
 * sequential round-trips for npm (220k records × ~10 child rows) and a
 * 40-minute run that fly's boot reaper killed. Buffering 1000 records
 * per chunk and flushing as multi-row INSERTs (max 1000 rows per
 * statement) drops that to ~1000 round-trips. Same upsert semantics —
 * vulnerabilities still COALESCEs to preserve KEV/EPSS, the three child
 * tables still ON CONFLICT DO NOTHING.
 *
 * In-buffer dedup is required because Postgres can't deduplicate within
 * a single statement — same (cveId, version, source) appearing twice in
 * one INSERT fails the conflict target. The four `*Seen` maps/sets are
 * keyed on each table's UNIQUE constraint.
 */
import { sql } from "drizzle-orm";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import type { Pool } from "pg";

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

export const CHUNK_RECORDS = 1000; // records per buffer flush
const FLUSH_INSERT_BATCH = 1000; // rows per single INSERT statement
const PKG_CACHE_HIGH_WATER = 50_000;

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
