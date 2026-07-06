/**
 * Ingest write-path abstraction.
 *
 * The OSV/KEV/EPSS READ + TRANSFORM logic (zip streaming, record shaping
 * in osv-batch.ts::bufferRecord) is DB-agnostic. Only the WRITE path
 * differs between targets:
 *   - Postgres (production, via `pg` Pool + drizzle) — see PgIngestSink.
 *   - SQLite (Cloudflare D1 migration, via better-sqlite3) — see
 *     SqliteIngestSink in ./sink-sqlite.ts.
 *
 * `IngestSink` is the minimal surface the shared ingest core needs:
 * get-or-create a package id, and flush each buffered child-table batch
 * with the correct ON CONFLICT upsert semantics. Both implementations
 * preserve the exact conflict targets + COALESCE-on-conflict behaviour
 * the Postgres path always had, so switching sinks does NOT change the
 * shape of the data written.
 */

// ─── Row shapes handed to the sink ───────────────────────────────────────────
// These mirror the buffer row shapes in osv-batch.ts but with primitives
// only (no Date objects on the SQLite side — the sink serializes as it
// sees fit). Dates arrive as Date | null; each sink stores them in its
// native format (Postgres timestamptz vs. SQLite ISO-8601 TEXT).

export type VulnRow = {
  cveId: string;
  sourceId: string;
  summary: string | null;
  description: string | null;
  publishedAt: Date | null;
  modifiedAt: Date | null;
};
export type CvssRow = {
  cveId: string;
  version: string;
  vector: string;
  baseScore: string | null;
  severity: string | null;
};
export type AffectedRow = {
  cveId: string;
  packageId: number;
  ecosystem: string;
  rangesJson: unknown;
  versionsJson: unknown;
  sourceId: string;
};
export type RefRow = { cveId: string; url: string; type: string | null };
export type AliasRow = { cveId: string; alias: string; source: string };

/**
 * The write surface the shared OSV ingest core targets. Implementations
 * must apply the same upsert semantics the Postgres path documents:
 *   - vulns: ON CONFLICT (cve_id) DO UPDATE with COALESCE-preserving
 *     fields (see PgIngestSink for the canonical set).
 *   - cvss:  ON CONFLICT (cve_id, version, source) DO NOTHING.
 *   - affected: ON CONFLICT (cve_id, package_id, source_id) DO NOTHING.
 *   - refs: ON CONFLICT (cve_id, url) DO NOTHING.
 *   - aliases: ON CONFLICT (alias) DO NOTHING.
 *
 * All flush methods receive pre-deduped, pre-sliced batches (the core
 * handles chunking + in-buffer dedup) and may write them in one shot.
 */
export interface IngestSink {
  /**
   * Get-or-create a package row and return its id. `eco` is the canonical
   * ecosystem; `name` is already normalized (PyPI names lowercased by the
   * caller). Implementations cache via ctx.pkgCache upstream, so this is
   * only called on cache misses.
   */
  getOrCreatePackageId(eco: string, name: string): Promise<number>;

  flushVulns(rows: VulnRow[]): Promise<void>;
  flushCvss(rows: CvssRow[]): Promise<void>;
  flushAffected(rows: AffectedRow[]): Promise<void>;
  flushRefs(rows: RefRow[]): Promise<void>;
  flushAliases(rows: AliasRow[]): Promise<void>;
}
