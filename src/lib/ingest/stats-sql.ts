/**
 * SQL statement generators for the precomputed stats tables.
 *
 * Why these tables exist: the request path previously ran full-table
 * aggregations (COUNT(*) over 74k vulnerabilities, GROUP BY over 119k
 * affected rows) on every cold render, which overloaded D1
 * ("D1 DB is overloaded. Requests queued for too long.", 2026-07-06).
 * Data changes only at ingest, so aggregates are computed at ingest and
 * the request path reads them back with O(1)/indexed queries.
 *
 * Three contexts, three generators:
 *  - fullBuildStatsSql(): local full build — full scans are fine locally.
 *  - deltaStatsSql():     daily D1 delta — every statement bounded (Task 2).
 *  - rebuildAllStatsSql():one-time D1 backfill — sharded (Task 2).
 *
 * All functions return arrays of single SQL statements WITHOUT trailing
 * semicolons — callers append ';' and/or the '--@@STMT@@' sentinel.
 */

export function statsDdl(): string[] {
  return [
    `CREATE TABLE IF NOT EXISTS page_stats (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  vuln_total INTEGER NOT NULL DEFAULT 0,
  package_total INTEGER NOT NULL DEFAULT 0,
  critical_total INTEGER NOT NULL DEFAULT 0,
  kev_total INTEGER NOT NULL DEFAULT 0,
  computed_at TEXT
)`,
    `CREATE TABLE IF NOT EXISTS package_stats (
  package_id INTEGER PRIMARY KEY,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  cve_count INTEGER NOT NULL DEFAULT 0,
  kev_count INTEGER NOT NULL DEFAULT 0,
  max_epss REAL
)`,
    `CREATE INDEX IF NOT EXISTS idx_pkgstats_eco_rank
  ON package_stats(ecosystem, kev_count DESC, cve_count DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_pkgstats_rank
  ON package_stats(kev_count DESC, cve_count DESC)`,
  ];
}

/**
 * The one aggregation SELECT shared by every package_stats writer.
 * `fromClause` supplies the driving table(s); it must expose packages as
 * `p`, affected as `a`, vulnerabilities as `v`.
 */
const PACKAGE_STATS_SELECT = `SELECT p.id, p.ecosystem, p.name,
       COUNT(DISTINCT a.cve_id),
       COUNT(DISTINCT CASE WHEN v.kev = 1 THEN a.cve_id END),
       CAST(MAX(v.epss_score) AS REAL)`;

/** Local full build: full scans are fine on the build machine. */
export function fullBuildStatsSql(): string[] {
  return [
    `DELETE FROM package_stats`,
    `INSERT INTO package_stats (package_id, ecosystem, name, cve_count, kev_count, max_epss)
${PACKAGE_STATS_SELECT}
  FROM packages p
  JOIN affected a ON a.package_id = p.id
  JOIN vulnerabilities v ON v.cve_id = a.cve_id
 GROUP BY p.id, p.ecosystem, p.name`,
    `INSERT OR REPLACE INTO page_stats
  (id, vuln_total, package_total, critical_total, kev_total, computed_at)
SELECT 1,
  (SELECT COUNT(*) FROM vulnerabilities),
  (SELECT COUNT(*) FROM packages),
  (SELECT COUNT(*) FROM cvss_scores WHERE severity = 'CRITICAL'),
  (SELECT COUNT(*) FROM vulnerabilities WHERE kev = 1),
  datetime('now')`,
  ];
}

export interface StatsSqlOptions {
  /** First CVE year chunk (default 1999). */
  yearStart?: number;
  /** Exclusive upper year; the final chunk is open-ended `>= 'CVE-<this>-'`.
   *  Default: current UTC year + 1, so the current year is always a bounded
   *  chunk and anything newer lands in the open-ended tail. */
  yearEndExclusive?: number;
  /** packages id-range chunk size for page_stats.package_total (default 2000). */
  pkgIdStep?: number;
  /** Last bounded package id; final chunk is open-ended `>= this` (default 100000). */
  pkgIdMax?: number;
  /** package_stats rebuild id-range chunk size (default 1000). */
  rebuildStep?: number;
  /** _delta_cves manifest ids per INSERT statement (default 200). */
  idsPerInsert?: number;
  /** Modulo shards for the touched-package recompute (default 8). */
  recomputeShards?: number;
}

function resolveOpts(opts?: StatsSqlOptions): Required<StatsSqlOptions> {
  return {
    yearStart: opts?.yearStart ?? 1999,
    yearEndExclusive: opts?.yearEndExclusive ?? new Date().getUTCFullYear() + 1,
    pkgIdStep: opts?.pkgIdStep ?? 2000,
    pkgIdMax: opts?.pkgIdMax ?? 100_000,
    rebuildStep: opts?.rebuildStep ?? 1000,
    idsPerInsert: opts?.idsPerInsert ?? 200,
    recomputeShards: opts?.recomputeShards ?? 8,
  };
}

function sqlQuote(id: string): string {
  return `'${id.replace(/'/g, "''")}'`;
}

/**
 * Chunked recount of page_stats. Bounded per statement:
 *  - vuln_total / critical_total: CVE-year PK ranges + under/over catch-alls
 *  - package_total: integer id ranges + open-ended tail
 *  - kev_total: single statement via idx_vuln_kev (~1.6k rows)
 * Results accumulate in _stats_scratch, then one INSERT OR REPLACE.
 */
function pageStatsRecountSql(o: Required<StatsSqlOptions>): string[] {
  // ponytail: _stats_scratch uses PRIMARY KEY so INSERT OR REPLACE is idempotent on retry
  const stmts: string[] = [
    `DROP TABLE IF EXISTS _stats_scratch`,
    `CREATE TABLE _stats_scratch (k TEXT PRIMARY KEY, v INTEGER NOT NULL)`,
  ];
  const yearRanges: Array<[string, string | null]> = [];
  yearRanges.push(["", `CVE-${o.yearStart}-`]); // under-range catch-all
  for (let y = o.yearStart; y < o.yearEndExclusive; y++) {
    yearRanges.push([`CVE-${y}-`, `CVE-${y + 1}-`]);
  }
  yearRanges.push([`CVE-${o.yearEndExclusive}-`, null]); // open-ended tail

  // Keys: 'vuln:<lo-or-under>' and 'crit:<lo-or-under>' — unique per chunk
  for (const [lo, hi] of yearRanges) {
    const bounds = [
      lo ? `cve_id >= ${sqlQuote(lo)}` : null,
      hi ? `cve_id < ${sqlQuote(hi)}` : null,
    ].filter(Boolean).join(" AND ");
    const chunkKey = lo || "under";
    stmts.push(
      `INSERT OR REPLACE INTO _stats_scratch (k, v) VALUES ('vuln:${chunkKey}',
  (SELECT COUNT(*) FROM vulnerabilities WHERE ${bounds}))`,
      `INSERT OR REPLACE INTO _stats_scratch (k, v) VALUES ('crit:${chunkKey}',
  (SELECT COUNT(*) FROM cvss_scores WHERE ${bounds} AND severity = 'CRITICAL'))`,
    );
  }
  for (let lo = 0; lo < o.pkgIdMax; lo += o.pkgIdStep) {
    stmts.push(
      `INSERT OR REPLACE INTO _stats_scratch (k, v) VALUES ('pkg:${lo}',
  (SELECT COUNT(*) FROM packages WHERE id >= ${lo} AND id < ${lo + o.pkgIdStep}))`,
    );
  }
  stmts.push(
    `INSERT OR REPLACE INTO _stats_scratch (k, v) VALUES ('pkg:${o.pkgIdMax}',
  (SELECT COUNT(*) FROM packages WHERE id >= ${o.pkgIdMax}))`,
    `INSERT OR REPLACE INTO _stats_scratch (k, v) VALUES ('kev',
  (SELECT COUNT(*) FROM vulnerabilities WHERE kev = 1))`,
    `INSERT OR REPLACE INTO page_stats
  (id, vuln_total, package_total, critical_total, kev_total, computed_at)
SELECT 1,
  (SELECT COALESCE(SUM(v), 0) FROM _stats_scratch WHERE k LIKE 'vuln:%'),
  (SELECT COALESCE(SUM(v), 0) FROM _stats_scratch WHERE k LIKE 'pkg:%'),
  (SELECT COALESCE(SUM(v), 0) FROM _stats_scratch WHERE k LIKE 'crit:%'),
  (SELECT COALESCE(SUM(v), 0) FROM _stats_scratch WHERE k = 'kev'),
  datetime('now')`,
    `DROP TABLE _stats_scratch`,
  );
  return stmts;
}

/**
 * Daily-delta stats refresh, run ON D1 after the data statements landed.
 * Scoped: only packages touched by the delta's CVEs are recomputed
 * (idx_affected_cve finds them; idx_affected_pkg drives each recompute).
 */
export function deltaStatsSql(cveIds: string[], opts?: StatsSqlOptions): string[] {
  if (cveIds.length === 0) return [];
  const o = resolveOpts(opts);
  // ponytail: statsDdl() first so delta works even on a D1 missing the stats tables (IF NOT EXISTS = idempotent)
  const stmts: string[] = [
    ...statsDdl(),
    `DROP TABLE IF EXISTS _delta_cves`,
    `CREATE TABLE _delta_cves (cve_id TEXT PRIMARY KEY)`,
  ];
  for (let i = 0; i < cveIds.length; i += o.idsPerInsert) {
    const batch = cveIds.slice(i, i + o.idsPerInsert);
    stmts.push(
      `INSERT OR IGNORE INTO _delta_cves (cve_id) VALUES ${batch
        .map((id) => `(${sqlQuote(id)})`)
        .join(",")}`,
    );
  }
  stmts.push(
    `DROP TABLE IF EXISTS _touched_pkgs`,
    `CREATE TABLE _touched_pkgs (package_id INTEGER PRIMARY KEY)`,
    `INSERT OR IGNORE INTO _touched_pkgs (package_id)
SELECT DISTINCT package_id FROM affected
 WHERE package_id IS NOT NULL
   AND cve_id IN (SELECT cve_id FROM _delta_cves)`,
  );
  for (let k = 0; k < o.recomputeShards; k++) {
    stmts.push(
      `DELETE FROM package_stats WHERE package_id IN
  (SELECT package_id FROM _touched_pkgs WHERE package_id % ${o.recomputeShards} = ${k})`,
      // ponytail: OR REPLACE so a retried batch can't PK-conflict if DELETE/INSERT split across batch boundary
      `INSERT OR REPLACE INTO package_stats (package_id, ecosystem, name, cve_count, kev_count, max_epss)
${PACKAGE_STATS_SELECT}
  FROM _touched_pkgs t
  JOIN packages p ON p.id = t.package_id
  JOIN affected a ON a.package_id = t.package_id
  JOIN vulnerabilities v ON v.cve_id = a.cve_id
 WHERE t.package_id % ${o.recomputeShards} = ${k}
 GROUP BY p.id, p.ecosystem, p.name`,
    );
  }
  stmts.push(...pageStatsRecountSql(o));
  stmts.push(`DROP TABLE IF EXISTS _touched_pkgs`, `DROP TABLE IF EXISTS _delta_cves`);
  return stmts;
}

/**
 * One-time D1 backfill (additive migration) and disaster-recovery rebuild.
 * DDL first (IF NOT EXISTS), then package_stats sharded by id ranges, then
 * the same chunked page_stats recount the daily delta uses.
 */
export function rebuildAllStatsSql(opts?: StatsSqlOptions): string[] {
  const o = resolveOpts(opts);
  const stmts: string[] = [...statsDdl()];
  const ranges: Array<[number, number | null]> = [];
  for (let lo = 0; lo < o.pkgIdMax; lo += o.rebuildStep) ranges.push([lo, lo + o.rebuildStep]);
  ranges.push([o.pkgIdMax, null]);
  for (const [lo, hi] of ranges) {
    const bound = hi === null ? `p.id >= ${lo}` : `p.id >= ${lo} AND p.id < ${hi}`;
    const delBound = hi === null ? `package_id >= ${lo}` : `package_id >= ${lo} AND package_id < ${hi}`;
    stmts.push(
      `DELETE FROM package_stats WHERE ${delBound}`,
      // ponytail: OR REPLACE guards against PK conflict on batch retry
      `INSERT OR REPLACE INTO package_stats (package_id, ecosystem, name, cve_count, kev_count, max_epss)
${PACKAGE_STATS_SELECT}
  FROM packages p
  JOIN affected a ON a.package_id = p.id
  JOIN vulnerabilities v ON v.cve_id = a.cve_id
 WHERE ${bound}
 GROUP BY p.id, p.ecosystem, p.name`,
    );
  }
  stmts.push(...pageStatsRecountSql(o));
  return stmts;
}
