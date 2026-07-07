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
