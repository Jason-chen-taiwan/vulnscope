/**
 * Request-path SQL for the precomputed stats tables.
 *
 * Lives in its own module (WITHOUT the `server-only` guard queries.ts
 * carries) so vitest can execute every statement against a real SQLite
 * fixture — the SQL that runs in production is the SQL that is tested.
 *
 * Background: these replace COUNT(*) full scans and 119k-row GROUP BY
 * aggregations that overloaded D1 (2026-07-06). See
 * docs/superpowers/specs/2026-07-07-query-optimization-design.md.
 */

/**
 * Homepage dashboard. The four totals come from page_stats (written by
 * ingest); new_today/new_week stay live because they are cheap
 * idx_vuln_published range scans AND are relative to "now", which a
 * once-a-day precompute would misrepresent. The LEFT JOIN from a 1-row
 * inline table guarantees exactly one result row even when page_stats
 * is empty (pre-migration D1) — totals coalesce to 0.
 */
export const DASHBOARD_STATS_SQL = `
  SELECT
    (SELECT COUNT(*) FROM vulnerabilities WHERE published_at > datetime('now','-1 day'))  AS new_today,
    (SELECT COUNT(*) FROM vulnerabilities WHERE published_at > datetime('now','-7 days')) AS new_week,
    COALESCE(ps.critical_total, 0) AS critical_total,
    COALESCE(ps.kev_total, 0)      AS kev_total,
    COALESCE(ps.package_total, 0)  AS package_total,
    COALESCE(ps.vuln_total, 0)     AS vuln_total
  FROM (SELECT 1 AS one) dummy
  LEFT JOIN page_stats ps ON ps.id = 1
`;

/** Unfiltered search total. 0 rows ⇒ caller falls back to a live COUNT. */
export const VULN_TOTAL_SQL = `SELECT vuln_total FROM page_stats WHERE id = 1`;

/** Homepage per-ecosystem ranking. Params: [ecosystem, limit]. */
export const TOP_PACKAGES_BY_ECO_SQL = `
  SELECT ecosystem, name, cve_count, kev_count
    FROM package_stats
   WHERE ecosystem = ?
   ORDER BY kev_count DESC, cve_count DESC
   LIMIT ?
`;

/** /insights/most-vulnerable-packages. Params: [limit]. */
export const TOP_PACKAGES_ALL_SQL = `
  SELECT ecosystem, name, cve_count, kev_count, max_epss
    FROM package_stats
   ORDER BY kev_count DESC, cve_count DESC
   LIMIT ?
`;

/** /insights/ecosystem/[eco]. Params: [ecosystem, limit]. */
export const ECOSYSTEM_DEEP_DIVE_SQL = `
  SELECT name, cve_count, kev_count, max_epss
    FROM package_stats
   WHERE ecosystem = ?
   ORDER BY kev_count DESC, cve_count DESC
   LIMIT ?
`;

/** generateMetadata package CVE count. Params: [package_id]. */
export const PACKAGE_CVE_COUNT_SQL = `
  SELECT cve_count FROM package_stats WHERE package_id = ?
`;

/** Sitemap package URLs. Params: [limit]. */
export const SITEMAP_TOP_PACKAGES_SQL = `
  SELECT ecosystem, name
    FROM package_stats
   ORDER BY cve_count DESC
   LIMIT ?
`;

/**
 * /packages listing. Replaces the old 119k-row agg CTE with a LEFT JOIN
 * against package_stats (16k rows). Param order is textual:
 * [nameParam?, ecosystem?, pageSize, offset].
 */
export function browsePackagesListSql(opts: {
  /** name filter uses packages_fts MATCH (≥3 chars) vs plain LIKE */
  nameViaFts: boolean;
  hasName: boolean;
  hasEcosystem: boolean;
  sort: "cves" | "name";
}): string {
  const where: string[] = [];
  if (opts.hasName) {
    where.push(
      opts.nameViaFts
        ? `p.id IN (SELECT rowid FROM packages_fts WHERE packages_fts MATCH ?)`
        : `p.name LIKE ?`,
    );
  }
  if (opts.hasEcosystem) where.push(`p.ecosystem = ?`);
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const orderBy =
    opts.sort === "name"
      ? `p.ecosystem, p.name`
      : `kev_count DESC, cve_count DESC, p.name`;
  return `
    SELECT p.ecosystem, p.name,
           COALESCE(ps.cve_count, 0) AS cve_count,
           COALESCE(ps.kev_count, 0) AS kev_count
      FROM packages p
      LEFT JOIN package_stats ps ON ps.package_id = p.id
      ${whereSql}
     ORDER BY ${orderBy}
     LIMIT ? OFFSET ?
  `;
}
