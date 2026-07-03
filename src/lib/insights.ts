import "server-only";
import { unstable_cache } from "next/cache";
import { pool } from "@/db/client";

const SSR_CACHE_TTL_SEC = 60;

/**
 * Aggregation queries for the /insights/* pages. Each returns a result
 * shape ready for table rendering. All are cheap enough to run on each
 * request given our current scale (~75k vulns); when we cross a few
 * hundred thousand we should switch to materialized views.
 */

export interface TopPackageRow {
  ecosystem: string;
  name: string;
  cve_count: number;
  kev_count: number;
  max_epss: number | null;
}

async function _getTopPackagesAllEcos(limit: number): Promise<TopPackageRow[]> {
  // Pre-aggregate from affected first (driven by idx_affected_pkg / its
  // composite siblings), then JOIN packages by PK. Previously this drove
  // from packages and forced a full scan of affected + vulnerabilities
  // joins per package — observed RED in the query audit.
  const { rows } = await pool.query(
    `WITH agg AS (
       SELECT a.package_id,
              COUNT(DISTINCT a.cve_id) AS cve_count,
              COUNT(DISTINCT CASE WHEN v.kev = 1 THEN a.cve_id END) AS kev_count,
              CAST(MAX(v.epss_score) AS REAL) AS max_epss
         FROM affected a
         JOIN vulnerabilities v ON v.cve_id = a.cve_id
        GROUP BY a.package_id
     )
     SELECT p.ecosystem, p.name,
            agg.cve_count, agg.kev_count, agg.max_epss
       FROM agg
       JOIN packages p ON p.id = agg.package_id
      ORDER BY agg.kev_count DESC, agg.cve_count DESC
      LIMIT ?`,
    [limit],
  );
  return rows as TopPackageRow[];
}
export const getTopPackagesAllEcos = (limit = 100): Promise<TopPackageRow[]> =>
  unstable_cache(_getTopPackagesAllEcos, ["getTopPackagesAllEcos", String(limit)], {
    revalidate: SSR_CACHE_TTL_SEC,
  })(limit);

async function _getKevCatalog(limit: number) {
  const { rows } = await pool.query(
    `SELECT v.cve_id, v.summary, v.description, v.kev_added_at, CAST(v.epss_score AS REAL) AS epss_score,
            (SELECT severity FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
              ORDER BY base_score DESC LIMIT 1) AS severity,
            CAST((SELECT base_score FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
              ORDER BY base_score DESC LIMIT 1) AS REAL) AS base_score
       FROM vulnerabilities v
      WHERE v.kev = 1
      ORDER BY v.kev_added_at DESC
      LIMIT ?`,
    [limit],
  );
  return rows;
}
export const getKevCatalog = (limit = 500) =>
  unstable_cache(_getKevCatalog, ["getKevCatalog", String(limit)], {
    revalidate: SSR_CACHE_TTL_SEC,
  })(limit);

async function _getEpssRising(limit: number) {
  const { rows } = await pool.query(
    `SELECT v.cve_id, v.summary, v.description, CAST(v.epss_score AS REAL) AS epss_score,
            CAST(v.epss_percentile AS REAL) AS epss_percentile, v.kev,
            (SELECT severity FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
              ORDER BY base_score DESC LIMIT 1) AS severity,
            CAST((SELECT base_score FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
              ORDER BY base_score DESC LIMIT 1) AS REAL) AS base_score
       FROM vulnerabilities v
      WHERE v.epss_score IS NOT NULL
      ORDER BY v.epss_score DESC
      LIMIT ?`,
    [limit],
  );
  return rows.map((r) => ({ ...r, kev: Boolean(r.kev) }));
}
export const getEpssRising = (limit = 100) =>
  unstable_cache(_getEpssRising, ["getEpssRising", String(limit)], {
    revalidate: SSR_CACHE_TTL_SEC,
  })(limit);

async function _getEcosystemDeepDive(ecosystem: string, limit: number) {
  // Drive from affected via idx_affected_eco_pkg (ecosystem, package_id)
  // INCLUDE (cve_id) — same trick that took getTopPackages from 21s to 55ms.
  const { rows } = await pool.query(
    `WITH agg AS (
       SELECT a.package_id,
              COUNT(DISTINCT a.cve_id) AS cve_count,
              COUNT(DISTINCT CASE WHEN v.kev = 1 THEN a.cve_id END) AS kev_count,
              CAST(MAX(v.epss_score) AS REAL) AS max_epss
         FROM affected a
         JOIN vulnerabilities v ON v.cve_id = a.cve_id
        WHERE a.ecosystem = ?
        GROUP BY a.package_id
     )
     SELECT p.name, agg.cve_count, agg.kev_count, agg.max_epss
       FROM agg
       JOIN packages p ON p.id = agg.package_id
      ORDER BY agg.kev_count DESC, agg.cve_count DESC
      LIMIT ?`,
    [ecosystem, limit],
  );
  return rows as { name: string; cve_count: number; kev_count: number; max_epss: number | null }[];
}
export const getEcosystemDeepDive = (ecosystem: string, limit = 200) =>
  unstable_cache(
    _getEcosystemDeepDive,
    ["getEcosystemDeepDive", ecosystem, String(limit)],
    { revalidate: SSR_CACHE_TTL_SEC },
  )(ecosystem, limit);

export const INSIGHT_ECOSYSTEMS = [
  "npm", "PyPI", "Maven", "Go", "Debian", "Alpine",
] as const;
export type InsightEcosystem = (typeof INSIGHT_ECOSYSTEMS)[number];
