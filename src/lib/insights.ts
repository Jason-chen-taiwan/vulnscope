import "server-only";
import { unstable_cache } from "next/cache";
import { pool } from "@/db/client";
import { TOP_PACKAGES_ALL_SQL, ECOSYSTEM_DEEP_DIVE_SQL } from "./stats-read-sql";

const SSR_CACHE_TTL_SEC = 60;

/**
 * Aggregation queries for the /insights/* pages. Each returns a result
 * shape ready for table rendering. All read the ingest-precomputed
 * `package_stats` table — request-path aggregation over `affected`
 * overloaded D1 (2026-07-06).
 */

export interface TopPackageRow {
  ecosystem: string;
  name: string;
  cve_count: number;
  kev_count: number;
  max_epss: number | null;
}

async function _getTopPackagesAllEcos(limit: number): Promise<TopPackageRow[]> {
  // Ingest-precomputed ranking (package_stats, idx_pkgstats_rank). The old
  // query aggregated all 119k affected rows on every view.
  const { rows } = await pool.query(TOP_PACKAGES_ALL_SQL, [limit]);
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
  // Ingest-precomputed ranking (package_stats, idx_pkgstats_eco_rank).
  const { rows } = await pool.query(ECOSYSTEM_DEEP_DIVE_SQL, [ecosystem, limit]);
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
