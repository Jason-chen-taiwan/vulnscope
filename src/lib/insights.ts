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
              COUNT(DISTINCT a.cve_id)::int AS cve_count,
              COUNT(DISTINCT a.cve_id) FILTER (WHERE v.kev)::int AS kev_count,
              MAX(v.epss_score)::float8 AS max_epss
         FROM affected a
         JOIN vulnerabilities v ON v.cve_id = a.cve_id
        GROUP BY a.package_id
     )
     SELECT p.ecosystem, p.name,
            agg.cve_count, agg.kev_count, agg.max_epss
       FROM agg
       JOIN packages p ON p.id = agg.package_id
      ORDER BY agg.kev_count DESC, agg.cve_count DESC
      LIMIT $1`,
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
    `SELECT v.cve_id, v.summary, v.description, v.kev_added_at, v.epss_score::float8 AS epss_score,
            cs.severity, cs.base_score::float8 AS base_score
       FROM vulnerabilities v
       LEFT JOIN LATERAL (
         SELECT severity, base_score FROM cvss_scores
          WHERE cve_id = v.cve_id ORDER BY base_score DESC NULLS LAST LIMIT 1
       ) cs ON true
      WHERE v.kev = true
      ORDER BY v.kev_added_at DESC NULLS LAST
      LIMIT $1`,
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
    `SELECT v.cve_id, v.summary, v.description, v.epss_score::float8 AS epss_score,
            v.epss_percentile::float8 AS epss_percentile, v.kev,
            cs.severity, cs.base_score::float8 AS base_score
       FROM vulnerabilities v
       LEFT JOIN LATERAL (
         SELECT severity, base_score FROM cvss_scores
          WHERE cve_id = v.cve_id ORDER BY base_score DESC NULLS LAST LIMIT 1
       ) cs ON true
      WHERE v.epss_score IS NOT NULL
      ORDER BY v.epss_score DESC
      LIMIT $1`,
    [limit],
  );
  return rows;
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
              COUNT(DISTINCT a.cve_id)::int AS cve_count,
              COUNT(DISTINCT a.cve_id) FILTER (WHERE v.kev)::int AS kev_count,
              MAX(v.epss_score)::float8 AS max_epss
         FROM affected a
         JOIN vulnerabilities v ON v.cve_id = a.cve_id
        WHERE a.ecosystem = $1
        GROUP BY a.package_id
     )
     SELECT p.name, agg.cve_count, agg.kev_count, agg.max_epss
       FROM agg
       JOIN packages p ON p.id = agg.package_id
      ORDER BY agg.kev_count DESC, agg.cve_count DESC
      LIMIT $2`,
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
