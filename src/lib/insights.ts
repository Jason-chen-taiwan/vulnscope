import "server-only";
import { pool } from "@/db/client";

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

export async function getTopPackagesAllEcos(limit = 100): Promise<TopPackageRow[]> {
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

export async function getKevCatalog(limit = 500) {
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

export async function getEpssRising(limit = 100) {
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

export async function getEcosystemDeepDive(ecosystem: string, limit = 200) {
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

export const INSIGHT_ECOSYSTEMS = [
  "npm", "PyPI", "Maven", "Go", "Debian", "Alpine",
] as const;
export type InsightEcosystem = (typeof INSIGHT_ECOSYSTEMS)[number];
