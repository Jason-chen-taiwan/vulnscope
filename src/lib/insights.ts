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
  const { rows } = await pool.query(
    `SELECT p.ecosystem,
            p.name,
            COUNT(DISTINCT a.cve_id)::int AS cve_count,
            COUNT(DISTINCT a.cve_id) FILTER (WHERE v.kev)::int AS kev_count,
            MAX(v.epss_score)::float8 AS max_epss
       FROM packages p
       JOIN affected a ON a.package_id = p.id
       JOIN vulnerabilities v ON v.cve_id = a.cve_id
      GROUP BY p.ecosystem, p.name
      ORDER BY kev_count DESC, cve_count DESC
      LIMIT $1`,
    [limit],
  );
  return rows as TopPackageRow[];
}

export async function getKevCatalog(limit = 500) {
  const { rows } = await pool.query(
    `SELECT v.cve_id, v.summary, v.kev_added_at, v.epss_score::float8 AS epss_score,
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
    `SELECT v.cve_id, v.summary, v.epss_score::float8 AS epss_score,
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
  const { rows } = await pool.query(
    `SELECT p.name,
            COUNT(DISTINCT a.cve_id)::int AS cve_count,
            COUNT(DISTINCT a.cve_id) FILTER (WHERE v.kev)::int AS kev_count,
            MAX(v.epss_score)::float8 AS max_epss
       FROM packages p
       JOIN affected a ON a.package_id = p.id
       JOIN vulnerabilities v ON v.cve_id = a.cve_id
      WHERE p.ecosystem = $1
      GROUP BY p.name
      ORDER BY kev_count DESC, cve_count DESC
      LIMIT $2`,
    [ecosystem, limit],
  );
  return rows as { name: string; cve_count: number; kev_count: number; max_epss: number | null }[];
}

export const INSIGHT_ECOSYSTEMS = [
  "npm", "PyPI", "Maven", "Go", "Debian", "Alpine",
] as const;
export type InsightEcosystem = (typeof INSIGHT_ECOSYSTEMS)[number];
