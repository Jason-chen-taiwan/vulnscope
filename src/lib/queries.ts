import "server-only";
import { sql } from "drizzle-orm";
import { db, pool } from "@/db/client";
import { isAffected, type Ecosystem } from "./version-match";
import type { OsvRange } from "./osv";
// Start the daily-refresh scheduler the first time any page/API handler
// imports this module. The scheduler dedupes via a global flag.
import { startScheduler } from "./scheduler";
startScheduler();

export interface VulnRow {
  cve_id: string;
  summary: string | null;
  description: string | null;
  published_at: Date | null;
  modified_at: Date | null;
  kev: boolean;
  kev_added_at: Date | null;
  epss_score: number | null;
  epss_percentile: number | null;
}

export interface VulnListItem extends VulnRow {
  severity: string | null;
  base_score: number | null;
}

export async function getCveById(cveId: string): Promise<VulnRow | null> {
  const { rows } = await pool.query(
    `SELECT cve_id, summary, description, published_at, modified_at,
            kev, kev_added_at, epss_score::float8 AS epss_score,
            epss_percentile::float8 AS epss_percentile
       FROM vulnerabilities WHERE cve_id = $1`,
    [cveId],
  );
  return rows[0] ?? null;
}

export async function getCveBundle(cveId: string) {
  const v = await getCveById(cveId);
  if (!v) return null;
  const [{ rows: scores }, { rows: aff }, { rows: refs }] = await Promise.all([
    pool.query(
      `SELECT version, vector, base_score::float8 AS base_score, severity, source
         FROM cvss_scores WHERE cve_id = $1 ORDER BY version DESC, source`,
      [cveId],
    ),
    pool.query(
      `SELECT a.ecosystem, p.name, a.ranges_json, a.versions_json
         FROM affected a JOIN packages p ON p.id = a.package_id
         WHERE a.cve_id = $1
         ORDER BY a.ecosystem, p.name`,
      [cveId],
    ),
    pool.query(
      `SELECT url, type FROM refs WHERE cve_id = $1 ORDER BY type, url`,
      [cveId],
    ),
  ]);
  return { vuln: v, scores, affected: aff, refs };
}

export interface SearchFilter {
  q?: string;
  severity?: string[]; // ['HIGH','CRITICAL']
  kev?: boolean;
  ecosystem?: string[]; // ['npm','PyPI']
  page?: number;
  pageSize?: number;
}

export async function searchVulns(f: SearchFilter): Promise<{ items: VulnListItem[]; total: number }> {
  const pageSize = Math.min(100, Math.max(1, f.pageSize ?? 25));
  const page = Math.max(1, f.page ?? 1);
  const offset = (page - 1) * pageSize;

  const where: string[] = [];
  const params: unknown[] = [];
  let p = 0;

  if (f.q && f.q.trim().length > 0) {
    const q = f.q.trim();
    // Prefer FTS; fall back to trigram for non-English / typo cases.
    params.push(q);
    p++;
    where.push(
      `(search_tsv @@ plainto_tsquery('english', $${p})
         OR cve_id ILIKE '%' || $${p} || '%'
         OR EXISTS (
           SELECT 1 FROM affected a2 JOIN packages p2 ON p2.id = a2.package_id
            WHERE a2.cve_id = v.cve_id AND p2.name ILIKE '%' || $${p} || '%'
         ))`,
    );
  }
  if (f.kev === true) where.push("v.kev = true");
  if (f.severity && f.severity.length > 0) {
    params.push(f.severity);
    p++;
    where.push(
      `EXISTS (SELECT 1 FROM cvss_scores cs WHERE cs.cve_id = v.cve_id AND cs.severity = ANY($${p}::text[]))`,
    );
  }
  if (f.ecosystem && f.ecosystem.length > 0) {
    params.push(f.ecosystem);
    p++;
    where.push(
      `EXISTS (SELECT 1 FROM affected a3 WHERE a3.cve_id = v.cve_id AND a3.ecosystem = ANY($${p}::text[]))`,
    );
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const baseFrom = `FROM vulnerabilities v ${whereSql}`;
  const totalRes = await pool.query(`SELECT COUNT(*)::int AS c ${baseFrom}`, params);
  const total = (totalRes.rows[0] as { c: number }).c;

  // Severity rollup via a subquery: pick the highest scoring CVSS row.
  params.push(pageSize);
  params.push(offset);
  const sqlText = `
    SELECT v.cve_id, v.summary, v.description, v.published_at, v.modified_at,
           v.kev, v.kev_added_at,
           v.epss_score::float8 AS epss_score,
           v.epss_percentile::float8 AS epss_percentile,
           cs.severity AS severity, cs.base_score::float8 AS base_score
      FROM vulnerabilities v
      LEFT JOIN LATERAL (
        SELECT severity, base_score
          FROM cvss_scores
         WHERE cve_id = v.cve_id
         ORDER BY base_score DESC NULLS LAST
         LIMIT 1
      ) cs ON true
      ${whereSql}
      ORDER BY v.published_at DESC NULLS LAST, v.cve_id DESC
      LIMIT $${p + 1} OFFSET $${p + 2}
  `;
  const res = await pool.query(sqlText, params);
  return { items: res.rows as VulnListItem[], total };
}

export interface PackageBundle {
  package: { id: number; ecosystem: string; name: string };
  cves: Array<{
    cve_id: string;
    summary: string | null;
    description: string | null;
    kev: boolean;
    severity: string | null;
    base_score: number | null;
    ranges_json: OsvRange[];
    versions_json: string[] | null;
  }>;
}

export async function getPackageWithCves(
  ecosystem: string,
  name: string,
): Promise<PackageBundle | null> {
  const { rows: pkgRows } = await pool.query(
    `SELECT id, ecosystem, name FROM packages WHERE ecosystem = $1 AND name = $2`,
    [ecosystem, name],
  );
  if (pkgRows.length === 0) return null;
  const pkg = pkgRows[0] as PackageBundle["package"];

  const { rows: cves } = await pool.query(
    `
    SELECT v.cve_id, v.summary, v.description, v.kev,
           cs.severity AS severity, cs.base_score::float8 AS base_score,
           a.ranges_json, a.versions_json
      FROM affected a
      JOIN vulnerabilities v ON v.cve_id = a.cve_id
      LEFT JOIN LATERAL (
        SELECT severity, base_score
          FROM cvss_scores
         WHERE cve_id = v.cve_id
         ORDER BY base_score DESC NULLS LAST
         LIMIT 1
      ) cs ON true
     WHERE a.package_id = $1
     ORDER BY v.kev DESC, cs.base_score DESC NULLS LAST, v.published_at DESC NULLS LAST
    `,
    [pkg.id],
  );
  return { package: pkg, cves: cves as PackageBundle["cves"] };
}

export interface VersionCheckResult {
  package: { ecosystem: string; name: string };
  version: string;
  is_vulnerable: boolean;
  affected_by: Array<{
    cve_id: string;
    severity: string | null;
    base_score: number | null;
    kev: boolean;
    fixed_in: string | null;
    summary: string | null;
  }>;
  recommended_version: string | null;
}

export async function checkPackageVersion(
  ecosystem: string,
  name: string,
  version: string,
): Promise<VersionCheckResult | null> {
  const bundle = await getPackageWithCves(ecosystem, name);
  if (!bundle) return null;
  const eco = ecosystem as Ecosystem;
  const matches: VersionCheckResult["affected_by"] = [];
  let smallestFix: string | null = null;
  for (const c of bundle.cves) {
    const r = isAffected(version, c.ranges_json, c.versions_json, eco);
    if (r.affected) {
      matches.push({
        cve_id: c.cve_id,
        severity: c.severity,
        base_score: c.base_score,
        kev: c.kev,
        fixed_in: r.fixedIn,
        summary: c.summary,
      });
      if (r.fixedIn && (smallestFix === null || r.fixedIn < smallestFix)) {
        smallestFix = r.fixedIn;
      }
    }
  }
  return {
    package: { ecosystem, name },
    version,
    is_vulnerable: matches.length > 0,
    affected_by: matches,
    recommended_version: smallestFix,
  };
}

export async function getDashboardStats() {
  const { rows } = await pool.query(`
    SELECT
      (SELECT COUNT(*)::int FROM vulnerabilities WHERE published_at > now() - interval '1 day') AS new_today,
      (SELECT COUNT(*)::int FROM vulnerabilities WHERE published_at > now() - interval '7 days') AS new_week,
      (SELECT COUNT(*)::int FROM cvss_scores WHERE severity = 'CRITICAL') AS critical_total,
      (SELECT COUNT(*)::int FROM vulnerabilities WHERE kev = true) AS kev_total,
      (SELECT COUNT(*)::int FROM packages) AS package_total,
      (SELECT COUNT(*)::int FROM vulnerabilities) AS vuln_total
  `);
  return rows[0] as {
    new_today: number; new_week: number; critical_total: number;
    kev_total: number; package_total: number; vuln_total: number;
  };
}

export async function getRecentKev(limit = 10) {
  const { rows } = await pool.query(
    `SELECT cve_id, summary, description, kev_added_at
       FROM vulnerabilities
      WHERE kev = true
      ORDER BY kev_added_at DESC NULLS LAST
      LIMIT $1`,
    [limit],
  );
  return rows as Array<{ cve_id: string; summary: string | null; description: string | null; kev_added_at: Date | null }>;
}

export async function getTopPackages(ecosystem: string, limit = 12) {
  const { rows } = await pool.query(
    `SELECT p.ecosystem, p.name, COUNT(DISTINCT a.cve_id)::int AS cve_count,
            COUNT(*) FILTER (WHERE v.kev)::int AS kev_count
       FROM packages p
       JOIN affected a ON a.package_id = p.id
       JOIN vulnerabilities v ON v.cve_id = a.cve_id
      WHERE p.ecosystem = $1
      GROUP BY p.ecosystem, p.name
      ORDER BY kev_count DESC, cve_count DESC
      LIMIT $2`,
    [ecosystem, limit],
  );
  return rows as Array<{ ecosystem: string; name: string; cve_count: number; kev_count: number }>;
}

export interface PackageListFilter {
  q?: string;
  ecosystem?: string;
  sort?: "cves" | "name";
  page?: number;
  pageSize?: number;
}

export async function browsePackages(f: PackageListFilter) {
  const pageSize = Math.min(100, Math.max(1, f.pageSize ?? 50));
  const page = Math.max(1, f.page ?? 1);
  const offset = (page - 1) * pageSize;
  const where: string[] = [];
  const params: unknown[] = [];
  let p = 0;
  if (f.q && f.q.trim()) {
    params.push(f.q.trim());
    p++;
    where.push(`p.name ILIKE '%' || $${p} || '%'`);
  }
  if (f.ecosystem) {
    params.push(f.ecosystem);
    p++;
    where.push(`p.ecosystem = $${p}`);
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const totalRes = await pool.query(
    `SELECT COUNT(*)::int AS c FROM packages p ${whereSql}`,
    params,
  );
  const total = (totalRes.rows[0] as { c: number }).c;

  const orderBy = f.sort === "name"
    ? "p.ecosystem, p.name"
    : "kev_count DESC, cve_count DESC, p.name";

  params.push(pageSize);
  params.push(offset);
  const { rows } = await pool.query(
    `SELECT p.ecosystem, p.name,
            COUNT(DISTINCT a.cve_id)::int AS cve_count,
            COUNT(*) FILTER (WHERE v.kev)::int AS kev_count
       FROM packages p
       LEFT JOIN affected a ON a.package_id = p.id
       LEFT JOIN vulnerabilities v ON v.cve_id = a.cve_id
       ${whereSql}
       GROUP BY p.ecosystem, p.name
       ORDER BY ${orderBy}
       LIMIT $${p + 1} OFFSET $${p + 2}`,
    params,
  );
  return {
    items: rows as Array<{ ecosystem: string; name: string; cve_count: number; kev_count: number }>,
    total,
  };
}

export async function autocompletePackages(prefix: string, limit = 10) {
  const q = prefix.trim();
  if (q.length < 2) return [];
  const { rows } = await pool.query(
    `SELECT p.ecosystem, p.name,
            COUNT(DISTINCT a.cve_id)::int AS cve_count
       FROM packages p
       LEFT JOIN affected a ON a.package_id = p.id
      WHERE p.name ILIKE $1 || '%'
         OR p.name ILIKE '%' || $1 || '%'
      GROUP BY p.ecosystem, p.name
      ORDER BY (CASE WHEN p.name ILIKE $1 || '%' THEN 0 ELSE 1 END),
               cve_count DESC, p.name
      LIMIT $2`,
    [q, limit],
  );
  return rows as Array<{ ecosystem: string; name: string; cve_count: number }>;
}

export async function getRecentVulns(limit = 10) {
  const { rows } = await pool.query(
    `SELECT v.cve_id, v.summary, v.description, v.published_at, v.kev,
            cs.severity, cs.base_score::float8 AS base_score
       FROM vulnerabilities v
       LEFT JOIN LATERAL (
         SELECT severity, base_score FROM cvss_scores
          WHERE cve_id = v.cve_id ORDER BY base_score DESC NULLS LAST LIMIT 1
       ) cs ON true
      WHERE v.published_at IS NOT NULL
      ORDER BY v.published_at DESC
      LIMIT $1`,
    [limit],
  );
  return rows as Array<{
    cve_id: string; summary: string | null; description: string | null;
    published_at: Date | null;
    kev: boolean; severity: string | null; base_score: number | null;
  }>;
}

// Suppress unused-import warnings in clients that don't need drizzle.
void db;
void sql;
