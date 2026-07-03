import "server-only";
import { sql } from "drizzle-orm";
import { unstable_cache } from "next/cache";
import { db, pool } from "@/db/client";
import { isAffected, type Ecosystem } from "./version-match";
import type { OsvRange } from "./osv";

/**
 * Default TTL for SSR-side caches. 60 seconds is generous enough that
 * during ingest (when PG is busy writing) the web tier serves entirely
 * from in-memory cache, and short enough that fresh CVE data shows up
 * on the next minute. unstable_cache stores per-Node-process — every
 * web replica builds its own cache, which is fine because the data is
 * read-only and inconsistencies between replicas are bounded by the
 * 60s TTL.
 */
const SSR_CACHE_TTL_SEC = 60;

/**
 * D1/SQLite stores `ranges_json` / `versions_json` as TEXT, whereas the old
 * Postgres `jsonb` columns were auto-parsed to JS values by the `pg` driver.
 * Consumers (version-match, CVE/package page components) expect parsed
 * arrays, so we parse the TEXT here to keep the result shape identical.
 * Tolerates already-parsed values (defensive), null/empty, and bad JSON.
 */
function parseJsonColumn<T>(value: unknown): T | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string") return value as T;
  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}

/**
 * SQLite has no boolean type — `kev` is stored/returned as 0/1. The old
 * Postgres path returned a real JS boolean, and several consumers rely on
 * that (JSON-LD serialization, strict comparisons). Coerce a row's `kev`
 * back to boolean while preserving every other field to keep the result
 * shape identical.
 */
function coerceKev<T extends { kev?: unknown }>(row: T): T {
  return { ...row, kev: Boolean(row.kev) };
}

/**
 * FTS5 MATCH syntax is a mini-language: bare `-`, `:`, `"`, `*`, `(` etc.
 * are operators, so a raw user string like "CVE-2021-44228" or "log4j:"
 * throws a syntax error. We neutralise this by quoting each whitespace-
 * delimited token as an FTS phrase (internal `"` doubled per FTS5 rules)
 * and joining with spaces — implicit AND, matching the old Postgres
 * `plainto_tsquery` semantics where all terms must be present.
 */
function ftsQuery(term: string): string {
  return term
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((tok) => `"${tok.replace(/"/g, '""')}"`)
    .join(" ");
}

/**
 * For the trigram `packages_fts`, the whole search string is a single
 * substring probe, so wrap it as one quoted phrase (again doubling `"`).
 * This also escapes `:` / `-` / `"` that would otherwise be FTS operators.
 */
function trigramQuery(term: string): string {
  return `"${term.trim().replace(/"/g, '""')}"`;
}

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
  const { rows } = await pool.query<VulnRow>(
    `SELECT cve_id, summary, description, published_at, modified_at,
            kev, kev_added_at, CAST(epss_score AS REAL) AS epss_score,
            CAST(epss_percentile AS REAL) AS epss_percentile
       FROM vulnerabilities WHERE cve_id = ?`,
    [cveId],
  );
  return rows[0] ? coerceKev(rows[0]) : null;
}

/**
 * Resolve any identifier (CVE-..., GHSA-..., DSA-..., ALPINE-..., etc.)
 * back to a canonical CVE id. Returns null if nothing matches — callers
 * should map that to a 404. The `vuln_aliases` table provides O(1)
 * lookup via the unique index on alias.
 */
export async function resolveToCveId(id: string): Promise<string | null> {
  const trimmed = id.trim();
  if (!trimmed) return null;
  // Fast path: it's already a CVE.
  if (/^CVE-\d{4}-\d+$/i.test(trimmed)) {
    const { rows } = await pool.query<{ cve_id: string }>(
      `SELECT cve_id FROM vulnerabilities WHERE cve_id = ?`,
      [trimmed.toUpperCase()],
    );
    return rows[0]?.cve_id ?? null;
  }
  // Alias lookup — case-sensitive because GHSA/DSA identifiers are
  // case-sensitive in their canonical form.
  const { rows } = await pool.query<{ cve_id: string }>(
    `SELECT cve_id FROM vuln_aliases WHERE alias = ? LIMIT 1`,
    [trimmed],
  );
  return rows[0]?.cve_id ?? null;
}

export async function getCveBundle(cveId: string) {
  const v = await getCveById(cveId);
  if (!v) return null;
  const [{ rows: scores }, { rows: aff }, { rows: refs }, { rows: aliases }] =
    await Promise.all([
      pool.query(
        `SELECT version, vector, CAST(base_score AS REAL) AS base_score, severity, source
           FROM cvss_scores WHERE cve_id = ? ORDER BY version DESC, source`,
        [cveId],
      ),
      pool.query<{ ecosystem: string; name: string; ranges_json: unknown; versions_json: unknown }>(
        `SELECT a.ecosystem, p.name, a.ranges_json, a.versions_json
           FROM affected a JOIN packages p ON p.id = a.package_id
           WHERE a.cve_id = ?
           ORDER BY a.ecosystem, p.name`,
        [cveId],
      ),
      pool.query(
        `SELECT url, type FROM refs WHERE cve_id = ? ORDER BY type, url`,
        [cveId],
      ),
      pool.query<{ alias: string; source: string }>(
        `SELECT alias, source FROM vuln_aliases WHERE cve_id = ?
          ORDER BY CASE source
            WHEN 'ghsa' THEN 0 WHEN 'rhsa' THEN 1
            WHEN 'dsa'  THEN 2 WHEN 'usn'  THEN 3
            WHEN 'alpine' THEN 4 ELSE 9 END,
            alias`,
        [cveId],
      ),
    ]);
  // The D1 schema (build-sqlite.ts) has no `exploits` table — that data
  // is Postgres-only enrichment that the Cloudflare build doesn't ship.
  // Return an empty list so page rendering (which reads `bundle.exploits`)
  // stays intact.
  const exploits: { url: string; source: string; description: string | null }[] = [];
  const affected = aff.map((a) => ({
    ecosystem: a.ecosystem,
    name: a.name,
    ranges_json: parseJsonColumn<OsvRange[]>(a.ranges_json) ?? [],
    versions_json: parseJsonColumn<string[]>(a.versions_json),
  }));
  return { vuln: v, scores, affected, refs, aliases, exploits };
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

  // CTE we'll splice into the FROM clause when the q branch needs
  // package-name fuzzy match. On D1 the package match runs against the
  // `packages_fts` trigram index; the CTE materialises the matching CVE
  // set ONCE, then the outer query does an IN lookup against the
  // vulnerabilities PK.
  let pkgSearchCte = "";
  if (f.q && f.q.trim().length > 0) {
    const q = f.q.trim();
    // Full-text over summary/description via the FTS5 `vulns_fts` porter
    // index. Sanitise the term so FTS operator chars don't blow up MATCH.
    params.push(ftsQuery(q));
    // Exact/prefix CVE-id lookup, e.g. "CVE-2021-4428".
    params.push(q);

    // Package-name fuzzy match. The trigram tokenizer needs ≥3-char
    // tokens; for shorter queries fall back to a plain infix LIKE so a
    // 1–2 char query still returns something.
    let pkgMatchClause: string;
    if (q.length >= 3) {
      params.push(trigramQuery(q));
      pkgMatchClause = `p2.id IN (SELECT rowid FROM packages_fts WHERE packages_fts MATCH ?)`;
    } else {
      params.push(`%${q}%`);
      pkgMatchClause = `p2.name LIKE ?`;
    }
    pkgSearchCte = `WITH pkg_match_cves AS (
        SELECT DISTINCT a.cve_id
          FROM packages p2
          JOIN affected a ON a.package_id = p2.id
         WHERE ${pkgMatchClause}
      )`;
    where.push(
      `(v.cve_id IN (SELECT cve_id FROM vulns_fts WHERE vulns_fts MATCH ?)
         OR v.cve_id LIKE ? || '%'
         OR v.cve_id IN (SELECT cve_id FROM pkg_match_cves))`,
    );
  }
  if (f.kev === true) where.push("v.kev = 1");
  if (f.severity && f.severity.length > 0) {
    const ph = f.severity.map(() => "?").join(", ");
    params.push(...f.severity);
    where.push(
      `EXISTS (SELECT 1 FROM cvss_scores cs WHERE cs.cve_id = v.cve_id AND cs.severity IN (${ph}))`,
    );
  }
  if (f.ecosystem && f.ecosystem.length > 0) {
    const ph = f.ecosystem.map(() => "?").join(", ");
    params.push(...f.ecosystem);
    where.push(
      `EXISTS (SELECT 1 FROM affected a3 WHERE a3.cve_id = v.cve_id AND a3.ecosystem IN (${ph}))`,
    );
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const baseFrom = `FROM vulnerabilities v ${whereSql}`;
  const totalRes = await pool.query<{ c: number }>(
    `${pkgSearchCte} SELECT COUNT(*) AS c ${baseFrom}`,
    params,
  );
  const total = totalRes.rows[0]?.c ?? 0;

  // Severity rollup via correlated subqueries: pick the highest scoring
  // CVSS row per CVE (SQLite has no LATERAL).
  params.push(pageSize);
  params.push(offset);
  const sqlText = `
    ${pkgSearchCte}
    SELECT v.cve_id, v.summary, v.description, v.published_at, v.modified_at,
           v.kev, v.kev_added_at,
           CAST(v.epss_score AS REAL) AS epss_score,
           CAST(v.epss_percentile AS REAL) AS epss_percentile,
           (SELECT severity FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
             ORDER BY base_score DESC LIMIT 1) AS severity,
           CAST((SELECT base_score FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
             ORDER BY base_score DESC LIMIT 1) AS REAL) AS base_score
      FROM vulnerabilities v
      ${whereSql}
      ORDER BY v.published_at DESC, v.cve_id DESC
      LIMIT ? OFFSET ?
  `;
  const res = await pool.query<VulnListItem>(sqlText, params);
  return { items: res.rows.map(coerceKev), total };
}

export interface PackageBundle {
  package: { id: number; ecosystem: string; name: string };
  cves: Array<{
    cve_id: string;
    summary: string | null;
    description: string | null;
    kev: boolean;
    epss_score: number | null;
    severity: string | null;
    base_score: number | null;
    ranges_json: OsvRange[];
    versions_json: string[] | null;
    exploits_count: number;
  }>;
}

/**
 * 60s in-memory cache for getPackageWithCves.
 *
 * Justification: `/package/[eco]/[name]` is force-dynamic so every
 * request re-runs the full bundle query. Most popular packages
 * (Debian/chromium, Maven/log4j-core, ...) have 100-800 CVEs and
 * the LATERAL CVSS join + ranges_json/versions_json columns make
 * each row chunky. Hit rate is per (ecosystem, name) so it depends
 * on whether the same page gets multiple views in 60s — heavy
 * social-share or crawler traffic benefits the most.
 *
 * Eviction (no lru-cache dep): sweep-then-clear. On insert, first
 * remove expired entries; if size still > MAX_ENTRIES, clear the
 * whole Map (worst case one cache-miss storm, recovers in 60s).
 * Strict LRU isn't worth the dep here.
 *
 * Cache key includes the limit so a 100-row render and an
 * unlimited "show all" fetch don't collide.
 */
const PACKAGE_BUNDLE_CACHE = new Map<
  string,
  { at: number; value: PackageBundle | null }
>();
const PACKAGE_BUNDLE_TTL_MS = 60_000;
const PACKAGE_BUNDLE_MAX_ENTRIES = 200;

function bundleCacheKey(
  ecosystem: string,
  name: string,
  limit: number | undefined,
): string {
  return `${ecosystem}/${name}#${limit ?? "all"}`;
}

function bundleCacheGet(key: string): PackageBundle | null | undefined {
  const hit = PACKAGE_BUNDLE_CACHE.get(key);
  if (!hit) return undefined;
  if (Date.now() - hit.at >= PACKAGE_BUNDLE_TTL_MS) {
    PACKAGE_BUNDLE_CACHE.delete(key);
    return undefined;
  }
  return hit.value;
}

function bundleCacheSet(key: string, value: PackageBundle | null): void {
  // Lazy sweep: clear expired before adding. Cheap when cache is
  // small; bounded by MAX_ENTRIES.
  const now = Date.now();
  for (const [k, v] of PACKAGE_BUNDLE_CACHE) {
    if (now - v.at >= PACKAGE_BUNDLE_TTL_MS) PACKAGE_BUNDLE_CACHE.delete(k);
  }
  if (PACKAGE_BUNDLE_CACHE.size >= PACKAGE_BUNDLE_MAX_ENTRIES) {
    PACKAGE_BUNDLE_CACHE.clear();
  }
  PACKAGE_BUNDLE_CACHE.set(key, { at: now, value });
}

export interface PackageMetadata {
  package: { id: number; ecosystem: string; name: string };
  cve_count: number;
}

/**
 * Lightweight metadata for `generateMetadata` — title and OG tags
 * need the package identity + CVE count, not the full CVE bundle.
 * Avoids a duplicate full-bundle fetch during SSR.
 */
export async function getPackageMetadata(
  ecosystem: string,
  name: string,
): Promise<PackageMetadata | null> {
  const { rows: pkgRows } = await pool.query<PackageMetadata["package"]>(
    `SELECT id, ecosystem, name FROM packages WHERE ecosystem = ? AND name = ?`,
    [ecosystem, name],
  );
  if (pkgRows.length === 0) return null;
  const pkg = pkgRows[0];
  const { rows: cntRows } = await pool.query<{ n: number }>(
    `SELECT COUNT(*) AS n FROM affected WHERE package_id = ?`,
    [pkg.id],
  );
  return { package: pkg, cve_count: cntRows[0]?.n ?? 0 };
}

export async function getPackageWithCves(
  ecosystem: string,
  name: string,
  limit?: number,
): Promise<PackageBundle | null> {
  const cacheKey = bundleCacheKey(ecosystem, name, limit);
  const cached = bundleCacheGet(cacheKey);
  if (cached !== undefined) return cached;

  const { rows: pkgRows } = await pool.query<PackageBundle["package"]>(
    `SELECT id, ecosystem, name FROM packages WHERE ecosystem = ? AND name = ?`,
    [ecosystem, name],
  );
  if (pkgRows.length === 0) {
    bundleCacheSet(cacheKey, null);
    return null;
  }
  const pkg = pkgRows[0];

  // The D1 schema has no `exploits` table (Postgres-only enrichment), so
  // exploits_count is always 0 here. The correlated subqueries below pick
  // the highest-scoring CVSS row per CVE (SQLite has no LATERAL).
  const limitSql = typeof limit === "number" && limit > 0 ? `LIMIT ${limit}` : "";

  const { rows: rawCves } = await pool.query<
    Omit<PackageBundle["cves"][number], "ranges_json" | "versions_json"> & {
      ranges_json: unknown;
      versions_json: unknown;
    }
  >(
    `
    SELECT v.cve_id, v.summary, v.description, v.kev,
           CAST(v.epss_score AS REAL) AS epss_score,
           (SELECT severity FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
             ORDER BY base_score DESC LIMIT 1) AS severity,
           CAST((SELECT base_score FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
             ORDER BY base_score DESC LIMIT 1) AS REAL) AS base_score,
           a.ranges_json, a.versions_json,
           0 AS exploits_count
      FROM affected a
      JOIN vulnerabilities v ON v.cve_id = a.cve_id
     WHERE a.package_id = ?
     ORDER BY v.kev DESC,
              (SELECT base_score FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
                ORDER BY base_score DESC LIMIT 1) DESC,
              v.published_at DESC
    ${limitSql}
    `,
    [pkg.id],
  );
  const cves: PackageBundle["cves"] = rawCves.map((c) => ({
    ...c,
    kev: Boolean(c.kev),
    ranges_json: parseJsonColumn<OsvRange[]>(c.ranges_json) ?? [],
    versions_json: parseJsonColumn<string[]>(c.versions_json),
  }));
  const bundle: PackageBundle = { package: pkg, cves };
  bundleCacheSet(cacheKey, bundle);
  return bundle;
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
    epss_score: number | null;
    fixed_in: string | null;
    summary: string | null;
    exploits_count: number;
  }>;
  recommended_version: string | null;
  /** Set by /check-batch when the package isn't in our DB. The CLI
   *  surfaces it so users can see which inputs couldn't be checked. */
  unknown?: boolean;
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
        epss_score: c.epss_score,
        fixed_in: r.fixedIn,
        summary: c.summary,
        exploits_count: c.exploits_count ?? 0,
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

export interface DashboardStats {
  new_today: number;
  new_week: number;
  critical_total: number;
  kev_total: number;
  package_total: number;
  vuln_total: number;
}

// 60s in-memory cache. The six COUNT(*) subqueries each force buffer-cache
// thrashing on the 243MB vulnerabilities table on our 512MB DB machine,
// taking 20+ seconds on cold cache. The displayed numbers change at most
// every few minutes during ingest, so a 60s TTL is generous from a UX
// perspective and removes the per-pageview cost entirely. Per-process
// memory (lives in the web Node process); two web machines would each
// hold an independent copy — fine, both stale at most 60s.
let dashboardStatsCache: { at: number; value: DashboardStats } | null = null;
const DASHBOARD_STATS_TTL_MS = 60_000;

export async function getDashboardStats(): Promise<DashboardStats> {
  const now = Date.now();
  if (dashboardStatsCache && now - dashboardStatsCache.at < DASHBOARD_STATS_TTL_MS) {
    return dashboardStatsCache.value;
  }
  const { rows } = await pool.query(`
    SELECT
      (SELECT COUNT(*) FROM vulnerabilities WHERE published_at > datetime('now','-1 day')) AS new_today,
      (SELECT COUNT(*) FROM vulnerabilities WHERE published_at > datetime('now','-7 days')) AS new_week,
      (SELECT COUNT(*) FROM cvss_scores WHERE severity = 'CRITICAL') AS critical_total,
      (SELECT COUNT(*) FROM vulnerabilities WHERE kev = 1) AS kev_total,
      (SELECT COUNT(*) FROM packages) AS package_total,
      (SELECT COUNT(*) FROM vulnerabilities) AS vuln_total
  `);
  const value = rows[0] as DashboardStats;
  dashboardStatsCache = { at: now, value };
  return value;
}

async function _getRecentKev(limit: number) {
  const { rows } = await pool.query(
    `SELECT cve_id, summary, description, kev_added_at
       FROM vulnerabilities
      WHERE kev = 1
      ORDER BY kev_added_at DESC
      LIMIT ?`,
    [limit],
  );
  return rows as Array<{ cve_id: string; summary: string | null; description: string | null; kev_added_at: Date | null }>;
}
export const getRecentKev = unstable_cache(_getRecentKev, ["getRecentKev"], {
  revalidate: SSR_CACHE_TTL_SEC,
});

async function _getTopPackages(ecosystem: string, limit: number) {
  // Drive the join from `affected` rather than `packages`. The new
  // composite index idx_affected_eco_pkg (ecosystem, package_id)
  // INCLUDE (cve_id) — created in migration 0006 — lets PG enter the
  // affected table via the ecosystem key directly and run COUNT(DISTINCT
  // cve_id) as an index-only scan.
  const { rows } = await pool.query(
    `SELECT a.ecosystem, p.name, COUNT(DISTINCT a.cve_id) AS cve_count,
            COUNT(*) FILTER (WHERE v.kev = 1) AS kev_count
       FROM affected a
       JOIN packages p ON p.id = a.package_id
       JOIN vulnerabilities v ON v.cve_id = a.cve_id
      WHERE a.ecosystem = ?
      GROUP BY a.ecosystem, p.name
      ORDER BY kev_count DESC, cve_count DESC
      LIMIT ?`,
    [ecosystem, limit],
  );
  return rows as Array<{ ecosystem: string; name: string; cve_count: number; kev_count: number }>;
}
// Wrapped in unstable_cache: the homepage calls this 6× per render
// (one per featured ecosystem) and it's the slowest query on the page.
// Cache key includes ecosystem + limit via args, so PyPI's cache doesn't
// collide with Maven's. TTL 60s — fresh enough for browsing.
export const getTopPackages = (ecosystem: string, limit = 12) =>
  unstable_cache(_getTopPackages, ["getTopPackages", ecosystem, String(limit)], {
    revalidate: SSR_CACHE_TTL_SEC,
  })(ecosystem, limit);

export interface PackageListFilter {
  q?: string;
  ecosystem?: string;
  sort?: "cves" | "name";
  page?: number;
  pageSize?: number;
}

async function _browsePackages(f: PackageListFilter) {
  const pageSize = Math.min(100, Math.max(1, f.pageSize ?? 50));
  const page = Math.max(1, f.page ?? 1);
  const offset = (page - 1) * pageSize;
  // Package-name predicate builder. On D1 the fuzzy match uses the
  // `packages_fts` trigram index (needs ≥3-char tokens); shorter queries
  // fall back to a plain infix LIKE so 1–2 char searches still work.
  const q = f.q?.trim() || "";
  const useFts = q.length >= 3;
  function nameMatchClause(): { clause: string; param: unknown } {
    return useFts
      ? { clause: `p.id IN (SELECT rowid FROM packages_fts WHERE packages_fts MATCH ?)`, param: trigramQuery(q) }
      : { clause: `p.name LIKE ?`, param: `%${q}%` };
  }

  const pkgWhere: string[] = [];
  const params: unknown[] = [];
  if (q) {
    const nm = nameMatchClause();
    pkgWhere.push(nm.clause);
    params.push(nm.param);
  }
  if (f.ecosystem) {
    pkgWhere.push(`p.ecosystem = ?`);
    params.push(f.ecosystem);
  }
  const pkgWhereSql = pkgWhere.length ? `WHERE ${pkgWhere.join(" AND ")}` : "";

  // Count over packages alone — fast, only touches the 15k-row table.
  const totalRes = await pool.query<{ c: number }>(
    `SELECT COUNT(*) AS c FROM packages p ${pkgWhereSql}`,
    params,
  );
  const total = totalRes.rows[0]?.c ?? 0;

  // Previously this query did `FROM packages p LEFT JOIN affected a LEFT
  // JOIN vulnerabilities v ... GROUP BY p.ecosystem, p.name` which forced
  // a full scan of the 120k-row affected table for every page request,
  // even with pagination. The new shape pre-aggregates from affected
  // first (using idx_affected_eco_pkg when ecosystem is filtered, or
  // idx_affected_pkg as a smaller scan), then joins the 15k packages
  // by PK. ORDER BY happens before pagination, so the aggregate is
  // computed once over the eligible affected rows, not per page.
  const orderBy = f.sort === "name"
    ? "p.ecosystem, p.name"
    : "agg.kev_count DESC, agg.cve_count DESC, p.name";

  // affected-side filter: same predicates as packages where applicable,
  // so the pre-aggregate already excludes packages we won't show.
  // Params are appended in positional order to match the `?` placeholders:
  // [agg ecosystem?, outer name?, outer ecosystem?, pageSize, offset].
  const affParams: unknown[] = [];
  const affWhere: string[] = [];
  if (f.ecosystem) {
    affWhere.push(`a.ecosystem = ?`);
    affParams.push(f.ecosystem);
  }
  const affWhereSql = affWhere.length ? `WHERE ${affWhere.join(" AND ")}` : "";

  // Push name-filter + ecosystem-filter into the outer SELECT against
  // packages so we can still narrow by name without breaking the
  // pre-aggregate's index path.
  const nameFilterClauses: string[] = [];
  if (q) {
    const nm = nameMatchClause();
    nameFilterClauses.push(nm.clause);
    affParams.push(nm.param);
  }
  if (f.ecosystem) {
    nameFilterClauses.push(`p.ecosystem = ?`);
    affParams.push(f.ecosystem);
  }
  const outerWhereSql = nameFilterClauses.length
    ? `WHERE ${nameFilterClauses.join(" AND ")}`
    : "";

  affParams.push(pageSize);
  affParams.push(offset);
  const { rows } = await pool.query(
    `WITH agg AS (
       SELECT a.package_id,
              COUNT(DISTINCT a.cve_id) AS cve_count,
              COUNT(*) FILTER (WHERE v.kev = 1) AS kev_count
         FROM affected a
         JOIN vulnerabilities v ON v.cve_id = a.cve_id
         ${affWhereSql}
        GROUP BY a.package_id
     )
     SELECT p.ecosystem, p.name,
            COALESCE(agg.cve_count, 0) AS cve_count,
            COALESCE(agg.kev_count, 0) AS kev_count
       FROM packages p
       LEFT JOIN agg ON agg.package_id = p.id
       ${outerWhereSql}
      ORDER BY ${orderBy}
      LIMIT ? OFFSET ?`,
    affParams,
  );
  return {
    items: rows as Array<{ ecosystem: string; name: string; cve_count: number; kev_count: number }>,
    total,
  };
}

/**
 * Cache key for browsePackages. Every filter combination gets its own
 * cache entry; the production traffic mix is dominated by the default
 * /packages first page, so the cache hit rate on that one entry alone
 * is very high. Free-text search (`q`) blows the cache up to a unique
 * entry per query, which is fine — those entries also serve repeat
 * searches for the same string.
 */
export function browsePackages(f: PackageListFilter) {
  const key = [
    "browsePackages",
    f.q?.trim() ?? "",
    f.ecosystem ?? "",
    f.sort ?? "cves",
    String(f.page ?? 1),
    String(f.pageSize ?? 50),
  ];
  return unstable_cache(_browsePackages, key, { revalidate: SSR_CACHE_TTL_SEC })(f);
}

export async function autocompletePackages(prefix: string, limit = 10) {
  const q = prefix.trim();
  if (q.length < 2) return [];
  // Autocomplete is type-ahead — every keystroke fires this. The old shape
  // did a LEFT JOIN affected with COUNT(DISTINCT cve_id) per match, which
  // forced a scan of the 120k-row affected table on every keypress.
  //
  // Cve count was nice-to-have in the dropdown but not load-bearing for
  // UX; consumers can fetch it after the user clicks. cve_count is kept
  // in the return shape as 0 so existing callers don't break — they
  // either ignore it or display it as "—".
  //
  // Result is a pure packages-table query. On D1 the infix match uses the
  // `packages_fts` trigram index for ≥3-char queries; 2-char queries fall
  // back to a plain infix LIKE (trigram needs ≥3-char tokens). Prefix
  // matches sort first via the CASE so type-ahead feels responsive.
  const infixMatch =
    q.length >= 3
      ? `id IN (SELECT rowid FROM packages_fts WHERE packages_fts MATCH ?)`
      : `name LIKE ?`;
  const infixParam = q.length >= 3 ? trigramQuery(q) : `%${q}%`;
  const { rows } = await pool.query(
    `SELECT ecosystem, name
       FROM packages
      WHERE ${infixMatch}
      ORDER BY (CASE WHEN name LIKE ? || '%' THEN 0 ELSE 1 END), name
      LIMIT ?`,
    [infixParam, q, limit],
  );
  return rows.map((r) => ({ ...r, cve_count: 0 })) as Array<{
    ecosystem: string;
    name: string;
    cve_count: number;
  }>;
}

async function _getRecentVulns(limit: number) {
  const { rows } = await pool.query<{
    cve_id: string; summary: string | null; description: string | null;
    published_at: Date | null;
    kev: boolean; severity: string | null; base_score: number | null;
  }>(
    `SELECT v.cve_id, v.summary, v.description, v.published_at, v.kev,
            (SELECT severity FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
              ORDER BY base_score DESC LIMIT 1) AS severity,
            CAST((SELECT base_score FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
              ORDER BY base_score DESC LIMIT 1) AS REAL) AS base_score
       FROM vulnerabilities v
      WHERE v.published_at IS NOT NULL
      ORDER BY v.published_at DESC
      LIMIT ?`,
    [limit],
  );
  return rows.map(coerceKev);
}
export const getRecentVulns = (limit = 10) =>
  unstable_cache(_getRecentVulns, ["getRecentVulns", String(limit)], {
    revalidate: SSR_CACHE_TTL_SEC,
  })(limit);

/**
 * Top N recent CVEs for a (ecosystem, packageName) pair, joined with
 * the highest CVSS severity per CVE. Returns [] if the package is
 * unknown — callers should display a "no CVEs known yet" placeholder
 * rather than treating it as an error.
 *
 * Used by the Pro tier watchlist dashboard to show "what's the latest
 * thing I should worry about on this package" without forcing the
 * user to navigate to the full package page.
 *
 * Sort: published_at DESC (most recent first), NULLs last. We
 * deliberately don't apply the KEV-first reordering that
 * getPackageWithCves does, because the dashboard wants "what just
 * dropped" not "what's most exploited in history".
 */
export async function getLatestCvesForPackage(
  ecosystem: string,
  name: string,
  limit = 3,
): Promise<VulnListItem[]> {
  const { rows } = await pool.query<VulnListItem>(
    `
    SELECT v.cve_id, v.summary, v.description,
           v.published_at, v.modified_at,
           v.kev, v.kev_added_at,
           CAST(v.epss_score AS REAL) AS epss_score,
           CAST(v.epss_percentile AS REAL) AS epss_percentile,
           (SELECT severity FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
             ORDER BY base_score DESC LIMIT 1) AS severity,
           CAST((SELECT base_score FROM cvss_scores cs WHERE cs.cve_id = v.cve_id
             ORDER BY base_score DESC LIMIT 1) AS REAL) AS base_score
      FROM affected a
      JOIN packages p ON p.id = a.package_id
      JOIN vulnerabilities v ON v.cve_id = a.cve_id
     WHERE p.ecosystem = ? AND p.name = ?
     ORDER BY v.published_at DESC
     LIMIT ?
    `,
    [ecosystem, name, limit],
  );
  return rows.map(coerceKev);
}

/**
 * Distinct concrete versions OSV has on file for a (ecosystem, name)
 * pair. Powers the version dropdown shown in the watchlist add flow.
 *
 * OSV records affected ranges (with `introduced` / `fixed` events)
 * and sometimes explicit version lists. We pull both, dedupe, and
 * return ordered DESC (newest-looking first per a loose lexical sort
 * — semver-aware sort would be nicer but the dropdown is bounded to
 * `limit` so the cost of mis-ordering tail entries is small).
 *
 * Returns [] if the package is unknown or OSV only has range data
 * without enumerable versions. Callers should fall back to a
 * free-text input in that case.
 */
export async function getPackageVersions(
  ecosystem: string,
  name: string,
  limit = 40,
): Promise<string[]> {
  const { rows } = await pool.query<{ version: string }>(
    `
    WITH pkg AS (
      SELECT id FROM packages WHERE ecosystem = ? AND name = ?
    ),
    versions_from_list AS (
      SELECT je.value AS version
        FROM affected a
        JOIN pkg ON pkg.id = a.package_id
       CROSS JOIN json_each(a.versions_json) je
       WHERE a.versions_json IS NOT NULL AND a.versions_json <> ''
    ),
    versions_from_ranges AS (
      SELECT json_extract(ev.value, '$.introduced') AS version
        FROM affected a
        JOIN pkg ON pkg.id = a.package_id
       CROSS JOIN json_each(a.ranges_json) r
       CROSS JOIN json_each(json_extract(r.value, '$.events')) ev
       WHERE a.ranges_json IS NOT NULL AND a.ranges_json <> ''
         AND json_extract(ev.value, '$.introduced') IS NOT NULL
         AND json_extract(ev.value, '$.introduced') <> '0'
      UNION
      SELECT json_extract(ev.value, '$.fixed') AS version
        FROM affected a
        JOIN pkg ON pkg.id = a.package_id
       CROSS JOIN json_each(a.ranges_json) r
       CROSS JOIN json_each(json_extract(r.value, '$.events')) ev
       WHERE a.ranges_json IS NOT NULL AND a.ranges_json <> ''
         AND json_extract(ev.value, '$.fixed') IS NOT NULL
    )
    SELECT DISTINCT version
      FROM (
        SELECT version FROM versions_from_list
        UNION
        SELECT version FROM versions_from_ranges
      ) all_versions
     WHERE version IS NOT NULL AND version <> ''
     ORDER BY version DESC
     LIMIT ?
    `,
    [ecosystem, name, limit],
  );
  return rows.map((r) => r.version);
}

/**
 * Top N recent CVEs for a (ecosystem, packageName) pair, joined with
 * the highest CVSS severity per CVE. Returns [] if the package is
 * unknown — callers should display a "no CVEs known yet" placeholder
 * rather than treating it as an error.
 *
 * Used by the Pro tier watchlist dashboard to show "what's the latest
 * thing I should worry about on this package" without forcing the
 * user to navigate to the full package page.
 *
 * Sort: published_at DESC (most recent first), NULLs last. We
 * deliberately don't apply the KEV-first reordering that
 * getPackageWithCves does, because the dashboard wants "what just
 * dropped" not "what's most exploited in history".
 */
// (function definition moved earlier in the file — see getLatestCvesForPackage above)

// Suppress unused-import warnings in clients that don't need drizzle.
void db;
void sql;
