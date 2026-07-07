# Request-Path Query Optimization — Design

**Date:** 2026-07-07
**Status:** Approved (brainstorming) → ready for implementation plan

## Goal

Eliminate every request-path query capable of overloading D1. Move all
whole-table aggregation from page render time to ingest time; make the
remaining caches actually work on Cloudflare Workers.

## Background — the 2026-07-06/07 D1 overload

Production D1 (`vulnscope`, 74,280 vulns / 119,395 affected / 65,791
cvss_scores / 15,839 packages, ~286 MB) went into a sustained
`D1 DB is overloaded. Requests queued for too long.` state, taking the
live site down intermittently (Server Components render errors on `/zh`
and CVE pages). Trigger was ad-hoc full-table scans during debugging, but
the audit found the site's own request path runs the same class of
queries on every cold render:

| Page | Query | Cost |
| --- | --- | --- |
| `/` `/zh` (force-dynamic) | `getDashboardStats`: `COUNT(*) FROM vulnerabilities` | full scan 74k |
| 〃 | `COUNT(*) FROM cvss_scores WHERE severity='CRITICAL'` | full scan 66k (no severity index) |
| 〃 | `COUNT(*) FROM packages` | full scan 16k |
| 〃 | `getTopPackages(eco, 8)` × 6, sequential | full scan 119k `affected` + join, ×6 — `idx_affected_eco_pkg` exists only in the old Postgres migration, never in the D1 schema |
| `/insights/most-vulnerable-packages` | `getTopPackagesAllEcos` | 119k agg per view |
| `/insights/ecosystem/[eco]` | `getEcosystemDeepDive` | 119k agg per view |
| `/packages` | `browsePackages` agg CTE | 119k agg per view |
| `/search` (no filter) | `COUNT(*) FROM vulnerabilities` for total | full scan 74k |
| `sitemap.xml` (force-dynamic) | 20k-row list + top-5000 package agg | heavy, hit by crawlers |

All mitigations that made this survivable on fly.io are silently dead on
Workers:

- `open-next.config.ts` is `defineCloudflareConfig()` with **no
  incremental cache backend** → `unstable_cache` has no shared store.
- Hand-rolled in-memory Maps (`dashboardStatsCache`,
  `PACKAGE_BUNDLE_CACHE`) are per-isolate; Workers isolates are many,
  short-lived, and global → effectively always cold.
- Every data page is `force-dynamic`, so each request SSRs against D1.

## Design principle

**Data changes only at ingest → aggregate at ingest.** The request path
performs only indexed point/range reads. Additionally, give
`unstable_cache` a real (KV) backend as a defense-in-depth layer.

## Phase 1 — Precomputed stats layer

### New table: `page_stats` (single row)

```sql
CREATE TABLE IF NOT EXISTS page_stats (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  vuln_total INTEGER NOT NULL DEFAULT 0,
  package_total INTEGER NOT NULL DEFAULT 0,
  critical_total INTEGER NOT NULL DEFAULT 0,
  kev_total INTEGER NOT NULL DEFAULT 0,
  computed_at TEXT
);
```

- `getDashboardStats` reads this row for the four expensive totals.
- `new_today` / `new_week` stay live: they are `idx_vuln_published`
  range scans over a few hundred rows — cheap and inherently
  time-relative (a precomputed value would go stale within the day).
- `searchVulns` with **no filters** uses `vuln_total` instead of
  `COUNT(*)`; filtered searches keep their (index-assisted) counts.

### New table: `package_stats` (~16k rows, all packages)

```sql
CREATE TABLE IF NOT EXISTS package_stats (
  package_id INTEGER PRIMARY KEY,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,            -- denormalized to avoid a join
  cve_count INTEGER NOT NULL DEFAULT 0,
  kev_count INTEGER NOT NULL DEFAULT 0,
  max_epss REAL
);
CREATE INDEX IF NOT EXISTS idx_pkgstats_eco_rank
  ON package_stats(ecosystem, kev_count DESC, cve_count DESC);
CREATE INDEX IF NOT EXISTS idx_pkgstats_rank
  ON package_stats(kev_count DESC, cve_count DESC);
```

Replaces every 119k-row aggregation:

| Consumer | New shape |
| --- | --- |
| `getTopPackages(eco, n)` (homepage ×6) | `SELECT … FROM package_stats WHERE ecosystem=? ORDER BY kev_count DESC, cve_count DESC LIMIT n` (indexed) |
| `getTopPackagesAllEcos` | same, no ecosystem filter, via `idx_pkgstats_rank` |
| `getEcosystemDeepDive` | same as getTopPackages with larger limit |
| `browsePackages` | drop the agg CTE; `LEFT JOIN package_stats` for counts/sort |
| `sitemap` top-5000 packages | read `package_stats` |
| `getPackageMetadata` cve_count | read `package_stats` (falls back to 0 if row missing) |

**No new indexes on big tables.** With the stats tables in place, the
formerly missing `idx_affected_eco_pkg` and a severity index become
unnecessary (their only would-be consumers now read `package_stats` /
`page_stats`). This also avoids a risky 119k-row `CREATE INDEX` build on
production D1.

### Freshness — how ingest keeps the tables current

**Full build (`build-sqlite.ts`):** compute both tables at the end of
the build with plain SQL aggregation (local SQLite — full scans are fine
locally).

**Daily delta (`push-to-d1.sh` delta mode):** the incremental SQLite
holds only changed records, so stats refresh runs **on D1, but strictly
scoped and sharded** so no single request does unbounded work:

1. *Delta CVE manifest.* The delta SQL creates a scratch table
   `_delta_cves(cve_id TEXT PRIMARY KEY)` and inserts the delta's CVE ids
   (small batches, sentinel-delimited like all other delta statements).
2. *`package_stats` scoped recompute.* Recompute rows **only for
   packages touched by the delta**: touched `package_id`s are found via
   `idx_affected_cve` over `_delta_cves` (typically a few hundred), each
   recomputed via `idx_affected_pkg`. All index-driven; emitted after
   the data statements.
3. *`page_stats` chunked recount.* Never `COUNT(*)` the whole table in
   one statement. Shard into bounded, index-driven chunks accumulated in
   a scratch table `_stats_scratch(k TEXT, v INTEGER)`:
   - `vuln_total`: ~30 PK-range chunks by CVE year
     (`cve_id >= 'CVE-2021-' AND cve_id < 'CVE-2022-'`).
   - `package_total`: 13 chunks by ecosystem via `idx_pkg_eco_name`.
   - `critical_total`: ~30 chunks by CVE-year prefix range on
     `cvss_scores.cve_id` via `idx_cvss_cve`, each chunk filtering
     `severity='CRITICAL'`.
   - `kev_total`: single statement via `idx_vuln_kev` (~1.6k rows).
   Then one `UPDATE page_stats … FROM _stats_scratch`, then drop scratch
   tables. Statements ride the existing sentinel batcher, so each D1
   request carries only a bounded slice.
4. Scratch tables are dropped at the end; a failed push leaves at worst
   a stale-but-consistent `page_stats` (yesterday's totals) and
   partially-refreshed `package_stats` rows that the next successful run
   re-covers (recompute is idempotent).

**Where the SQL lives:** a new pure module
`src/lib/ingest/stats-sql.ts` generates all statement lists (full-build
compute, sharded rebuild, scoped recompute, chunked recount) so they are
unit-testable; `build-sqlite.ts` executes them locally and a small CLI
(`scripts/emit-stats-sql.ts`) lets `push-to-d1.sh` append them to the
delta stream.

### Rollout (no downtime, no reseed)

Additive migration on live D1:

1. Delta-push the DDL (`CREATE TABLE IF NOT EXISTS` + small indexes on
   the 16k-row `package_stats` only).
2. Run a one-time **sharded full rebuild** of both tables on D1 — the
   same chunked machinery as the daily refresh, just unscoped: ~40–80
   small statements, each bounded and index-driven (~16k row writes
   total).
3. Deploy the query-layer changes.
4. Daily deltas keep the tables fresh from then on.

Full reseed remains the fallback if the additive path misbehaves.

## Phase 2 — Real caching on Workers

1. **KV incremental cache.** Create a KV namespace; bind it as
   `NEXT_INC_CACHE` in `wrangler.jsonc`; set
   `defineCloudflareConfig({ incrementalCache: kvIncrementalCache })`
   (import from
   `@opennextjs/cloudflare/overrides/incremental-cache/kv-incremental-cache`).
   Every existing `unstable_cache` (insights, browsePackages,
   getRecentKev, getRecentVulns…) becomes a real shared 60s cache.
2. **Retire hand-rolled Maps.** Replace `dashboardStatsCache` and
   `PACKAGE_BUNDLE_CACHE` with `unstable_cache` wrappers so all caching
   goes through one (now-working) mechanism.
3. **Sitemap caching.** `sitemap.xml` responses get
   `Cache-Control: public, s-maxage=3600` (edge-cacheable; crawlers stop
   re-triggering the 20k-row query).

## Error handling

| Situation | Handling |
| --- | --- |
| `page_stats` row missing (pre-migration D1) | `getDashboardStats` falls back to zeros for the four totals; page renders |
| `package_stats` row missing for a package | counts render as 0 (same as today's LEFT JOIN semantics) |
| Delta stats-refresh statements fail mid-push | tables stay stale-but-consistent; next daily run re-covers (idempotent) |
| KV namespace absent in a preview env | opennext falls back to no cache — identical to today |

## Testing

| Component | Tests |
| --- | --- |
| `stats-sql.ts` | vitest: statement generation (chunk boundaries, scoped-recompute SQL, scratch lifecycle, quoting) |
| Full build | integration: build a small SQLite, assert `page_stats`/`package_stats` contents match hand-computed aggregates |
| Query layer swaps | existing query tests updated; new tests for fallback-to-zero paths |
| Delta refresh | throwaway D1 e2e: seed → delta push → assert stats rows updated, scratch tables dropped |
| Regression | 231-test suite + tsc stay green |

## Out of scope

- `getFreshness`/`isIngestRunning` footer queries (indexed, has
  fallbacks; benefits automatically from Phase 2 KV cache if wrapped
  later).
- Semver-aware ordering, exploits table, or any data-model change to
  `affected`/`packages` (the earlier natural-key idea is superseded by
  this design — with aggregation moved to ingest, the N+1-prone delta
  subqueries stop being on any hot path).
- Edge Cache Rules for HTML pages (tracked in `docs/edge-caching.md`).
