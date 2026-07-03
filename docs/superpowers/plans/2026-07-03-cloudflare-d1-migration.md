# VulnScope → Cloudflare Workers + D1 Migration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move VulnScope off fly.io to run 100% free on Cloudflare — Workers (via OpenNext) serving the Next.js App Router site, reading CVE data from Cloudflare D1, with ingest run by GitHub Actions. Drop the SaaS tier entirely; keep full-text + fuzzy search.

**Architecture:** GitHub Actions runs the existing Node ingest scripts on a schedule, builds a local SQLite file (with FTS5 search indexes), and pushes it to D1 (`wrangler d1 execute --file --remote`). Cloudflare Workers serves every CVE page at the edge, reading from D1 via the OpenNext D1 binding. No VM, no Postgres, no auth/billing. Steady-state cost is $0; a one-time cold seed exceeds D1's free daily write cap and needs one paid month (~$5).

**Tech Stack:** Next.js 15 App Router, `@opennextjs/cloudflare`, Cloudflare Workers + D1 (SQLite) + Cache API, `better-sqlite3` (ingest sink), GitHub Actions, `wrangler` (≥ 4.107 for `d1 import`; 4.69 works with `d1 execute --file`).

## Global Constraints

- **D1 free per-database limit: 500 MB** (conservative planning number; account total 5 GB). Phase-0 measured the full 13-ecosystem dataset + FTS5 at **~286 MB in D1** — fits with ~43% headroom. Do NOT let the dataset grow past ~400 MB without re-checking.
- **D1 free write cap: 100,000 rows/day.** Phase-0 measured a cold seed at **~587k rows (data) + ~90k (FTS) = ~677k write-units** — 6.7× the daily cap. Cold seed therefore requires either a paid month or a multi-day split. Steady-state daily deltas must stay under 100k.
- **D1 free read cap: 5,000,000 rows/day.** A single un-indexed query in Phase-0 read 65,800 rows. Every list/search/detail query MUST be backed by an index AND fronted by the Workers Cache API, or crawler traffic blows the read cap.
- **Workers free: 100,000 requests/day.** Static assets don't count; each dynamic (SSR) render does. CVE pages MUST be edge-cached (they change ~daily) so crawlers hit cache, not the Worker.
- **Bilingual is UI-only** (next-intl `messages/en.json`, `messages/zh.json`) over ONE shared English CVE dataset. There is ONE D1 database, not two. Do not duplicate data per locale.
- **No SaaS.** No `better-auth`, `@polar-sh/sdk`, `resend`, no user accounts, watchlist, admin, or Pro tier. These are deleted, not ported.
- Preserve every CVE getting its own page and working search (FTS5 full-text + trigram fuzzy package search).

---

## File Structure

**Deleted (SaaS removal):**
- `pro/`, `pro-stub/` (entire dirs), `src/lib/pro-bridge.ts`
- Routes: `src/app/[locale]/{account,dashboard,sign-in,pricing,admin}/`, `src/app/api/auth/`, `src/app/api/v1/{admin,billing,watchlist}/`
- `src/lib/scheduler.ts`, `src/instrumentation-node.ts`, `src/instrumentation.ts` (in-process scheduler — replaced by GitHub Actions)
- `src/lib/rate-limit.ts`, `src/lib/rate-limit-auth.ts` (no origin/DB-write to protect once reads are cached)
- `src/components/dashboard/`

**New:**
- `src/db/d1.ts` — D1 binding accessor for the Worker (replaces `pg` Pool in `src/db/client.ts`)
- `scripts/build-sqlite.ts` — ingest sink: build local SQLite + FTS5 from OSV/KEV/EPSS
- `scripts/push-to-d1.sh` — dump SQLite → strip transactions → `wrangler d1 execute --file --remote`
- `wrangler.jsonc` — Worker + D1 binding config
- `open-next.config.ts` — OpenNext adapter config
- `.github/workflows/ingest.yml` — scheduled ingest → D1

**Modified:**
- `src/lib/queries.ts` — rewrite ~10 Postgres-specific sites for SQLite/D1 (line refs in tasks below)
- `src/lib/insights.ts` — same class of rewrites (LATERAL → window, FILTER kept, casts)
- `src/db/schema.ts` — Drizzle SQLite schema (or raw D1; queries use raw `pool.query` today)
- `next.config.ts` — remove `output: standalone`, `@pro` alias, SaaS `serverExternalPackages`
- `src/app/[locale]/cve/[id]/page.tsx` (line 11) & `src/app/[locale]/package/[ecosystem]/[name]/page.tsx` (line 11) — remove `@pro/components/AddToWatchlistCTA` import + JSX
- `package.json` — drop `better-auth`, `@polar-sh/sdk`, `resend`; add `@opennextjs/cloudflare`, `better-sqlite3`

---

## Phase 0: Feasibility spike — COMPLETE ✅

Already executed 2026-07-03. Results (recorded here as the baseline the rest of the plan depends on):
- Full 13-ecosystem dataset (74,280 CVEs, 15,839 packages, 119,395 affected, 237,574 refs) → SQLite **292 MB local / 286 MB in D1** including FTS5. **Fits under 500 MB.**
- FTS5 full-text (`porter unicode61`) search for `'sql injection'` → correct CVEs, 2 rows read.
- FTS5 `trigram` package search for `'log4'` → `log4js`, `log4j:log4j`, `log4j-core`. Replaces pg_trgm.
- Cold seed wrote ~677k rows (6.7× daily cap → confirms one-time paid seed).
- Un-indexed `kev=1` join read 65,800 rows → confirms indexes + edge cache are mandatory.
- Artifacts: `scripts/phase0-pg-to-sqlite.sh`, `scratch-phase0/vulnscope.sqlite`, D1 db `vulnscope-phase0`.

No action needed; this phase informs the constraints above.

---

## Phase 1: Delete the SaaS tier

Goal: strip auth/billing/Pro so the codebase is a pure public read-only CVE site that still builds. Do this first — it removes the most complex build machinery (`@pro` open-core aliasing) and shrinks everything downstream.

### Task 1.1: Remove @pro usages from the two public pages

**Files:**
- Modify: `src/app/[locale]/cve/[id]/page.tsx` (import at line 11 + JSX usage)
- Modify: `src/app/[locale]/package/[ecosystem]/[name]/page.tsx` (import at line 11 + JSX usage)

**Interfaces:**
- Produces: two pages with no `@pro` dependency, so the `@pro` alias can be deleted in Task 1.3.

- [ ] **Step 1: Find the import and JSX usage in the CVE page**

Run: `grep -n "AddToWatchlistCTA" src/app/\[locale\]/cve/\[id\]/page.tsx`
Expected: the `import { AddToWatchlistCTA } from "@pro/components/AddToWatchlistCTA";` line and its `<AddToWatchlistCTA .../>` render site.

- [ ] **Step 2: Remove the import line and the JSX usage**

Delete the `import ... AddToWatchlistCTA ...` line and remove the `<AddToWatchlistCTA .../>` element from the JSX (delete the element, keep surrounding layout).

- [ ] **Step 3: Repeat for the package page**

Run: `grep -n "AddToWatchlistCTA" "src/app/[locale]/package/[ecosystem]/[name]/page.tsx"` and remove the import + JSX the same way.

- [ ] **Step 4: Verify no @pro references remain in app/**

Run: `grep -rn "@pro/" src/app`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add "src/app/[locale]/cve/[id]/page.tsx" "src/app/[locale]/package/[ecosystem]/[name]/page.tsx"
git commit -m "refactor: drop @pro watchlist CTA from public CVE/package pages"
```

### Task 1.2: Delete SaaS routes, dirs, and the in-process scheduler

**Files:**
- Delete: `pro/`, `pro-stub/`, `src/lib/pro-bridge.ts`
- Delete: `src/app/[locale]/{account,dashboard,sign-in,pricing,admin}/`
- Delete: `src/app/api/auth/`, `src/app/api/v1/{admin,billing,watchlist}/`
- Delete: `src/lib/scheduler.ts`, `src/instrumentation.ts`, `src/instrumentation-node.ts`
- Delete: `src/lib/rate-limit.ts`, `src/lib/rate-limit-auth.ts`, `src/components/dashboard/`

**Interfaces:**
- Produces: a route tree with no auth/billing/account surface; no in-process scheduler (ingest moves to GitHub Actions in Phase 5).

- [ ] **Step 1: Delete the directories and files**

```bash
cd /Users/jnr350/Desktop/Yansiang/cve_list
git rm -r pro pro-stub src/lib/pro-bridge.ts
git rm -r "src/app/[locale]/account" "src/app/[locale]/dashboard" "src/app/[locale]/sign-in" "src/app/[locale]/pricing" "src/app/[locale]/admin"
git rm -r src/app/api/auth src/app/api/v1/admin src/app/api/v1/billing src/app/api/v1/watchlist
git rm src/lib/scheduler.ts src/instrumentation.ts src/instrumentation-node.ts src/lib/rate-limit.ts src/lib/rate-limit-auth.ts
git rm -r src/components/dashboard
```

- [ ] **Step 2: Find dangling imports of deleted modules**

Run: `grep -rnE "scheduler|pro-bridge|rate-limit|@pro|instrumentation-node|dashboard/" src --include=*.ts --include=*.tsx | grep -v node_modules`
Expected: a list of files still importing deleted modules (e.g. `middleware.ts` importing rate-limit, layout importing auth). Note each for Step 3.

- [ ] **Step 3: Remove each dangling import and its usage**

For each hit from Step 2, delete the import and the code that used it. Common ones: `src/middleware.ts` (rate-limit calls → delete the rate-limit branch, keep the next-intl middleware), any `layout.tsx` auth/session reads → remove.

- [ ] **Step 4: Verify the app builds**

Run: `pnpm build`
Expected: build succeeds (no "module not found" for deleted paths). Fix any remaining dangling import it reports.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: remove SaaS tier (auth, billing, Pro, scheduler, rate-limit)"
```

### Task 1.3: Simplify next.config.ts and drop SaaS dependencies

**Files:**
- Modify: `next.config.ts` (remove `@pro` alias block, `output: standalone`, SaaS externals)
- Modify: `package.json` (remove `better-auth`, `@polar-sh/sdk`, `resend`)

**Interfaces:**
- Produces: a minimal `next.config.ts` with no open-core aliasing — the config OpenNext expects in Phase 4.

- [ ] **Step 1: Remove the @pro webpack alias and PRO_ROOT/existsSync logic from next.config.ts**

Delete the webpack `resolve.alias` entries mapping `@pro/*`, the `PRO_ROOT`/`existsSync` detection, and any `pro-stub` fallback. Remove `output: "standalone"` and `outputFileTracingRoot` (OpenNext replaces these).

- [ ] **Step 2: Trim serverExternalPackages**

In `next.config.ts`, remove `pg`, `better-auth`, `@polar-sh/sdk`, `yauzl`, `unzipper`, `undici` from `serverExternalPackages` (ingest-only + SaaS packages no longer bundled in the Worker). Leave the array empty or remove it if nothing remains.

- [ ] **Step 3: Remove SaaS deps from package.json**

```bash
pnpm remove better-auth @polar-sh/sdk resend
```

- [ ] **Step 4: Verify build still passes**

Run: `pnpm build`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add next.config.ts package.json pnpm-lock.yaml
git commit -m "chore: simplify next.config, drop SaaS dependencies"
```

---

## Phase 2: SQLite ingest sink (GitHub-Action side)

Goal: make the existing ingest write to a local SQLite file (via `better-sqlite3`) instead of Postgres, and build FTS5 indexes. The read/transform logic (zip streaming, EPSS parse) is reused verbatim; only the DB sink changes.

### Task 2.1: Add better-sqlite3 and a SQLite schema builder

**Files:**
- Create: `scripts/build-sqlite.ts`
- Modify: `package.json` (add `better-sqlite3`, `@types/better-sqlite3`)

**Interfaces:**
- Produces: `buildSchema(db: Database): void` creating the 6 base tables + indexes + 2 FTS5 tables, matching the Phase-0 schema (`scripts/phase0-pg-to-sqlite.sh`).

- [ ] **Step 1: Install better-sqlite3**

```bash
pnpm add better-sqlite3 && pnpm add -D @types/better-sqlite3
```

- [ ] **Step 2: Write the schema builder (reuse Phase-0 DDL verbatim)**

Create `scripts/build-sqlite.ts` with a `buildSchema(db)` function containing the exact CREATE TABLE / CREATE INDEX / CREATE VIRTUAL TABLE statements from `scripts/phase0-pg-to-sqlite.sh` (the `vulnerabilities/packages/affected/cvss_scores/vuln_aliases/refs` tables, the 10 indexes incl. `idx_vuln_kev`, and `vulns_fts` (porter unicode61) + `packages_fts` (trigram)).

- [ ] **Step 3: Smoke-test the schema builds**

```bash
node node_modules/tsx/dist/cli.mjs -e "import Database from 'better-sqlite3'; import {buildSchema} from './scripts/build-sqlite.ts'; const db=new Database(':memory:'); buildSchema(db); console.log(db.prepare(\"SELECT name FROM sqlite_master WHERE type='table'\").all().length,'tables');"
```
Expected: prints a table count ≥ 6 (plus FTS shadow tables).

- [ ] **Step 4: Commit**

```bash
git add scripts/build-sqlite.ts package.json pnpm-lock.yaml
git commit -m "feat(ingest): SQLite schema builder with FTS5 indexes"
```

### Task 2.2: Swap the ingest write-path to the SQLite sink

**Files:**
- Modify: `src/lib/ingest/osv-batch.ts` (the `flushVulns/flushCvss/flushAffected/flushRefs/flushAliases` + `getOrCreatePackageId`)
- Modify: `src/lib/ingest/epss.ts` (the `UPDATE ... FROM (VALUES ...)` flush)
- Modify: `src/lib/ingest/kev.ts` (KEV upsert)
- Modify: `scripts/build-sqlite.ts` (wire ingest → SQLite)

**Interfaces:**
- Consumes: `buildSchema(db)` from Task 2.1.
- Produces: `pnpm build:sqlite` produces `scratch-phase0/vulnscope.sqlite` (or a configured path) from live OSV/KEV/EPSS.

- [ ] **Step 1: Parameterize the sink**

The ingest `flush*` functions take an `IngestPool`/`IngestDb`. Add a `better-sqlite3`-backed adapter exposing the same insert surface, using `INSERT ... ON CONFLICT DO UPDATE`. Keep the OSV record→row shaping (`bufferRecord`) untouched.

- [ ] **Step 2: Rewrite EPSS flush for SQLite**

Replace the Postgres `UPDATE vulnerabilities SET epss_score=... FROM (VALUES ...)` (epss.ts ~line 69-78) with prepared `UPDATE vulnerabilities SET epss_score=?, epss_percentile=?, epss_updated_at=? WHERE cve_id=?` in a `better-sqlite3` transaction.

- [ ] **Step 3: Build FTS at the end**

In `scripts/build-sqlite.ts`, after all ingest completes, run `INSERT INTO vulns_fts(...) SELECT ... FROM vulnerabilities;` and `INSERT INTO packages_fts(rowid,name) SELECT id,name FROM packages;`.

- [ ] **Step 4: Add the npm script and run a real ingest**

Add to `package.json`: `"build:sqlite": "node --max-old-space-size=4096 node_modules/tsx/dist/cli.mjs scripts/build-sqlite.ts"`. Run it.

Run: `pnpm build:sqlite`
Expected: produces a SQLite file; `sqlite3 <file> "SELECT count(*) FROM vulnerabilities"` returns a nonzero count and `SELECT count(*) FROM vulns_fts` matches.

- [ ] **Step 5: Verify search works locally**

Run: `sqlite3 <file> "SELECT cve_id FROM vulns_fts WHERE vulns_fts MATCH 'sql injection' LIMIT 2;"`
Expected: returns CVE ids. And `sqlite3 <file> "SELECT name FROM packages_fts WHERE packages_fts MATCH 'log4' LIMIT 3;"` returns package names.

- [ ] **Step 6: Commit**

```bash
git add src/lib/ingest/osv-batch.ts src/lib/ingest/epss.ts src/lib/ingest/kev.ts scripts/build-sqlite.ts package.json
git commit -m "feat(ingest): write to SQLite sink + build FTS5"
```

---

## Phase 3: Query-layer rewrite for D1/SQLite

Goal: rewrite the ~10 Postgres-specific query sites in `queries.ts`/`insights.ts` so they run on SQLite/D1. Each is verified against the Phase-0 D1 database (`vulnscope-phase0`) or the local SQLite file.

### Task 3.1: Replace LATERAL "highest CVSS per CVE" with window/correlated subquery

**Files:**
- Modify: `src/lib/queries.ts` (LATERAL at lines 204, 363, 679; also `getLatestCvesForPackage` ~line 730)
- Modify: `src/lib/insights.ts` (LATERAL sites)

**Interfaces:**
- Produces: same result shape (`base_score`, `severity` per CVE) with no `LATERAL`.

- [ ] **Step 1: Rewrite the searchVulns LATERAL (queries.ts:204)**

Replace `LEFT JOIN LATERAL (SELECT ... FROM cvss_scores cs WHERE cs.cve_id=v.cve_id ORDER BY base_score DESC LIMIT 1) cs ON true` with a correlated subquery pair in SELECT: `(SELECT base_score FROM cvss_scores cs WHERE cs.cve_id=v.cve_id ORDER BY base_score DESC LIMIT 1) AS base_score` and the matching `severity`. Convert `::float8` → `CAST(... AS REAL)`, `::int` → `CAST(... AS INTEGER)`.

- [ ] **Step 2: Rewrite the same pattern at queries.ts:363, 679, 730 and insights.ts sites**

Apply the identical correlated-subquery transform. Convert `= ANY($n::text[])` filters to dynamic `IN (?, ?, ...)` placeholder lists. Convert `now() - interval '1 day'` → `datetime('now','-1 day')` (getDashboardStats:464-469). Drop the `to_regclass('public.exploits')` guards (343-346) — schema is always current in the rebuilt D1.

- [ ] **Step 3: Verify against D1**

For each rewritten query, run it via `wrangler d1 execute vulnscope-phase0 --remote --command="<the rewritten SQL with literal params>"`.
Expected: returns rows with correct `base_score`/`severity`, no SQL error.

- [ ] **Step 4: Commit**

```bash
git add src/lib/queries.ts src/lib/insights.ts
git commit -m "refactor(queries): LATERAL→correlated subquery, PG casts→SQLite for D1"
```

### Task 3.2: Replace tsvector/pg_trgm search with FTS5, and jsonb with json_each

**Files:**
- Modify: `src/lib/queries.ts` (`searchVulns` FTS at 164-165; package ILIKE at 161, 538, 587, 662-663; `getPackageVersions` jsonb at ~767-801)

**Interfaces:**
- Produces: `searchVulns` and package search backed by FTS5; `getPackageVersions` using `json_each`.

- [ ] **Step 1: Rewrite full-text search (queries.ts:164)**

Replace `search_tsv @@ plainto_tsquery('english', $n)` with `v.cve_id IN (SELECT cve_id FROM vulns_fts WHERE vulns_fts MATCH ?)`. Keep the `cve_id ILIKE` prefix branch as `v.cve_id LIKE ? || '%'` for exact-id lookups.

- [ ] **Step 2: Rewrite fuzzy package search (queries.ts:161, 538, 587, 662)**

Replace `p.name ILIKE '%'||$n||'%'` with `p.id IN (SELECT rowid FROM packages_fts WHERE packages_fts MATCH ?)` (trigram). For the autocomplete prefix-sort (662-663), keep a `name LIKE ?||'%'` ordering branch.

- [ ] **Step 3: Rewrite getPackageVersions jsonb walk (queries.ts:767-801)**

Replace `jsonb_array_elements(ranges_json)` / `jsonb_array_elements_text(versions_json)` with SQLite `json_each(ranges_json)` / `json_each(versions_json)`. `ranges_json`/`versions_json` are TEXT in SQLite.

- [ ] **Step 4: Verify each against D1**

Run the rewritten `searchVulns` and package search via `wrangler d1 execute vulnscope-phase0 --remote --command=...` with a real term (e.g. `sql injection`, `log4`).
Expected: correct results, low rows_read.

- [ ] **Step 5: Commit**

```bash
git add src/lib/queries.ts
git commit -m "refactor(queries): FTS5 full-text + trigram package search, json_each for ranges"
```

### Task 3.3: Point the query layer at the D1 binding

**Files:**
- Create: `src/db/d1.ts`
- Modify: `src/db/client.ts` (replace `pg` Pool export with D1-backed `query` shim)
- Modify: `src/lib/queries.ts`, `src/lib/insights.ts` (call sites use `.prepare().bind().all()` semantics)

**Interfaces:**
- Consumes: OpenNext's D1 binding `env.DB` (configured in Phase 4).
- Produces: a `query(sql, params)` helper returning `{ rows }` so existing call sites change minimally.

- [ ] **Step 1: Write the D1 query shim**

Create `src/db/d1.ts` exporting `async function query(sql: string, params: unknown[] = []): Promise<{rows: any[]}>` that calls `getCloudflareContext().env.DB.prepare(sql).bind(...params).all()` and returns `{ rows: result.results }`. Convert `$1,$2` placeholders to `?` (D1 uses `?`).

- [ ] **Step 2: Re-export from client.ts**

Make `src/db/client.ts` re-export the D1 `query` as the `pool.query` shape the codebase uses, so the ~30 `pool.query(...)` call sites keep working with `?` placeholders.

- [ ] **Step 3: Convert `$n` placeholders to `?` in queries.ts/insights.ts**

Replace numbered `$1..$n` with `?` (D1 positional). Where dynamic placeholder counts are built, emit `?` instead of `$${p}`.

- [ ] **Step 4: Type-check**

Run: `pnpm exec tsc --noEmit`
Expected: no type errors in the query layer.

- [ ] **Step 5: Commit**

```bash
git add src/db/d1.ts src/db/client.ts src/lib/queries.ts src/lib/insights.ts
git commit -m "feat(db): D1 binding query shim, $n→? placeholders"
```

---

## Phase 4: OpenNext + Workers + D1 binding + edge caching

Goal: build and run the site on Workers, reading from D1, with CVE/list pages edge-cached.

### Task 4.1: Add OpenNext Cloudflare adapter and wrangler config

**Files:**
- Create: `wrangler.jsonc`, `open-next.config.ts`
- Modify: `package.json` (add `@opennextjs/cloudflare`; add `preview`/`deploy` scripts)

**Interfaces:**
- Produces: `pnpm preview` runs the Worker locally against D1; `pnpm deploy` ships it.

- [ ] **Step 1: Install the adapter**

```bash
pnpm add @opennextjs/cloudflare
```

- [ ] **Step 2: Write wrangler.jsonc with the D1 binding**

Create `wrangler.jsonc` with `"main"` pointing at the OpenNext worker output, `"compatibility_flags": ["nodejs_compat"]`, and a `d1_databases` binding `{ "binding": "DB", "database_name": "vulnscope", "database_id": "<from wrangler d1 create vulnscope>" }`. Create the prod DB first: `wrangler d1 create vulnscope`.

- [ ] **Step 3: Write open-next.config.ts**

Create `open-next.config.ts` per the OpenNext Cloudflare docs (default config with the Cloudflare adapter). Add scripts to `package.json`: `"preview": "opennextjs-cloudflare build && opennextjs-cloudflare preview"`, `"deploy": "opennextjs-cloudflare build && opennextjs-cloudflare deploy"`.

- [ ] **Step 4: Seed the prod D1 for local preview**

Run `scripts/push-to-d1.sh` (Task 5.1) against `vulnscope`, or reuse the Phase-0 dump against the new DB, so preview has data.

- [ ] **Step 5: Preview locally and load one CVE page**

Run: `pnpm preview`
Expected: Worker boots; visiting a CVE URL (e.g. `/en/cve/CVE-2021-46385`) renders with data from D1.

- [ ] **Step 6: Commit**

```bash
git add wrangler.jsonc open-next.config.ts package.json pnpm-lock.yaml
git commit -m "feat: OpenNext Cloudflare adapter + D1 binding + wrangler config"
```

### Task 4.2: Edge-cache CVE and list pages (mandatory for free-tier reads)

**Files:**
- Modify: `src/app/[locale]/cve/[id]/page.tsx` and list/insights pages (add cache headers)
- Modify: `wrangler.jsonc` or a Worker cache rule

**Interfaces:**
- Produces: CVE pages served from Cloudflare cache on repeat hits, so crawler traffic doesn't touch D1.

- [ ] **Step 1: Set Cache-Control on CVE responses**

In the CVE page (or a `Cache-Control` via `headers()` in `next.config.ts` / response), set `s-maxage=86400, stale-while-revalidate=604800` (data changes ~daily). Confirm the page is still `force-dynamic` but cacheable at the edge.

- [ ] **Step 2: Add a Cloudflare Cache Rule for /*/cve/* (dashboard or wrangler)**

Cache eligible CVE/list paths at the edge with the 1-day TTL so repeat requests never invoke the Worker.

- [ ] **Step 3: Verify cache HIT**

Run: `curl -sI https://<preview-or-prod-url>/en/cve/CVE-2021-46385 | grep -i cf-cache-status` twice.
Expected: second request shows `cf-cache-status: HIT`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "perf: edge-cache CVE/list pages to stay under D1 read cap"
```

---

## Phase 5: GitHub Actions ingest → D1 pipeline

Goal: a scheduled workflow builds the SQLite file and pushes the daily delta to D1; a separate one-time job does the cold seed.

### Task 5.1: Push script — SQLite → D1

**Files:**
- Create: `scripts/push-to-d1.sh`

**Interfaces:**
- Consumes: the SQLite file from `pnpm build:sqlite`.
- Produces: applies data to the `vulnscope` D1 via `wrangler d1 execute --file --remote`.

- [ ] **Step 1: Write the dump+strip+push script (reuse Phase-0 mechanics)**

Create `scripts/push-to-d1.sh`: `sqlite3 <file> ".dump vulnerabilities packages affected cvss_scores vuln_aliases refs" | grep -vE '^(BEGIN TRANSACTION|COMMIT|PRAGMA )' > d1-import.sql`, then `wrangler d1 execute vulnscope --file=d1-import.sql --remote --yes`, then a second file rebuilding FTS (`CREATE VIRTUAL TABLE ... ; INSERT INTO ..._fts SELECT ...`). This mirrors the verified Phase-0 commands.

- [ ] **Step 2: Test the push against the prod DB**

Run: `bash scripts/push-to-d1.sh`
Expected: reports `success: true` and a `size_after` near ~286 MB; `wrangler d1 execute vulnscope --remote --command="SELECT count(*) FROM vulnerabilities"` matches the SQLite count.

- [ ] **Step 3: Commit**

```bash
git add scripts/push-to-d1.sh
git commit -m "feat(ingest): push SQLite dataset to D1"
```

### Task 5.2: Scheduled GitHub Actions workflow

**Files:**
- Create: `.github/workflows/ingest.yml`

**Interfaces:**
- Consumes: `pnpm build:sqlite`, `scripts/push-to-d1.sh`.
- Produces: a daily cron that refreshes D1. Requires repo secret `CLOUDFLARE_API_TOKEN` (+ account id).

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/ingest.yml` with `on: schedule: - cron: '0 5 * * *'` and `workflow_dispatch`. Steps: checkout, setup-node + pnpm, `pnpm install`, `pnpm build:sqlite`, `bash scripts/push-to-d1.sh` with `env: CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}`. Split full OSV (weekly cron) from daily KEV/EPSS to fit free CI minutes and stay under the 100k/day D1 write cap.

- [ ] **Step 2: Add the Cloudflare API token as a repo secret**

In GitHub repo Settings → Secrets → Actions, add `CLOUDFLARE_API_TOKEN` (D1 edit scope). Document this in the workflow file header.

- [ ] **Step 3: Trigger a manual run and verify**

Run the workflow via `workflow_dispatch` (or `gh workflow run ingest.yml`).
Expected: the Action completes; D1 row counts update.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ingest.yml
git commit -m "ci: scheduled ingest → D1 via GitHub Actions"
```

---

## Phase 6: Cutover + verification

### Task 6.1: Cold seed and go live

**Files:** none (operational)

- [ ] **Step 1: Cold-seed D1**

Either enable Workers Paid ($5) for one month and run the full `push-to-d1.sh` in one shot, OR split the seed across ~7 days under the 100k/day cap. Verify final `size_after` < 500 MB and row counts match SQLite.

- [ ] **Step 2: Deploy the Worker**

Run: `pnpm deploy`
Expected: Worker deployed; note the `*.workers.dev` URL.

- [ ] **Step 3: Point the domain at the Worker (Cloudflare DNS)**

Add the custom domain to the Worker (Workers → Custom Domains) so `NEXT_PUBLIC_SITE_URL` resolves to it. Cloudflare handles HTTPS.

- [ ] **Step 4: Smoke-test production**

Verify: a CVE page renders, search returns results, `cf-cache-status: HIT` on repeat CVE hits, `/api/health` (if kept) is 200. Load a handful of CVE/search/insights URLs.

- [ ] **Step 5: Load-check rows-read**

After a day of traffic, check `wrangler d1 insights vulnscope` (or the D1 dashboard) that daily rows-read stays < 5M and writes < 100k.

- [ ] **Step 6: Decommission fly.io**

Once production is stable for a few days: `fly apps destroy vulnscope-tw`.

---

## Self-Review Notes

- **Cold-seed $0 caveat is explicit** (Global Constraints + Task 6.1): steady-state $0, one-time ~$5 seed month. This is the single honest crack in "$0 from day one."
- **Biggest remaining risk:** rows-read blowing the 5M/day cap if edge caching is misconfigured. Task 4.2 is mandatory, not optional, and Task 6.1 Step 5 verifies it with real numbers.
- **Reversibility:** the `deploy/oracle/` VM setup remains in the repo as a fallback if the D1 path hits an unforeseen wall mid-migration.

## Sources
- [Next.js · Cloudflare Workers docs](https://developers.cloudflare.com/workers/framework-guides/web-apps/nextjs/)
- [OpenNext Cloudflare](https://opennext.js.org/cloudflare)
- [OpenNext Cloudflare bindings](https://opennext.js.org/cloudflare/bindings)
