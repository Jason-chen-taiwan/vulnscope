<p align="left">
  <img src="docs/wordmark.svg" alt="VulnScope" width="480">
</p>

> **Package-centric CVE lookup, self-hosted in two commands.** Type a package
> name and a version, see which CVEs affect it and which upgrade clears them.

![License](https://img.shields.io/badge/license-MIT-green)
![Node](https://img.shields.io/badge/node-22%2B-339933)
![Postgres](https://img.shields.io/badge/postgres-16%2B-336791)

Local-first vulnerability database that aggregates **OSV.dev + CISA KEV +
FIRST.org EPSS** across 14 ecosystems. No accounts, no servers, no SaaS —
clone, ingest, browse.

## Why

Most CVE search tools (NVD, MITRE, Snyk UI) are either CVE-centric (you
already know the CVE ID) or stuck inside vendor portals. When you actually
need to ask **"is `lodash@4.17.20` exploitable, and if so what do I bump
to?"**, none of them are good at that. This project starts from that
question and works outward.

- **Per-package timeline** — one URL per package, all known CVEs, severity,
  EPSS, KEV flag, version ranges
- **Version checker** — paste a version, get back the affected CVEs and
  the smallest patched version above it
- **14 ecosystems** — npm, PyPI, Maven, Go, RubyGems, Packagist, crates.io,
  NuGet, Hex, Hackage, Debian, Alpine, Bitnami, Linux
- **EPSS + KEV badges** — see exploitation probability and "actually being
  exploited" status, not just CVSS theatre

## Quick start

```bash
git clone <repo-url> vulnscope && cd vulnscope
pnpm install
cp .env.example .env.local

# Pick one:
docker compose up -d        # Docker variant
# pnpm db:start             # Homebrew variant (macOS, postgresql@16)

pnpm db:migrate
pnpm db:psql -f drizzle/0001_fts_and_trgm.sql
pnpm db:psql -f drizzle/0002_epss.sql
pnpm db:psql -f drizzle/0003_sync_jobs.sql

pnpm ingest:all             # ~5 min locally, downloads ~700 MB of zips once
pnpm dev                    # http://localhost:3000
```

For a faster first run, ingest just a couple of ecosystems:

```bash
pnpm ingest:kev
pnpm ingest:osv --ecosystem=npm,PyPI
pnpm ingest:epss
```

### Data stays fresh automatically

Once `pnpm dev` (or `pnpm start` in production) is running, an in-process
scheduler runs **a full refresh every 24 hours** — pulling fresh KEV,
OSV across all 14 ecosystems, and EPSS. The first run happens 10 seconds
after server boot. See progress at
[`/admin/jobs`](http://localhost:3000/admin/jobs) and the data-freshness
indicator on the homepage.

Manual trigger: `POST /api/v1/admin/refresh` (loopback-only by default;
set `ADMIN_TOKEN` env to allow remote calls).

Disable via `SCHEDULER_DISABLED=1`.

#### Incremental ingest

Each source has a cheap freshness anchor stored in `meta_kv`. When the
upstream value matches what we already have, the source is skipped
entirely:

| Source | Anchor | Behaviour when unchanged |
|---|---|---|
| KEV | `catalogVersion` | Full skip — no per-entry upsert |
| OSV (per ecosystem) | `Last-Modified` HTTP header (HEAD request) | Full skip — no download |
| OSV (per record) | record's `modified` vs. DB's `modified_at` | Skip the record's writes |
| EPSS | `score_date` from CSV header | Close the stream, skip remaining rows |

A typical day's refresh writes orders of magnitude less than a cold
ingest — KEV/EPSS often complete in milliseconds, and per-ecosystem OSV
runs upsert only the records whose `modified` actually advanced.

#### Reliability

A full OSV refresh runs for an hour or two and touches every record
in every zip. Seven layered safety nets keep a misbehaving upstream,
a network blip, a runaway ingest, or a hostile client from breaking
the user-facing web tier:

- **Web / worker process split.** Two Node processes share one Docker
  image: the `web` process runs Next.js only, the `worker` process
  runs the scheduler + ingest only. `PROCESS_ROLE` env decides which
  side of `src/instrumentation-node.ts` boots. Ingest hogging the
  event loop for a 1 – 3 s parse-and-flush chunk can't stall HTTP
  request handling because they're literally different Node
  processes — deploy them as separate containers / process groups /
  systemd units, doesn't matter. Manual `POST /api/v1/admin/refresh`
  returns 503 in this mode (the web process has no scheduler to call);
  daily auto-refresh on the worker is the only trigger.
- **Heartbeat-based source timeout.** Each `JobHandle.progress()`
  flush updates `sync_jobs.last_heartbeat_at`. The orchestrator polls
  this column every 30 s and aborts a source only if no heartbeat for
  5 min — so a legitimately-slow npm ingest runs for as long as it
  needs to (we've seen 90+ min on small shared-CPU instances), but a
  truly hung HTTP fetch dies fast. Replaces the old wall-clock
  timeout, which kept killing healthy sources just because the
  ecosystem was large. A 4 h absolute cap is retained as a paranoid
  backstop.
- **Per-pool `'error'` listeners + TCP keepalive.** Managed Postgres
  providers close idle connections after a few minutes. Without a
  listener, pg.Pool's `'error'` event escalates to
  `uncaughtException` and crashes the entire Node process — one idle
  drop would take down 15 in-flight ingests at once (we hit this in
  production). The pool listener acknowledges the event so pg can
  drop the dead client and the next query gets a fresh one;
  `keepAlive` reduces how often the drop happens in the first place.
  Both the web pool (`src/db/client.ts`) and the ingest pool
  (`src/db/ingest-pool.ts`) carry the listener — early versions only
  had it on ingest and an idle drop took down SSR.
- **Orchestrator watchdog + boot-time orphan cleanup.** Even if every
  per-source heartbeat check fails, the scheduler force-releases its
  in-flight flag and marks the `refresh` sync_jobs row failed after
  3 h. **At worker boot**, every `running` refresh row is cleared
  unconditionally — the in-memory `__vulnscope_refresh_in_flight` flag
  just reset, so any row still marked running is by definition an
  orphan from the previous process. Without this, a worker crash leaves
  `shouldSkipScheduled()` permanently refusing future ticks
  (observed: 3 stuck refresh rows from earlier process deaths blocking
  the daily scheduler for hours).
- **Stale-job reaper.** Every 10 min (and on boot), two passes run:
  child sources (kev, osv:\*, epss, nvd, exploits) get reclassified as
  `failed (reaped)` if `last_heartbeat_at` hasn't moved in 5 min;
  refresh rows get reaped after 3 h (matching the watchdog). Different
  thresholds because they have different liveness signals — the
  refresh wrapper doesn't heartbeat itself.
- **Per-route rate limiting on every public HTTP path.** Token-bucket
  limiter in `src/lib/rate-limit.ts` protects API routes, SSR pages,
  RSS feeds, and the sitemap. A CDN in front of the domain blocks
  volumetric attacks at the edge, but attackers can bypass to the
  origin directly — without app-layer limits, one
  `curl /zh/search?q=foo` loop saturated the small Postgres instance.
  Identity precedence is `signed-in user > CF-Connecting-IP >
  Fly-Client-IP > X-Forwarded-For`. Signed-in users get 3× capacity.
  Coverage is layered:
    - **API routes**: per-route `withRateLimit(bucket, handler)` HOF.
      Tight buckets on the expensive shapes (`autocomplete` 60/min,
      `check_batch` 10/min, `auth` 10/min — the credential-stuffing
      target).
    - **SSR pages** (`/zh/**`, `/en/**`): `src/middleware.ts` checks
      a path-dispatched bucket BEFORE next-intl runs. Cheap pages
      (`page_view` 300/min) vs. expensive routes (`search_page`
      60/min, `insights_page` 60/min).
    - **Feeds** (`/feed/*`): same HOF as API, bucket `feed` 60/min.
    - **Sitemap** (`/sitemap.xml`): inline `checkLimit` at the top of
      `sitemap.ts`; on 429 it returns an empty sitemap rather than a
      structurally-invalid error response (`sitemap` 30/min).
  Exempt: `/api/health`, Polar webhook (HMAC + 429 would look like a
  webhook bug), all OPTIONS preflights. The in-memory Map is capped at
  50 000 entries with probabilistic eviction so a botnet cycling
  source IPs can't OOM the process. Edge-bundle compatibility is
  preserved: middleware never pulls the Better Auth chain because the
  auth-aware identity helper lives in a separately-imported module
  resolved through an opaque specifier that webpack's Edge tracer
  ignores. Single web machine today; swap the in-memory store for
  Redis or Postgres when we scale to ≥ 2.
- **Health check decoupled from DB.** `/api/health` is a pure liveness
  probe — it does NOT touch Postgres. Reverse proxies use this with a
  5 s timeout and route traffic away from "unhealthy" machines; doing
  `SELECT 1` here meant a busy Postgres (mid-checkpoint, ingest
  contention) would mark the Node process as dead and cascade into a
  "no good candidate" outage even though the process was fine. DB
  health is observable via `sync_jobs` and logs.

#### Memory profile

OSV's npm zip is 206 MB compressed, ~1.5 GB inflated, ~220k JSON
files. Naive zip handling will OOM a small VM, and the symptom is
usually a silent crash with a permanently-`running` `sync_jobs` row.

The ingest is tuned to keep working-set size bounded regardless of how
big the upstream zip grows:

- **yauzl `lazyEntries: true` (pull-based) instead of unzipper.Parse
  (push-based).** unzipper is a Transform stream whose internal
  buffer grows unboundedly when downstream is slower than inflate —
  we measured 1.48 GB RSS at 0.45% of npm records before swapping.
  yauzl with lazyEntries inflates exactly one entry per `readEntry()`
  call, so RSS stays flat regardless of zip size. MAL-* entries
  (110k+ on npm) are skipped at the central-directory layer without
  ever being inflated.
- **Per-chunk allocation lifecycle.** Each parse chunk (50 records)
  builds its own fresh buffers, flushes once, then the chunk is
  dropped and `setImmediate`-yielded so V8 can reap it before the
  next chunk. **Per-record `setImmediate` yield inside the parse
  worker** keeps the event loop responsive on the worker process —
  without it, 50 zod-validated records back-to-back blocked the loop
  for 1 – 3 s and broke health checks. Never aggregate across chunks;
  earlier "buffer 1000 records then flush" attempts starved the
  event loop during npm ingest.
- **Multi-row INSERTs at `FLUSH_INSERT_BATCH = 500`.** Lowered from
  1000 after we observed `statement_timeout` cancellations on the
  vulnerabilities table once it carried GIN+trgm fulltext indexes
  (index maintenance scales superlinearly with batch size). 500 keeps
  each statement comfortably under the 5 min ingest-pool timeout.
- **`pkgCache` cleared at 50k entries** so the package-id Map can't
  grow unbounded across a long npm run.

- **Ingest pool capped at 2 connections** (vs. the web pool's 10),
  leaving headroom for SSR while a hot ingest is grinding. With 3
  ingest slots and 6 parallel SSR aggregates on the homepage we saw
  the pool fully starved during ingest; trimming to 2 keeps one slot
  permanently available for web queries at the cost of ~10% slower
  ingest.

Result: ~220 – 480 MB RSS steady-state on the npm ingest. 1 GB is
comfortable for the worker process.

#### Query performance

The 243 MB `vulnerabilities` table doesn't comfortably fit in
`shared_buffers` on a small Postgres instance. Without careful
indexing, SSR pages do full-table scans, thrash buffer cache, and
stack up at `IO:DataFileRead` — we observed `/zh` and `/en` timing
out at 30 s under modest traffic before the work below landed.

Four families of fix layered on top of each other; combined, they
take warm-cache SSR pages from 26 s down to ~0.3 s.

- **Composite indexes that cover the hot aggregates.** Three migrations
  (`0006_perf_indexes.sql`, `0007_perf_indexes_p2.sql`) add:
    - `idx_affected_eco_pkg (ecosystem, package_id) INCLUDE (cve_id)`
      — lets `getTopPackages`-shaped queries do an index-only scan,
      no heap fetches for the `COUNT(DISTINCT cve_id)` aggregate.
      Production EXPLAIN dropped from 21 000 ms to 55 ms (380×).
    - `idx_cvss_cve_score (cve_id, base_score DESC NULLS LAST)`
      satisfies the `LEFT JOIN LATERAL (... ORDER BY base_score DESC
      LIMIT 1)` pattern with a pure index scan, no sort.
    - `idx_vuln_kev_added` partial on `(kev_added_at DESC) WHERE
      kev = true` — the 1 600 KEV rows of 75 000 total, indexed just
      enough for `getRecentKev` and the KEV catalog page.
    - `idx_vuln_epss_score_partial` on `(epss_score DESC) WHERE
      epss_score IS NOT NULL` — drives EPSS rising + sitemap's
      `kev OR epss>=0.05` bitmap-or path.
- **Query shape: pre-aggregate from the smaller table first.** The
  classic mistake was `FROM packages p LEFT JOIN affected a … GROUP BY
  p.ecosystem, p.name` — every page request fully re-aggregated 120 k
  affected rows. The rewrite materialises the aggregate first as a CTE
  driven from `affected`, then joins the 15 k packages table by PK
  at the end:
    ```sql
    WITH agg AS (
      SELECT a.package_id, COUNT(DISTINCT a.cve_id) AS cve_count, ...
        FROM affected a JOIN vulnerabilities v ON v.cve_id = a.cve_id
       [WHERE a.ecosystem = $1]
       GROUP BY a.package_id
    )
    SELECT p.ecosystem, p.name, agg.cve_count, ...
      FROM agg JOIN packages p ON p.id = agg.package_id
     ORDER BY agg.kev_count DESC LIMIT $N
    ```
  Applied to `getTopPackages`, `browsePackages`, `getTopPackagesAllEcos`,
  `getEcosystemDeepDive`, and the sitemap package query.
- **A 60 s in-memory cache for `getDashboardStats`.** The six
  `COUNT(*)` subqueries that feed the homepage widget return the same
  numbers for every user and don't need to be precise to the second.
  Caching in the web process drops 6 expensive queries per pageview
  to 6 queries per minute, regardless of traffic. Implementation is a
  module-level `{at, value}` pair — no Redis, no LRU, deliberately
  trivial.
- **`unstable_cache(60 s)` on every read-only SSR fetch.** Wrapped:
  `getTopPackages`, `getRecentKev`, `getRecentVulns`,
  `browsePackages`, `getTopPackagesAllEcos`, `getKevCatalog`,
  `getEpssRising`, `getEcosystemDeepDive`. All produce identical
  output for every user; caching for 60 s means after one warm-up
  the entire homepage + insights + packages pages render with zero
  PG hits. During ingest the web tier essentially serves from
  in-memory cache, completely decoupled from PG load. Stale data
  window is ≤ 60 s, fine for CVE data that refreshes daily.
- **Homepage 6 × `getTopPackages` run sequentially**, not via
  `Promise.all`. The 6 ecosystem aggregates all hit the same
  buffer-cache pages; running them in parallel during ingest had
  them stacking up to 30 s in `pg_stat_activity`. Sequential costs
  ~1 s on the cold-cache homepage render but avoids the pile-up
  entirely, and after the first render the `unstable_cache` above
  serves all six in 0 ms anyway.

Two patterns we explicitly avoid:

- **`EXISTS (… subquery with ILIKE infix …)` inside an `OR`.** The
  optimizer routinely refuses to use the trigram GIN index inside an
  `EXISTS`. The fix is a CTE that materialises the matching CVE set
  once via the trigram index, then the outer query does
  `cve_id IN (SELECT cve_id FROM matching_cves)`. Used in
  `searchVulns` to keep the "type `log4j`, find CVE-2021-44228" UX
  working without the per-row scan it used to do.
- **N+1 aggregates in type-ahead.** `autocompletePackages` used to
  `LEFT JOIN affected` with `COUNT(DISTINCT cve_id)` per match. Every
  keystroke fired a full aggregate. Now it's a pure `packages` query
  with the trigram index; the dropdown doesn't need a CVE count next
  to each candidate.

Cold cache is still the long tail: the first request to a path after
DB restart or a long idle period pays disk-read latency for whatever
isn't already in `shared_buffers`. Once a page is warm, SSR is
~0.3 s. The next step for further reducing cold-cache pain is a
read-replica deployment (separates write-heavy ingest from read-heavy
SSR at the DB level); not yet implemented for cost reasons.

## Deploy your own

The repo ships with a production-ready `Dockerfile`. Any platform
that runs Docker + Postgres works (Fly.io, Render, Railway, AWS
ECS, your own Hetzner box…). You need:

1. **A Postgres 16 instance** with `pg_trgm` available
   (Neon / Supabase / RDS / self-managed — anything).
2. **One Node container per role**, both running the same image with
   different `PROCESS_ROLE` env:
   - `PROCESS_ROLE=web`  → Next.js HTTP server only
   - `PROCESS_ROLE=worker` → scheduler + ingest only (no HTTP routed
     to it; ingest is on a 24 h timer)
3. **Env vars** (see `.env.example` for the full list):
   - `DATABASE_URL=postgres://…`
   - `NEXT_PUBLIC_SITE_URL=https://your.domain`
   - OAuth + Polar keys if you want sign-in and Pro tier

The in-process scheduler picks up where it left off, so the worker
container refreshes data daily without external cron.

### Sizing the deployment

Tested with this topology on a small managed-PaaS provider:

| Component | Resources |
|---|---|
| web (Next.js HTTP only) | 1 vCPU, 1 GB RAM |
| worker (scheduler + ingest) | 1 vCPU, 1 GB RAM |
| Postgres | 1 vCPU, 1 GB RAM |

A few sizing notes:

- **Two 1 GB containers, not one 2 GB**: splitting `web` and `worker`
  means an OSV ingest pegging the event loop on the worker doesn't
  block SSR on the web side. Memory-wise each side fits in 1 GB
  independently — web's working set is <300 MB, worker's is
  220 – 480 MB (see *Memory profile*). You can run both on a single
  larger box too; the process-role split still gives event-loop
  isolation.
- **Postgres ≥ 1 GB RAM**: at 512 MB, the 243 MB `vulnerabilities`
  table doesn't fit in `shared_buffers` and cold-cache SSR pages
  pay disk-read latency. 1 GB gives Postgres a ~256 MB shared
  buffer pool which holds the hot tables + indexes comfortably.
- **Worker container doesn't need HTTP routed to it.** It hosts a
  Next.js server because the Docker image is shared, but no public
  traffic should hit it. Health checks and load balancers target
  the web container only.
- **`config.dangerouslyAllowAllBuilds=true` in the Dockerfile.**
  pnpm 11 refuses to run unapproved postinstall scripts in
  non-interactive environments. Without this flag the Docker build
  fails on `esbuild`, `sharp`, etc. Inside the build image we
  genuinely want them to run.

Full refresh takes ~65 min (npm and Debian are the long tail); a
typical incremental day takes 30 – 60 min with most ecosystems writing
zero or only a few hundred rows. Warm-cache SSR pages render in
~0.3 s; cold-cache requests (first hit after DB idle / restart) take
a few seconds longer.

### Hosted demo vs. self-host

The author runs [vulnscope.dev](https://vulnscope.dev) (a hosted demo)
with Carbon Ads in the sidebar and Plausible analytics to cover server
costs. **None of that runs in this repo by default** — they're all
opt-in env vars (`NEXT_PUBLIC_ADS_ENABLED`, `NEXT_PUBLIC_PLAUSIBLE_DOMAIN`,
`NEXT_PUBLIC_NEWSLETTER_URL`). Self-hosters get a clean, tracker-free
build. The codebase is 100% open source under MIT — see `.env.example`
for every available knob.

### Open source vs. hosted Pro

VulnScope is MIT open source — clone, self-host, hack it forever, no
strings attached. Everything you need to run the same web app, ingest
pipeline, and CLI lives in this repo.

I also run a hosted Pro tier on [vulnscope.dev](https://vulnscope.dev)
that adds:

- **Watchlist** — pin packages, see new CVEs in one place
- **Email alerts** — daily digest when a CVE hits a package you watch
- **Higher API limits** for the CLI

Pro features live in a separate private repo and aren't part of this
codebase. The $9/mo pays the hosting bill and lets me work on this on
weekends instead of letting it bitrot. If you self-host, you get the
full open-source feature set forever — drop a cron entry and you can
build the same alerting on top of `pnpm ingest:all`. If you want me to
do the ops + send you CVE alerts, pay me $9/mo. Both are valid.

See [`docs/pro-launch-plan.md`](./docs/pro-launch-plan.md) for the
full Open Core split — which features stay open source, which are
hosted-only, and why.

## CLI: `npx vulnscope check`

A companion command-line tool that scans your lockfile against this
database. Lives in [`cli/`](./cli) as its own npm package.

```bash
npx vulnscope check                       # auto-detect lockfile
npx vulnscope check ./pnpm-lock.yaml      # explicit path
npx vulnscope check --severity CRITICAL,HIGH --json
```

Supports `package-lock.json` (npm v2/v3) and `pnpm-lock.yaml` (v9).
Calls the hosted batch endpoint
(`POST /api/v1/packages/check-batch`) so 100s of packages check in one
round-trip. Exits 1 on findings (overridable with `--exit-zero`) so it
drops straight into CI. See [`cli/README.md`](./cli/README.md) for the
full flag list.

Both packages live in one pnpm workspace:

```
.
├── src/                  ← Next.js web app (@vulnscope/web)
├── cli/                  ← npm package `vulnscope`
└── pnpm-workspace.yaml
```

The web app is the backend; the CLI is a pure HTTP client (no DB
coupling). They version independently.

## Insights pages

`/insights/...` are auto-generated content pages from the database:

- `/insights/most-vulnerable-packages` — top 100 packages across all ecosystems
- `/insights/cisa-kev-catalog` — every CVE on CISA's Known Exploited list
- `/insights/epss-rising` — vulnerabilities with the highest exploitation probability
- `/insights/ecosystem/{eco}` — per-ecosystem breakdown for npm, PyPI, Maven, Go, Debian, Alpine

These power evergreen SEO landing pages and are revalidated hourly.

## i18n

UI is available in **English** (`/en/...`) and **繁體中文** (`/zh/...`).
The root path `/` redirects to the user's preferred locale based on
`Accept-Language`. Toggle via the **EN / 中** switch in the header.

To add another language: drop a `messages/<lang>.json` into the repo
mirroring `messages/en.json`, add the code to `src/i18n/routing.ts`,
and you're done — no other code changes needed.

## What it does

| URL | What you see |
|---|---|
| `/` | Dashboard: stats, recent KEV additions, most-vulnerable packages per ecosystem |
| `/packages` | Browse all 15k+ tracked packages with filters |
| `/package/{ecosystem}/{name}` | One package: all CVEs, severity, version checker |
| `/cve/{id}` | One CVE: description, affected packages, CVSS/EPSS, references |
| `/search?q=…` | Full-text + trigram search across CVEs and packages |
| `/api/v1/packages/{eco}/{name}/check?version=X` | JSON API for the version checker |
| `/api/v1/vulns/{id}` | JSON envelope for a CVE bundle |

Try it: `/package/Maven/org.apache.logging.log4j:log4j-core`,
`/package/Debian/openssl`, `/package/PyPI/django?` then check `3.2.0`.

## What it doesn't do

Deliberately. If you need any of these, look elsewhere or fork:

- **No user accounts, watchlists, email alerts, or API keys.** This is a
  self-hosted tool, not a SaaS. Drop a cron entry for `pnpm ingest:all`
  if you want fresh data.
- **No SBOM scanning.** [Trivy](https://github.com/aquasecurity/trivy),
  [Grype](https://github.com/anchore/grype), and
  [osv-scanner](https://github.com/google/osv-scanner) already do that
  well — they're better suited for "scan my repo / image", while VulnScope
  is better suited for "I'm reading a security advisory, tell me everything".
- **No NVD ingest.** OSV already pulls CVE data from NVD upstream, plus
  GHSA-quality CVSS, plus ecosystem-tagged ranges. NVD's enrichment has
  been months behind since 2024, and CPE → package mapping is unreliable.
  KEV (overlay) and EPSS (overlay) we ingest directly.

## How it works

```
                 OSV.dev bulk zips       CISA KEV          FIRST.org EPSS
                 (14 ecosystems)         (daily JSON)       (daily CSV.gz)
                       │                      │                   │
                       ▼                      ▼                   ▼
                 ┌─────────────────────────────────────────────────┐
                 │  scripts/ingest/{osv,kev,epss}.ts (Node + zod)  │
                 │  - normalize to OSV-style canonical schema      │
                 │  - upsert (idempotent, safe to re-run)          │
                 └────────────────────┬────────────────────────────┘
                                      │
                                      ▼
                            ┌────────────────────┐
                            │   PostgreSQL 16    │
                            │   FTS + pg_trgm    │
                            └─────────┬──────────┘
                                      │
                                      ▼
                            ┌────────────────────┐
                            │   Next.js 15 App   │
                            │   Server-rendered  │
                            └────────────────────┘
```

Version range comparison lives in `src/lib/version-match.ts` and walks the
OSV `events[]` form (`introduced` / `fixed` / `last_affected` / `limit`)
using `semver` for npm-shaped ecosystems and `@renovatebot/pep440` for
PyPI. CVSS v3.x base scores are computed from the vector string in
`src/lib/cvss.ts`. Both modules are pure functions with a `vitest` suite
right next to them.

### Schema notes

- `vulnerabilities.search_tsv` is a `GENERATED ALWAYS AS ... STORED`
  tsvector and not emitted by `drizzle-kit`, which is why migration 0001
  is hand-written SQL.
- `affected.ranges_json` stores raw OSV `ranges[]` rather than normalizing
  into a per-event table. At 100k rows this is faster and simpler than a
  join, and the matcher reads it directly.
- `cvss_scores` keeps one row per `(cve_id, version, source)` so we can
  add NVD or vendor scores later without schema changes.
- `epss_score` and `epss_percentile` live on `vulnerabilities` (1:1
  relationship) with a `DESC NULLS LAST` index.
- **Performance indexes (migrations 0006 and 0007) are hand-written
  SQL** because drizzle 0.36 can't express the features that make them
  cheap: partial `WHERE` clauses on `idx_vuln_kev_added` /
  `idx_vuln_epss_score_partial`, and the `INCLUDE (cve_id)` covering
  column on `idx_affected_eco_pkg`. `schema.ts` carries a column-only
  approximation of each so `db:generate` doesn't try to drop the live
  index on the next migration run.
- **`CREATE INDEX CONCURRENTLY` requires running outside a transaction.**
  Apply 0006 and 0007 to a populated DB with `psql -f` (each statement
  auto-commits), not via a transactional migration wrapper.

## Stack

| Layer | Choice |
|---|---|
| App | Next.js 15 (App Router) + TypeScript + Tailwind |
| DB | PostgreSQL 16 + Drizzle ORM + `pg_trgm` + tsvector |
| Version match | `semver` (npm-shape) + `@renovatebot/pep440` (PyPI) |
| Ingest | Node + `undici` + `zod`, system `unzip` for OSV bulk zips |
| Tests | `vitest` |

No Redis, no ElasticSearch, no Kubernetes, no message broker. Add them
when you actually need them.

## Roadmap

These are the things plausibly worth doing without turning this into a
SaaS. PRs welcome.

- [x] Incremental ingest (KEV catalogVersion, OSV Last-Modified +
      per-record `modified`, EPSS score_date) — done; see "Incremental
      ingest" above.
- [x] CLI: `vulnscope check package.json` — done; see [`cli/`](./cli)
      (npm + pnpm lockfiles; Yarn / Python / Go on the way).
- [ ] OSV per-record-changed feed — currently we still download the full
      zip per ecosystem (zips update hourly upstream) and rely on the
      per-record `modified` to skip writes. A `firstSeen.json`-style
      diff source would let us skip the download too.
- [ ] NVD CVSS fallback — fill score gaps where OSV gives vectors only.
- [ ] GHSA as a separate source (currently merged into OSV) to enable
      source-diff view.
- [ ] ExploitDB / Metasploit / Nuclei template mapping per CVE.
- [ ] RSS / Atom feeds (per ecosystem, per severity).
- [ ] CLI Phase 2: Yarn / Bun lockfiles, Python (`requirements.txt`,
      `poetry.lock`), Go (`go.sum`).
- [ ] Read replica + materialized views for `/packages` aggregation.

## Acknowledgments

This project is mostly plumbing on top of:

- [OSV.dev](https://osv.dev) by Google — unified vulnerability schema and
  bulk downloads, the foundation of the whole ingest pipeline
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — the "really being exploited" overlay
- [FIRST.org EPSS](https://www.first.org/epss/) — exploitation probability model
- [`semver`](https://github.com/npm/node-semver) and
  [`@renovatebot/pep440`](https://github.com/renovatebot/pep440) — the
  only way version comparison is sane

## License

MIT. See [LICENSE](LICENSE).
