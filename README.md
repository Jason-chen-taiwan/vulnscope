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
in every zip. Four layered safety nets keep a misbehaving upstream
or a network blip from locking the scheduler forever:

- **Heartbeat-based source timeout.** Each `JobHandle.progress()`
  flush updates `sync_jobs.last_heartbeat_at`. The orchestrator polls
  this column every 30 s and aborts a source only if no heartbeat for
  5 min — so a legitimately-slow npm ingest runs for as long as it
  needs to (we've seen 90+ min on Fly shared CPU), but a truly
  hung HTTP fetch dies fast. Replaces the old wall-clock timeout,
  which kept killing healthy sources just because the ecosystem was
  large. A 4 h absolute cap is retained as a paranoid backstop.
- **Per-pool `'error'` listeners + TCP keepalive.** Managed Postgres
  (Fly / RDS / Supabase / Neon) closes idle connections after a few
  minutes. Without a listener, pg.Pool's `'error'` event escalates to
  `uncaughtException` and crashes the entire Node process — one idle
  drop would take down 15 in-flight ingests at once (we hit this in
  production). The pool listener acknowledges the event so pg can
  drop the dead client and the next query gets a fresh one;
  `keepAlive` reduces how often the drop happens in the first place.
- **Orchestrator watchdog.** Even if every per-source heartbeat
  check fails, the scheduler force-releases its in-flight flag and
  marks the `refresh` sync_jobs row failed after 3 hours.
- **Stale-job reaper.** Every 10 min (and on boot), any `sync_jobs`
  row whose `last_heartbeat_at` hasn't moved in 5 min gets
  reclassified as `failed (reaped)`. Excludes `source='refresh'`,
  which is the orchestrator wrapper and doesn't heartbeat itself.
  Heartbeat-based (not started_at-based) so a process crash during
  ingest gets cleaned up in minutes instead of the next reboot.

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
  next chunk. Never aggregate across chunks; earlier "buffer 1000
  records then flush" attempts starved Node's event loop during npm
  ingest and broke Fly health checks.
- **Multi-row INSERTs at `FLUSH_INSERT_BATCH = 500`.** Lowered from
  1000 after we observed `statement_timeout` cancellations on the
  vulnerabilities table once it carried GIN+trgm fulltext indexes
  (index maintenance scales superlinearly with batch size). 500 keeps
  each statement comfortably under the 5 min ingest-pool timeout.
- **`pkgCache` cleared at 50k entries** so the package-id Map can't
  grow unbounded across a long npm run.

Result: ~220 – 480 MB RSS steady-state on the npm ingest. A 1 GB Node
heap is technically enough but tight; the demo runs on a Fly
`shared-cpu-1x` with 2 GB RAM for headroom against burst allocation
during the parallel-flush window.

## Deploy your own

The repo ships with a production-ready `Dockerfile` and `fly.toml` for
Fly.io. Self-host in three commands:

```bash
fly launch --copy-config --no-deploy   # accept the existing fly.toml
fly postgres create                    # or use Neon / Supabase / RDS
fly secrets set DATABASE_URL=postgres://...
fly deploy
```

The in-process scheduler picks up where it left off, so your hosted
instance refreshes data daily without external cron.

### Sizing on Fly.io (or any small VM)

A few things that look like overspending and aren't:

- **App machine: 2 GB RAM, not 1 GB.** Steady-state RSS is
  ~220 – 480 MB (see *Memory profile* above), but transient bursts
  during the parallel cvss/affected/refs/aliases flush — combined
  with V8's lazy GC under shared CPU — can push past 1 GB and trip
  OOM. 2 GB gives enough headroom that GC has time to reclaim between
  chunks without the event loop stalling Fly's health checks. Cost on
  Fly: ~$5/month, just outside the $5 free credit.
- **`auto_stop_machines = 'off'` and `min_machines_running = 1`.** A
  full refresh takes 30 – 60 minutes and doesn't generate HTTP traffic,
  so Fly's idle-stop will kill the ingest. The added cost is small;
  the alternative is a never-completing refresh.
- **Postgres: 512 MB RAM, not 256 MB.** At 256 MB the WAL checkpoint
  takes ~2 min on a Debian-sized ingest and stalls connections; 512 MB
  is the floor at which OSV ingest doesn't hit the pg connection pool.
- **`config.dangerouslyAllowAllBuilds=true` in the Dockerfile.** pnpm 11
  refuses to run unapproved postinstall scripts in non-interactive
  environments. Without this flag the Docker build fails on `esbuild`,
  `sharp`, etc. Inside the build image we genuinely want them to run.

The hosted demo at `vulnscope-tw.fly.dev` runs on this config. Full
refresh takes ~65 minutes (npm and Debian are the long tail); a typical
incremental day takes 30 – 60 minutes with most ecosystems writing
zero or only a few hundred rows.

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
codebase. The $9/mo pays the Fly bill and lets me work on this on
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
