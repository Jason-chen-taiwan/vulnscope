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

A full OSV refresh runs for tens of minutes and touches every record
in every zip. Three safety nets keep a misbehaving upstream from
locking the scheduler forever:

- **Per-source timeouts.** The EPSS ingest wraps both the HTTP fetch
  and the readline loop in an `AbortController` (5 min). Without this,
  a half-closed Cloudflare connection would hang `for await` indefinitely
  and the in-flight flag would never clear. This is exactly what
  happened on the demo deployment — the EPSS row sat in `running` for
  85 hours before the bug was found.
- **Orchestrator watchdog.** Even if every per-source timeout fails,
  the scheduler force-releases the in-flight flag and marks the
  `refresh` sync_jobs row failed after 3 hours. Defense in depth.
- **Stale-job reaper.** On boot, any `sync_jobs` row stuck in `running`
  for more than 2 hours is reclassified as `failed (reaped)`. Anything
  shorter is left alone so a real in-flight ingest survives a planned
  restart.

#### Memory profile

OSV's npm zip expands to ~219k JSON files. Naive concurrent reads can
OOM a small VM, and the symptom is usually a silent crash with a
permanently-`running` `sync_jobs` row.

The ingest is tuned to keep working-set size bounded regardless of how
big the DB grows:

- **`pLimit(3)` × chunk size 100** instead of 6 × 200. Bounds in-flight
  parsed records.
- **No in-memory `Map<cve_id, modified_at>`.** The per-record skip is a
  primary-key SELECT against `vulnerabilities` (~1 ms). A bit more
  round-trip volume, but heap stays flat.
- **`await new Promise(setImmediate)` at the chunk boundary** so V8 can
  reap the previous chunk's parsed records before loading the next.
- **`p-limit` cleared every 50k packages** so the `pkgCache` Map can't
  grow unbounded.

These add up to a ~512 MB working set even on the npm zip. A
1 GB Node heap is comfortable; the demo runs on a Fly `shared-cpu-1x`
with 2 GB RAM.

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

- **App machine: 2 GB RAM, not 1 GB.** OSV's npm zip plus zod parsing
  plus the chunk-level concurrent reads sit around ~512 MB working set;
  1 GB will OOM mid-ingest, leave a stuck `running` row, and skip the
  next 24 h's tick. Cost on Fly: ~$3/month, inside the $5 free credit.
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
- [ ] OSV per-record-changed feed — currently we still download the full
      zip per ecosystem (zips update hourly upstream) and rely on the
      per-record `modified` to skip writes. A `firstSeen.json`-style
      diff source would let us skip the download too.
- [ ] NVD CVSS fallback — fill score gaps where OSV gives vectors only.
- [ ] GHSA as a separate source (currently merged into OSV) to enable
      source-diff view.
- [ ] ExploitDB / Metasploit / Nuclei template mapping per CVE.
- [ ] RSS / Atom feeds (per ecosystem, per severity).
- [ ] CLI: `vulnscope check package.json` — ingest your manifest, list CVEs.
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
