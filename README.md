# VulnScope

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

pnpm ingest:all             # ~5 min, downloads ~700 MB of zips once
pnpm dev                    # http://localhost:3000
```

For a faster first run, ingest just a couple of ecosystems:

```bash
pnpm ingest:kev
pnpm ingest:osv --ecosystem=npm,PyPI
pnpm ingest:epss
```

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

- [ ] NVD CVSS fallback — fill score gaps where OSV gives vectors only
- [ ] GHSA as a separate source (currently merged into OSV) to enable
      source-diff view
- [ ] ExploitDB / Metasploit / Nuclei template mapping per CVE
- [ ] RSS / Atom feeds (per ecosystem, per severity)
- [ ] CLI: `vulnscope check package.json` — ingest your manifest, list CVEs
- [ ] Read replica + materialized views for `/packages` aggregation

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
