# Contributing to VulnScope

Thanks for considering a contribution! This project is small and
opinionated — please open an issue before starting non-trivial work so we
can agree on the shape.

## Dev loop

```bash
pnpm install
cp .env.example .env.local
docker compose up -d        # or: pnpm db:start (Homebrew)
pnpm db:migrate
pnpm db:psql -f drizzle/0001_fts_and_trgm.sql   # one-time; tsvector + trigram
pnpm db:psql -f drizzle/0002_epss.sql            # one-time; EPSS columns
pnpm ingest:kev                                  # ~5 seconds, ~1600 rows
pnpm ingest:osv --ecosystem=npm,PyPI             # ~30 seconds, a few thousand CVEs
pnpm ingest:epss                                 # ~10 seconds
pnpm dev                                         # http://localhost:3000
pnpm test                                        # vitest, must pass
```

Faster path for big-picture browsing: `pnpm ingest:all` pulls every
ecosystem (~5 minutes, ~700 MB of zips downloaded once).

## Standards

- **TypeScript strict mode**; no `any` in new code without justification.
- **Vitest** for the version matcher, CVSS calculator, and any new
  pure-logic module. Tests live next to the source as `*.test.ts`.
- **No new dependencies without rationale** — the dependency surface is
  intentionally small. If you need to add one, mention it in your PR.
- **Don't touch unrelated files** in a PR. One concern per branch.

## Adding a new OSV ecosystem

The ingest script already accepts any ecosystem name listed at
[osv-vulnerabilities](https://osv-vulnerabilities.storage.googleapis.com/).
To make it visible in the UI, add the name to:

- `FEATURED_ECOSYSTEMS` in `src/app/page.tsx` (homepage cards)
- `KNOWN_ECOSYSTEMS` in `src/app/packages/page.tsx` (filter dropdown)

## Reporting bugs

Include:

- What you ran (`pnpm ...` command, URL hit, query string).
- What you expected vs. what happened.
- Postgres version (`pnpm db:psql -c "SELECT version();"`).
- A sample CVE-ID or package that demonstrates the issue, if applicable.

## What's intentionally out of scope

- User accounts, watchlists, email notifications, API keys — anything
  that requires a long-running server with state. This is a tool, not a
  SaaS. If you want that, fork it.
- NVD ingest. OSV covers our needs and NVD has severe enrichment delays.
  See the design notes in the README.
- SBOM scanning (Trivy / Grype / Syft already do this well).
