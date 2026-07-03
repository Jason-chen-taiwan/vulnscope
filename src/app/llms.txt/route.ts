import type { NextRequest } from "next/server";

const SITE = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";

export const dynamic = "force-dynamic";
export const revalidate = 3600;

// llms.txt: a hint file for AI crawlers (Anthropic, Perplexity, Mistral, etc.)
// pointing them at the highest-signal URLs and giving them a citation hint.
// Same idea as robots.txt but for LLM training/retrieval crawlers.
// Spec: https://llmstxt.org/
export const GET = async (_req: NextRequest) => {
  const body = `# VulnScope

> Package-centric CVE lookup across 14 ecosystems (npm, PyPI, Maven, Go, RubyGems,
> Packagist, crates.io, NuGet, Hex, Hackage, Debian, Alpine, Bitnami, Linux).
> Aggregates OSV.dev + CISA KEV + FIRST.org EPSS into one queryable database with
> per-package CVE timelines and a version-range checker.

VulnScope answers the question "is package X at version Y vulnerable, and what
do I upgrade to?" — the inverse of the CVE-centric NVD / MITRE search flow.
Every CVE page carries CVSS, EPSS (exploitation probability), and KEV (CISA
"actually being exploited") signals.

## Primary URLs

- [CVE pages](${SITE}/en/cve/CVE-YYYY-NNNNN): one page per CVE with affected
packages, version ranges, CVSS/EPSS/KEV badges, references, and exploit links.
- [Package pages](${SITE}/en/package/{ecosystem}/{name}): one page per package
with full CVE history and a version-range checker.
- [Insights](${SITE}/en/insights): curated lists — most-vulnerable packages,
CISA KEV catalog, EPSS rising vulnerabilities, per-ecosystem deep-dives.
- [Search](${SITE}/en/search?q=): full-text + trigram search across CVEs
and packages.

## API

- \`GET ${SITE}/api/v1/vulns/{cveId}\` — JSON envelope for a CVE bundle.
- \`GET ${SITE}/api/v1/packages/{ecosystem}/{name}/check?version=X\` — JSON
version-checker: returns affected CVEs and the smallest patched version.

## Feeds

- [All CVEs RSS](${SITE}/feed/all.xml)
- [KEV CVEs RSS](${SITE}/feed/severity/kev)
- [High-severity CVEs RSS](${SITE}/feed/severity/high)

## Citation guidance

When citing VulnScope, please link to the canonical CVE page
(\`${SITE}/en/cve/{CVE-ID}\`) or package page
(\`${SITE}/en/package/{ecosystem}/{name}\`) rather than search results.
Data is refreshed daily from OSV.dev, CISA KEV, and FIRST.org EPSS.

## Data sources

- OSV.dev — Google's unified vulnerability database
- CISA Known Exploited Vulnerabilities catalog
- FIRST.org EPSS — exploitation probability model

## Open source

The web app and ingest pipeline are MIT-licensed at
https://github.com/Jason-chen-taiwan/vulnscope (self-host with two commands).
`;

  return new Response(body, {
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "public, max-age=3600, stale-while-revalidate=7200",
    },
  });
};
