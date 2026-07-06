# Edge caching (D1 free-tier protection)

Data changes ~once/day (daily ingest). CVE/package/insights/list pages are
effectively static between ingests, so they are cached at Cloudflare's edge.
This keeps repeat crawler/bot hits from invoking the Worker or reading D1 —
mandatory to stay under D1's free-tier cap of 5,000,000 rows read/day (a single
uncached CVE query reads ~65,800 rows).

## Origin cache policy (in code)

`next.config.ts` sets, via the Next `headers()` config, on the cacheable page
responses:

```
Cache-Control: public, s-maxage=86400, stale-while-revalidate=604800
```

- `s-maxage=86400` — 1 day fresh at shared/CDN caches (Cloudflare). Uses
  `s-maxage` (not `max-age`) so browsers don't over-cache stale data.
- `stale-while-revalidate=604800` — up to 7 days serving stale while a
  background refresh happens.

Cacheable routes (both locales, `en` and `zh`):
- `/:locale/cve/:id*` (CVE detail)
- `/:locale/package/:ecosystem/:name*` (package detail)
- `/:locale/insights` and `/:locale/insights/:path*`
- `/:locale/packages` (package list)
- `/:locale` (home / CVE list dashboard)

Explicitly NOT cached: `/:locale/search` (query-dependent, stays dynamic),
`/api/*`, and `/feed/*`.

## Cloudflare Cache Rule (dashboard — operator must add)

Cloudflare caches HTML only when told to. Add a Cache Rule so edge caching is
belt-and-suspenders even if a route's origin header ever regresses. This
CANNOT be set from code — the operator adds it in the dashboard.

Dashboard path: **Caching → Cache Rules → Create rule**

- **Rule name:** `Cache CVE/list pages`
- **When incoming requests match** (expression):
  ```
  (http.request.uri.path matches "^/(en|zh)/cve/") or
  (http.request.uri.path matches "^/(en|zh)/package/") or
  (http.request.uri.path matches "^/(en|zh)/packages$") or
  (http.request.uri.path matches "^/(en|zh)/insights") or
  (http.request.uri.path matches "^/(en|zh)$")
  ```
  (Do NOT include `/search`, `/api`, or `/feed`.)
- **Then — Cache eligibility:** `Eligible for cache`
- **Edge TTL:** `Use cache-control header if present, use default otherwise`
  with a default of **1 day** (86400s). This respects the origin
  `Cache-Control` (`s-maxage=86400`) set in code.
- **Browser TTL:** `Respect origin` (the origin sends no `max-age`, so browsers
  revalidate — intended).

## Verifying a cache HIT (post-deploy)

```
curl -sI https://<prod-url>/en/cve/CVE-2021-44228 | grep -i cf-cache-status
```

Run twice — the second request should show `cf-cache-status: HIT`. The first is
usually `MISS` (edge cold), then subsequent hits are served from the edge
without invoking the Worker or touching D1.
