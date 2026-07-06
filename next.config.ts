import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

const withNextIntl = createNextIntlPlugin("./src/i18n/request.ts");

// Edge-cache policy for pages whose data only changes on the daily ingest.
// 1-day fresh at the shared/CDN edge (Cloudflare honours `s-maxage`), then
// up to 7 days of stale-while-revalidate. `s-maxage` (not `max-age`) keeps
// browsers from over-caching while letting Cloudflare's edge serve repeat
// bot/crawler hits WITHOUT invoking the Worker or reading D1 — mandatory to
// stay under D1's free-tier read cap (a single uncached CVE query reads
// ~65.8k rows; the free cap is 5M rows/day).
const EDGE_CACHE = "public, s-maxage=86400, stale-while-revalidate=604800";

// Locale segment is always present (routing.localePrefix = "always") and is
// one of the configured locales. Anchoring to `(en|zh)` avoids accidentally
// matching non-locale first segments.
const LOCALE = "(en|zh)";

const cacheableHeader = (source: string) => ({
  source,
  headers: [{ key: "Cache-Control", value: EDGE_CACHE }],
});

const nextConfig: NextConfig = {
  serverExternalPackages: [
    "@renovatebot/pep440",
    "xregexp",
  ],
  experimental: {
    serverActions: { bodySizeLimit: "2mb" },
  },
  // `headers()` is applied by the Next server at the routing layer (before the
  // filesystem) and OpenNext honours it for rendered page responses. It runs
  // regardless of a page's `dynamic = "force-dynamic"` setting — that flag
  // controls rendering, not the response-header routing layer. NOTE: it does
  // NOT apply to immutable static assets (the Worker doesn't run in front of
  // those), which is fine here — every route below is a rendered page.
  //
  // Cacheable (data changes ~once/day on ingest): CVE detail, package detail,
  // insights hub + sub-pages, and the CVE/package LIST pages (home dashboard +
  // /packages). Explicitly EXCLUDED: /:locale/search (query-dependent, must
  // stay dynamic), API routes, and RSS feed routes.
  async headers() {
    return [
      cacheableHeader(`/${LOCALE}/cve/:id*`),
      cacheableHeader(`/${LOCALE}/package/:ecosystem/:name*`),
      cacheableHeader(`/${LOCALE}/insights`),
      cacheableHeader(`/${LOCALE}/insights/:path*`),
      cacheableHeader(`/${LOCALE}/packages`),
      // CVE list / dashboard lives at the locale root.
      cacheableHeader(`/${LOCALE}`),
    ];
  },
  // pg's native binding is optional; webpack tries to resolve it eagerly
  // and warns even when we never use it. Externalize it explicitly so the
  // server bundle skips the attempted resolution. The webpack type isn't
  // a direct dependency of this project so we use `any` rather than
  // pulling @types/webpack in just for one parameter.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  webpack: (config: any, { isServer }: { isServer: boolean }) => {
    if (isServer) {
      const existing = Array.isArray(config.externals) ? config.externals : [];
      config.externals = [...existing, "pg-native"];
    }

    return config;
  },
};

export default withNextIntl(nextConfig);

// Populate `getCloudflareContext().env` (the D1 `DB` binding, etc.) during
// `next dev` so server code that reads bindings works in local development.
// No-op in production builds.
import { initOpenNextCloudflareForDev } from "@opennextjs/cloudflare";
void initOpenNextCloudflareForDev();
