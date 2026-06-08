import { NextRequest, NextResponse } from "next/server";
import createMiddleware from "next-intl/middleware";
import { checkLimit, type BucketName } from "./lib/rate-limit";
import { routing } from "./i18n/routing";

/**
 * Composed middleware: rate-limit gate → next-intl locale handling.
 *
 * Why rate-limit lives here:
 *   - API routes are protected one-by-one via `withRateLimit` HOF
 *     (round 1, commit 98c998b).
 *   - SSR pages (everything under /zh/** and /en/**) are NOT route
 *     handlers; the HOF doesn't fit them. They all funnel through
 *     this middleware, so this is the natural choke point.
 *   - One curl loop on `/zh/search?q=log4j` saturated the 512 MB
 *     Postgres machine (2026-06-08 incident) — without middleware
 *     rate-limit, that attack still works even though /api/v1/vulns
 *     is fully protected.
 *
 * Identity is IP-only. The auth path inside `checkLimit` lazy-imports
 * @/lib/pro-bridge which carries `import "server-only"` and Better
 * Auth — Node-runtime only. Middleware runs on Node today (no
 * `export const runtime` set), but keeping the auth lookup out of
 * the request path saves ~1ms per page render and stays portable if
 * we ever migrate middleware to Edge.
 */
const intl = createMiddleware(routing);

function bucketForPath(pathname: string): BucketName {
  // next-intl always prefixes the locale (localePrefix: "always"), so
  // pathname always starts with /xx/. Match against /xx/<segment>.
  if (/^\/[a-z]{2}\/search\b/.test(pathname)) return "search_page";
  if (/^\/[a-z]{2}\/insights\b/.test(pathname)) return "insights_page";
  // /<locale>/admin/* is the admin DASHBOARD (e.g. /zh/admin/jobs).
  // Treat as page_view, NOT admin bucket. The `admin` bucket is for
  // the mutating /api/v1/admin/* endpoints (which are also ADMIN_TOKEN
  // gated). The dashboard auto-refreshes every 5s (12/min); admin
  // bucket's 5/min cap would lock the operator out of their own UI.
  return "page_view";
}

export default async function middleware(req: NextRequest) {
  const r = await checkLimit(req, bucketForPath(req.nextUrl.pathname), {
    identityHint: "ip-only",
  });
  if (!r.allow) {
    return new NextResponse(
      JSON.stringify({
        data: null,
        meta: null,
        errors: [
          {
            code: "RATE_LIMITED",
            message: `Rate limit exceeded. Try again in ${r.retryAfterSec}s.`,
          },
        ],
      }),
      {
        status: 429,
        headers: { "Content-Type": "application/json", ...r.headers },
      },
    );
  }
  const resp = await intl(req);
  for (const [k, v] of Object.entries(r.headers)) resp.headers.set(k, v);
  return resp;
}

export const config = {
  // Same matcher as the original i18n-only middleware. Intentionally
  // excludes /api (per-route limiter), /feed (wrapped in their route
  // handlers below — different bucket), /_next, and any path with a
  // file extension (static assets).
  matcher: ["/((?!api|feed|_next|.*\\..*).*)"],
};
