import { NextRequest } from "next/server";
import { fail } from "@/lib/envelope";

export const dynamic = "force-dynamic";

/**
 * Manual refresh trigger — deprecated under the web/worker process split.
 *
 * Background: in the single-process era this route called
 * `tick({ manual: true })` to kick off an immediate refresh. After the
 * web/worker split (one Next.js process for HTTP, a separate Node
 * process for scheduler + ingest), the web process has no scheduler
 * to invoke; calling tick() here would set the in-flight flag inside
 * the web process's memory only — the worker would never know.
 *
 * Keep the route as a tombstone (auth check stays in front to avoid
 * leaking the deprecation message to unauthorized callers). Daily
 * auto-refresh on the worker still runs every 24h; to force one, restart
 * the worker machine via `fly machine restart <worker-id>`.
 *
 * If we later need manual trigger back, the right approach is a DB
 * sentinel that the worker polls, or a real queue (pg-boss / BullMQ).
 */
function isAuthorized(req: NextRequest): boolean {
  const token = process.env.ADMIN_TOKEN;
  if (token) {
    const fromQuery = req.nextUrl.searchParams.get("token");
    const auth = req.headers.get("authorization") ?? "";
    const fromHeader = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    return fromQuery === token || fromHeader === token;
  }
  const host = req.headers.get("host") ?? "";
  return host.startsWith("localhost") || host.startsWith("127.0.0.1");
}

export async function POST(req: NextRequest) {
  if (!isAuthorized(req)) {
    return fail(401, "UNAUTHORIZED", "set ADMIN_TOKEN env var or call from localhost");
  }
  return fail(
    503,
    "MANUAL_REFRESH_DISABLED",
    "Manual refresh is disabled under the web/worker process split. " +
      "Daily auto-refresh runs on the worker process every 24h and on " +
      "worker boot. To force a refresh, restart the worker machine: " +
      "`fly machine restart <worker-id>`.",
  );
}
