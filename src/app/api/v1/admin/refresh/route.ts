import { NextRequest } from "next/server";
import { ok, fail } from "@/lib/envelope";
import { tick } from "@/lib/scheduler";

export const dynamic = "force-dynamic";

/**
 * Manual refresh trigger. Returns immediately; the refresh runs in the
 * background and progress is visible at /admin/jobs.
 *
 * Localhost-only by default. Set ADMIN_TOKEN in env and pass it as
 * `?token=...` (or `Authorization: Bearer ...`) to allow remote calls.
 */
function isAuthorized(req: NextRequest): boolean {
  const token = process.env.ADMIN_TOKEN;
  if (token) {
    const fromQuery = req.nextUrl.searchParams.get("token");
    const auth = req.headers.get("authorization") ?? "";
    const fromHeader = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    return fromQuery === token || fromHeader === token;
  }
  // No token configured → only allow loopback connections.
  const host = req.headers.get("host") ?? "";
  return host.startsWith("localhost") || host.startsWith("127.0.0.1");
}

export async function POST(req: NextRequest) {
  if (!isAuthorized(req)) {
    return fail(401, "UNAUTHORIZED", "set ADMIN_TOKEN env var or call from localhost");
  }
  // Fire and forget — the scheduler module dedupes concurrent ticks.
  void tick({ manual: true });
  return ok({ triggered: true, note: "refresh running in background; see /admin/jobs" });
}
