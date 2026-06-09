/**
 * POST /api/v1/admin/run-digest
 *
 * Manual trigger for the daily watchlist digest. Used to:
 *   1. Smoke-test the email integration before flipping cron on
 *      (?onlyEmail=you@example.com)
 *   2. Re-run if a previous day's send failed and we want to retry
 *      (?sentDate=YYYY-MM-DD to override the alert_logs idempotency
 *       key — same date means "skip already-sent rows", a fresh
 *       date means "send again")
 *   3. Dry-run rendering to inspect the output without sending
 *      (?dryRun=1)
 *
 * Gated by ADMIN_TOKEN (header or query string). Localhost is
 * allowed without a token for dev.
 */
import { NextRequest } from "next/server";

import { fail, ok } from "@/lib/envelope";
import { proAuth } from "@/lib/pro-bridge";
import { withRateLimit } from "@/lib/rate-limit";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
// Digest run can hit 25+ users in worst case + Resend round-trips
// per user; default 10s server function limit is too tight.
export const maxDuration = 300;

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

export const POST = withRateLimit("admin", async (req: NextRequest) => {
  if (!isAuthorized(req)) {
    return fail(
      401,
      "UNAUTHORIZED",
      "set ADMIN_TOKEN env var or call from localhost",
    );
  }
  const pro = await proAuth();
  if (!pro) {
    return fail(404, "PRO_DISABLED", "Pro tier not enabled");
  }

  const q = req.nextUrl.searchParams;
  const onlyEmail = q.get("onlyEmail") ?? undefined;
  const dryRun = q.get("dryRun") === "1";
  const sentDate = q.get("sentDate") ?? undefined;

  try {
    const result = await pro.runDigest({ onlyEmail, dryRun, sentDate });
    return ok(result);
  } catch (e) {
    console.error("[admin/run-digest] failed:", e);
    return fail(
      500,
      "DIGEST_RUN_FAILED",
      e instanceof Error ? e.message : String(e),
    );
  }
});
