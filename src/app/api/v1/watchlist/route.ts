/**
 * GET  /api/v1/watchlist — list the current user's watched packages
 *                          with each item's top-3 recent CVEs
 * POST /api/v1/watchlist — add a package (idempotent on duplicate)
 *
 * Both require a signed-in user (free OR pro). POST enforces the
 * 3-item free-tier limit before insert; returns 402
 * `free_limit_reached` so the UI can show an inline upsell.
 *
 * Returns 503 when Pro is disabled (self-host build / PRO_ENABLED=0)
 * so the UI can degrade gracefully rather than show 500s.
 */
import { NextRequest } from "next/server";
import { z } from "zod";

import { ok, fail } from "@/lib/envelope";
import { proAuth } from "@/lib/pro-bridge";
import { ECOSYSTEMS } from "@/lib/ecosystems";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const ECOSYSTEM_ENUM = z.enum(ECOSYSTEMS);

const PostInput = z.object({
  ecosystem: ECOSYSTEM_ENUM,
  packageName: z.string().min(1).max(255),
  // Pin a specific version. Omit or null = "watch any version".
  version: z.string().min(1).max(120).nullable().optional(),
});

const ACTIVE_STATUSES = new Set(["active", "trialing"]);

function isPro(status: string | null | undefined): boolean {
  return !!status && ACTIVE_STATUSES.has(status);
}

export async function GET() {
  const pro = await proAuth();
  if (!pro) return fail(503, "pro_unavailable", "Pro features are not enabled on this build");

  let user;
  try {
    user = await pro.getCurrentUser();
  } catch (e) {
    console.error("[watchlist GET] getCurrentUser failed:", e);
    return fail(503, "upstream_down", "Auth service is unavailable");
  }
  if (!user) return fail(401, "unauthenticated", "Sign in to view your watchlist");

  try {
    const items = await pro.getWatchlistWithSummary(user.id);
    const userIsPro = isPro(user.subscriptionStatus);
    return ok(items, {
      used: items.length,
      limit: userIsPro ? pro.PRO_WATCHLIST_LIMIT : pro.FREE_WATCHLIST_LIMIT,
      isPro: userIsPro,
    });
  } catch (e) {
    console.error("[watchlist GET] failed:", e);
    return fail(502, "list_failed", "Could not load watchlist");
  }
}

export async function POST(req: NextRequest) {
  const pro = await proAuth();
  if (!pro) return fail(503, "pro_unavailable", "Pro features are not enabled on this build");

  let user;
  try {
    user = await pro.getCurrentUser();
  } catch (e) {
    console.error("[watchlist POST] getCurrentUser failed:", e);
    return fail(503, "upstream_down", "Auth service is unavailable");
  }
  if (!user) return fail(401, "unauthenticated", "Sign in to add to your watchlist");

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return fail(400, "invalid_json", "Request body must be JSON");
  }

  const parsed = PostInput.safeParse(body);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    return fail(
      400,
      "invalid_input",
      first?.message ?? "Invalid input",
      first?.path.join(".") ?? undefined,
    );
  }
  const { ecosystem, packageName, version } = parsed.data;

  // Tier limit. Known TOCTOU between countWatches and addWatch —
  // see comment in pro/lib/watchlist.ts for why we accept it for MVP.
  // Pro is capped too (anti-abuse + DB pool protection); the failure
  // code is different so the UI can show a different message
  // ("upgrade" vs "you've hit your plan's cap, contact us").
  const userIsPro = isPro(user.subscriptionStatus);
  const limit = userIsPro ? pro.PRO_WATCHLIST_LIMIT : pro.FREE_WATCHLIST_LIMIT;
  const used = await pro.countWatches(user.id);
  if (used >= limit) {
    return fail(
      402,
      userIsPro ? "pro_limit_reached" : "free_limit_reached",
      userIsPro
        ? `Pro plan supports up to ${limit} packages. Contact support@vulnscope.dev if you need more.`
        : `Free tier supports up to ${limit} packages. Upgrade to Pro for ${pro.PRO_WATCHLIST_LIMIT}.`,
    );
  }

  try {
    const { row, created } = await pro.addWatch(
      user.id,
      ecosystem,
      packageName,
      version ?? null,
    );
    return ok(row, { created });
  } catch (e) {
    console.error("[watchlist POST] addWatch failed:", e);
    return fail(502, "add_failed", "Could not add to watchlist");
  }
}
