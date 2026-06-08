/**
 * POST /api/v1/billing/checkout
 *
 * Returns a one-time Polar Checkout URL the browser should redirect
 * to. The user must already be signed in (Pro routes redirect to
 * /sign-in if not).
 *
 * Idempotent in the sense that calling it twice in a row just
 * creates two checkout sessions — Polar treats each as independent
 * and only the one the user actually completes turns into a
 * subscription. We make no attempt to dedupe.
 *
 * OSS-side stub: forwards into /pro/billing/checkout if Pro is
 * enabled, otherwise 404.
 */
import { proAuth } from "@/lib/pro-bridge";
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { withRateLimit } from "@/lib/rate-limit";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export const POST = withRateLimit("mutation", async (req: NextRequest) => {
  const pro = await proAuth();
  if (!pro) {
    return NextResponse.json({ error: "Pro tier not enabled" }, { status: 404 });
  }

  let user;
  try {
    user = await pro.getCurrentUser();
  } catch (e) {
    console.error("[billing/checkout] getCurrentUser failed:", e);
    return NextResponse.json({ error: "Auth error" }, { status: 500 });
  }
  if (!user) {
    return NextResponse.json({ error: "Sign in required" }, { status: 401 });
  }

  // Already paid — short-circuit to the customer portal instead of
  // creating a duplicate subscription.
  if (
    user.subscriptionStatus &&
    ["active", "trialing"].includes(user.subscriptionStatus)
  ) {
    return NextResponse.json(
      { error: "Already subscribed", redirect: "/dashboard" },
      { status: 409 },
    );
  }

  // Resolve site URL from the request (so localhost + Fly + the
  // future vulnscope.dev all work without env juggling).
  const url = new URL(req.url);
  const siteUrl =
    process.env.NEXT_PUBLIC_SITE_URL ?? `${url.protocol}//${url.host}`;

  try {
    const { url: checkoutUrl } = await pro.createCheckoutSession({
      userId: user.id,
      email: user.email,
      siteUrl,
    });
    return NextResponse.json({ url: checkoutUrl });
  } catch (e) {
    console.error("[billing/checkout] Polar createCheckoutSession failed:", e);
    return NextResponse.json(
      { error: "Could not create checkout session" },
      { status: 502 },
    );
  }
});
