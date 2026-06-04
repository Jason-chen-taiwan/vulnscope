/**
 * POST /api/v1/billing/webhook
 *
 * Polar webhook endpoint. Register this URL in
 *   https://polar.sh/dashboard/<org>/settings/webhooks
 * with at least the subscription.* and order.created events
 * subscribed, and paste the generated signing secret into
 * POLAR_WEBHOOK_SECRET.
 *
 * OSS-side stub: forwards into /pro/billing/webhook if Pro is
 * enabled, otherwise 404 (self-host doesn't accept Polar webhooks).
 */
import { proAuth } from "@/lib/pro-bridge";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(req: Request) {
  const pro = await proAuth();
  if (!pro) {
    return new Response("Pro tier not enabled", { status: 404 });
  }
  return pro.handlePolarWebhook(req);
}
