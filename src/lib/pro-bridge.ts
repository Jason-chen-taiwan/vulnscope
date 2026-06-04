/**
 * Bridge from OSS code to the Pro tier.
 *
 * Pro implementation lives in /pro (private repo, cloned at build
 * time for hosted deploys). OSS / self-host builds fall through to
 * /pro-stub via the `@pro/*` webpack alias configured in
 * next.config.ts. Both expose the same surface, so the imports here
 * are statically analyzable and webpack bundles whichever side the
 * alias resolved to at build time.
 *
 * No dynamic import. No native ESM gymnastics. No node_modules
 * splicing in the runner image. The whole Pro layer just rides the
 * Next.js webpack tree like any other module.
 *
 * PRO_ENABLED is still consulted at request time: even with the real
 * Pro code bundled, you can force OSS behaviour with PRO_ENABLED=0
 * (useful during incident response if Pro routes are misbehaving and
 * you want them to 404 immediately without a redeploy).
 */
import "server-only";

import { auth as proAuthInstance } from "@pro/auth/config";
import {
  getCurrentUser,
  requirePro,
  ProAccessError,
  type ProUser,
} from "@pro/auth/server";
import {
  createCheckoutSession,
  customerPortalUrl,
} from "@pro/billing/polar";
import { handlePolarWebhook } from "@pro/billing/webhook";

const PRO_ENABLED = process.env.PRO_ENABLED === "1";

export type ProModule = {
  auth: typeof proAuthInstance;
  getCurrentUser: typeof getCurrentUser;
  requirePro: typeof requirePro;
  ProAccessError: typeof ProAccessError;
  createCheckoutSession: typeof createCheckoutSession;
  customerPortalUrl: typeof customerPortalUrl;
  handlePolarWebhook: typeof handlePolarWebhook;
};

const proModule: ProModule = {
  auth: proAuthInstance,
  getCurrentUser,
  requirePro,
  ProAccessError,
  createCheckoutSession,
  customerPortalUrl,
  handlePolarWebhook,
};

/**
 * Returns the Pro module if enabled, otherwise null. Routes that
 * want to gracefully 404 in OSS mode (or when PRO_ENABLED=0) should
 * branch on this.
 */
export async function proAuth(): Promise<ProModule | null> {
  return PRO_ENABLED ? proModule : null;
}

export async function isPro(): Promise<boolean> {
  if (!PRO_ENABLED) return false;
  try {
    const user = await getCurrentUser();
    return (
      !!user?.subscriptionStatus &&
      ["active", "trialing"].includes(user.subscriptionStatus)
    );
  } catch (e) {
    // OAuth env missing / DB unreachable / etc. Public pages
    // (/pricing, etc.) shouldn't crash because the Pro tier is
    // mid-configuration; just treat the visitor as anonymous.
    console.warn(
      "[pro-bridge] isPro() failed, treating as not-pro:",
      e instanceof Error ? e.message : e,
    );
    return false;
  }
}

export type { ProUser };
