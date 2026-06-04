/**
 * Bridge from OSS code to optional /pro code.
 *
 * The Pro tier lives in a separate private repo cloned into ./pro on
 * the hosted build. Self-host doesn't have it. To keep this single
 * codebase buildable in both modes, we never import from `../pro`
 * statically — that would fail on self-host with
 * `Module not found: ../pro/auth/server`.
 *
 * Instead, every OSS-side touchpoint goes through this file. It does
 * a *dynamic* import gated on `PRO_ENABLED=1`. When Pro is off, the
 * functions return safe defaults (null user, not-subscribed, 404 on
 * Pro routes).
 *
 * If you find yourself wanting to import `pro/...` from OSS code,
 * add a function here instead. The lint rule in /scripts/check-pro-
 * isolation.ts enforces this.
 */
import "server-only";

const PRO_ENABLED = process.env.PRO_ENABLED === "1";

type ProModule = {
  auth: typeof import("../../pro/auth/config").auth;
  getCurrentUser: typeof import("../../pro/auth/server").getCurrentUser;
  requirePro: typeof import("../../pro/auth/server").requirePro;
  ProAccessError: typeof import("../../pro/auth/server").ProAccessError;
  createCheckoutSession: typeof import("../../pro/billing/polar").createCheckoutSession;
  customerPortalUrl: typeof import("../../pro/billing/polar").customerPortalUrl;
  handlePolarWebhook: typeof import("../../pro/billing/webhook").handlePolarWebhook;
};

let cached: ProModule | null = null;

async function loadPro(): Promise<ProModule | null> {
  if (!PRO_ENABLED) return null;
  if (cached) return cached;

  // Path is a runtime variable so webpack/Turbopack doesn't try to
  // statically resolve it during the OSS-only build (which doesn't
  // have ./pro on disk).
  const authPath = "../../pro/auth/config";
  const serverPath = "../../pro/auth/server";
  const billingPath = "../../pro/billing/polar";
  const webhookPath = "../../pro/billing/webhook";

  try {
    const [authMod, serverMod, billingMod, webhookMod] = await Promise.all([
      import(/* webpackIgnore: true */ authPath),
      import(/* webpackIgnore: true */ serverPath),
      import(/* webpackIgnore: true */ billingPath),
      import(/* webpackIgnore: true */ webhookPath),
    ]);
    cached = {
      auth: authMod.auth,
      getCurrentUser: serverMod.getCurrentUser,
      requirePro: serverMod.requirePro,
      ProAccessError: serverMod.ProAccessError,
      createCheckoutSession: billingMod.createCheckoutSession,
      customerPortalUrl: billingMod.customerPortalUrl,
      handlePolarWebhook: webhookMod.handlePolarWebhook,
    };
    return cached;
  } catch (e) {
    // Pro was enabled but the code isn't on disk — likely a
    // misconfigured self-host. Log and degrade to OSS mode.
    console.warn(
      "[pro-bridge] PRO_ENABLED=1 but ./pro module failed to load:",
      e instanceof Error ? e.message : e,
    );
    return null;
  }
}

export async function proAuth() {
  return loadPro();
}

export async function isPro(): Promise<boolean> {
  const pro = await loadPro();
  if (!pro) return false;
  const user = await pro.getCurrentUser();
  return !!user?.subscriptionStatus &&
    ["active", "trialing"].includes(user.subscriptionStatus);
}
