import { getTranslations, setRequestLocale } from "next-intl/server";
import { redirect } from "next/navigation";

import { Link } from "@/i18n/navigation";
import { proAuth } from "@/lib/pro-bridge";

export const dynamic = "force-dynamic";

/**
 * Account / "Manage plan" page.
 *
 * Shows the user's current subscription state in-app (status, next
 * billing date, tier). The actual self-service actions (update card,
 * download invoices, cancel) live on Polar's hosted portal — clicking
 * "Open billing portal" runs a server action that mints a one-time
 * Polar customer-session URL and redirects.
 *
 * Why a server action instead of pre-rendering the portal URL into
 * the page: Polar's customer-session URLs are short-lived and tied
 * to the click. Rendering them upfront means the URL is stale if
 * the user opens the page and walks away.
 */
export default async function AccountPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "Account" });

  const pro = await proAuth();
  const user = pro ? await pro.getCurrentUser().catch(() => null) : null;

  if (!user) {
    redirect(`/${locale}/sign-in?next=/${locale}/account`);
  }

  const isActive =
    !!user.subscriptionStatus &&
    ["active", "trialing"].includes(user.subscriptionStatus);
  const isCanceled = user.subscriptionStatus === "canceled";
  const periodEnd = user.currentPeriodEnd
    ? new Date(user.currentPeriodEnd).toLocaleDateString(
        locale === "zh" ? "zh-TW" : "en",
      )
    : null;

  async function openPortal() {
    "use server";
    const proInner = await proAuth();
    if (!proInner) return;
    const u = await proInner.getCurrentUser().catch(() => null);
    if (!u?.polarCustomerId) return;
    const url = await proInner.customerPortalUrl(u.polarCustomerId);
    redirect(url);
  }

  return (
    <div className="max-w-3xl mx-auto py-10 space-y-8">
      <header className="space-y-2">
        <Link
          href="/dashboard"
          className="text-xs text-[hsl(var(--muted-foreground))] no-underline hover:underline"
        >
          {t("backToDashboard")}
        </Link>
        <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          {t("subtitle")}
        </p>
      </header>

      {/* Current plan card */}
      <section className="rounded-lg border border-[hsl(var(--border))] p-5 space-y-3">
        <h2 className="text-base font-semibold">{t("currentPlan")}</h2>
        {isActive || isCanceled ? (
          <dl className="text-sm space-y-2">
            <div className="flex items-baseline gap-3">
              <dt className="text-[hsl(var(--muted-foreground))] w-24 shrink-0">
                {t("currentPlan")}
              </dt>
              <dd>
                <span className="inline-flex items-center rounded-full bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] px-2 py-0.5 text-xs font-medium">
                  Pro
                </span>
              </dd>
            </div>
            <div className="flex items-baseline gap-3">
              <dt className="text-[hsl(var(--muted-foreground))] w-24 shrink-0">
                {t("statusLabel")}
              </dt>
              <dd className="font-mono text-xs">
                {user.subscriptionStatus}
              </dd>
            </div>
            {periodEnd && (
              <div className="flex items-baseline gap-3">
                <dt className="text-[hsl(var(--muted-foreground))] w-24 shrink-0">
                  {isCanceled ? t("endsLabel") : t("renewsLabel")}
                </dt>
                <dd className="font-mono text-xs">{periodEnd}</dd>
              </div>
            )}
          </dl>
        ) : (
          <div className="space-y-3 text-sm">
            <p>
              <span className="inline-flex items-center rounded-full border border-[hsl(var(--border))] px-2 py-0.5 text-xs font-medium">
                {t("freeTier")}
              </span>
            </p>
            <p className="text-[hsl(var(--muted-foreground))]">
              {t("freeBody")}
            </p>
            <Link
              href="/pricing"
              className="inline-block rounded-md bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] px-4 py-2 text-sm font-medium no-underline hover:opacity-90"
            >
              {t("upgradeCta")}
            </Link>
          </div>
        )}
      </section>

      {/* Manage subscription card — only for paying users */}
      {(isActive || isCanceled) && user.polarCustomerId && (
        <section className="rounded-lg border border-[hsl(var(--border))] p-5 space-y-3">
          <h2 className="text-base font-semibold">{t("manageHeading")}</h2>
          <p className="text-sm text-[hsl(var(--muted-foreground))]">
            {t("manageBody")}
          </p>
          <form action={openPortal}>
            <button
              type="submit"
              className="rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-4 py-2 text-sm font-medium hover:bg-[hsl(var(--muted))]"
            >
              {t("openPolar")} ↗
            </button>
          </form>
          {isActive && (
            <p className="text-xs text-[hsl(var(--muted-foreground))]">
              {t("cancelHint")}
            </p>
          )}
        </section>
      )}
    </div>
  );
}
