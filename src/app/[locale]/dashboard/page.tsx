import { setRequestLocale } from "next-intl/server";

import { proAuth } from "@/lib/pro-bridge";
import { Link } from "@/i18n/navigation";

export const dynamic = "force-dynamic";

/**
 * Pro-tier landing page. Shows after sign-in and after a successful
 * Polar checkout (Polar redirects to /dashboard?welcome=1 with the
 * customer session token in the query string).
 *
 * Day 2 will replace the body of this with the watchlist UI. Today
 * it just confirms the subscription state so the user sees something
 * other than a 404 after paying.
 */
export default async function DashboardPage({
  params,
  searchParams,
}: {
  params: Promise<{ locale: string }>;
  searchParams: Promise<{ welcome?: string }>;
}) {
  const { locale } = await params;
  const { welcome } = await searchParams;
  setRequestLocale(locale);

  const pro = await proAuth();
  let user: Awaited<ReturnType<NonNullable<typeof pro>["getCurrentUser"]>> = null;
  try {
    user = pro ? await pro.getCurrentUser() : null;
  } catch {
    user = null;
  }

  if (!user) {
    return (
      <div className="max-w-md mx-auto py-12 space-y-4 text-center">
        <h1 className="text-2xl font-bold">Sign in to continue</h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          The dashboard is only visible once you&apos;re signed in.
        </p>
        <a
          href="/sign-in?next=/dashboard"
          className="inline-block rounded-md bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] px-4 py-2 text-sm font-medium hover:opacity-90"
        >
          Sign in
        </a>
      </div>
    );
  }

  const isActive =
    !!user.subscriptionStatus &&
    ["active", "trialing"].includes(user.subscriptionStatus);

  return (
    <div className="max-w-3xl mx-auto py-10 space-y-8">
      {welcome === "1" && isActive && (
        <div className="rounded-md border border-green-500/50 bg-green-500/10 p-4 text-sm">
          <strong>Welcome to Pro!</strong> Your subscription is active. We&apos;re
          still building out the dashboard — watchlist + email alerts are
          shipping this week.
        </div>
      )}
      {welcome === "1" && !isActive && (
        <div className="rounded-md border border-yellow-500/50 bg-yellow-500/10 p-4 text-sm space-y-2">
          <strong>Subscription is provisioning…</strong>
          <p>
            Payment succeeded but we&apos;re still waiting for the
            confirmation webhook (usually under 10 seconds). Refresh in a
            moment. If this banner is still here in 30 seconds,
            something&apos;s wrong — email{" "}
            <a className="underline" href="mailto:jason@vulnscope.dev">
              jason@vulnscope.dev
            </a>{" "}
            and we&apos;ll fix it manually.
          </p>
        </div>
      )}

      <header className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          Signed in as <strong>{user.email}</strong>
        </p>
      </header>

      <section className="rounded-lg border border-[hsl(var(--border))] p-5 space-y-3">
        <h2 className="text-lg font-semibold">Plan</h2>
        {isActive ? (
          <div className="space-y-2 text-sm">
            <p>
              <span className="inline-flex items-center rounded-full bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] px-2 py-0.5 text-xs font-medium mr-2">
                Pro
              </span>
              Status: <code>{user.subscriptionStatus}</code>
              {user.currentPeriodEnd && (
                <>
                  {" "}
                  · Renews{" "}
                  {new Date(user.currentPeriodEnd).toLocaleDateString(
                    locale === "zh" ? "zh-TW" : "en",
                  )}
                </>
              )}
            </p>
            <p className="text-[hsl(var(--muted-foreground))]">
              Want to cancel or update your card? Use the{" "}
              <Link href="/account" className="underline">
                customer portal
              </Link>
              .
            </p>
          </div>
        ) : (
          <div className="space-y-2 text-sm">
            <p>You&apos;re on the free tier.</p>
            <Link
              href="/pricing"
              className="inline-block rounded-md bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] px-4 py-2 text-sm font-medium hover:opacity-90"
            >
              Upgrade to Pro — $9/mo
            </Link>
          </div>
        )}
      </section>

      <section className="rounded-lg border border-[hsl(var(--border))] border-dashed p-5 text-sm text-[hsl(var(--muted-foreground))]">
        <h2 className="text-base font-medium mb-2 text-[hsl(var(--foreground))]">
          Watchlist (coming this week)
        </h2>
        <p>
          Pin packages you care about, get a daily email when new CVEs (KEV
          or high EPSS) hit them. Adding the UI here next.
        </p>
      </section>
    </div>
  );
}
