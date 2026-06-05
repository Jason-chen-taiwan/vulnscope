"use client";

import { useState, useTransition } from "react";
import { useTranslations, useLocale } from "next-intl";

/**
 * Pricing-page CTA for the Pro tier.
 *
 * Three states:
 *   - Already on Pro → link to /dashboard
 *   - Not signed in → 401 from /api/v1/billing/checkout → redirect
 *     to GitHub OAuth and bounce back to /pricing
 *   - Signed in, not paying → POST opens Polar checkout in same tab
 *
 * Locale-aware sign-in bounce so users land back on the right
 * /<locale>/pricing after auth.
 */
export function UpgradeButton({ alreadyPro }: { alreadyPro: boolean }) {
  const t = useTranslations("Pricing.cta");
  const locale = useLocale();
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  if (alreadyPro) {
    return (
      <a
        href={`/${locale}/dashboard`}
        className="block w-full rounded-md bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] text-center py-2 text-sm font-medium hover:opacity-90"
      >
        {t("alreadyPro")}
      </a>
    );
  }

  return (
    <div className="space-y-2">
      <button
        type="button"
        disabled={pending}
        onClick={() => {
          setError(null);
          startTransition(async () => {
            try {
              const res = await fetch("/api/v1/billing/checkout", {
                method: "POST",
                headers: { "content-type": "application/json" },
              });
              if (res.status === 401) {
                window.location.href = `/sign-in?next=/${locale}/pricing`;
                return;
              }
              if (!res.ok) {
                const body = await res.json().catch(() => ({}));
                throw new Error(body.error ?? `HTTP ${res.status}`);
              }
              const { url } = await res.json();
              window.location.href = url;
            } catch (e) {
              setError(e instanceof Error ? e.message : t("generic"));
            }
          });
        }}
        className="block w-full rounded-md bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] text-center py-2 text-sm font-medium hover:opacity-90 disabled:opacity-50"
      >
        {pending ? t("opening") : t("checkout")}
      </button>
      {error && (
        <p className="text-xs text-red-500 dark:text-red-400">{error}</p>
      )}
      <p className="text-xs text-center text-[hsl(var(--muted-foreground))]">
        {t("signinHint")}
      </p>
    </div>
  );
}
