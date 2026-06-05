"use client";

import { useTranslations } from "next-intl";
import { Link } from "@/i18n/navigation";

/**
 * Inline banner shown when a free-tier user tries to add their 4th
 * package. Direct link to /pricing — the page server-fetches isPro
 * so the actual CTA there will be correct (subscribe vs. open
 * dashboard).
 */
export function WatchlistUpsell() {
  const t = useTranslations("Dashboard");
  return (
    <div className="rounded-md border border-yellow-500/50 bg-yellow-500/10 p-4 space-y-2 text-sm">
      <strong>{t("limitReachedTitle")}</strong>
      <p className="text-[hsl(var(--muted-foreground))]">{t("limitReachedBody")}</p>
      <Link
        href="/pricing"
        className="inline-block rounded-md bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] px-3 py-1.5 text-xs font-medium hover:opacity-90"
      >
        {t("limitReachedCta")}
      </Link>
    </div>
  );
}
