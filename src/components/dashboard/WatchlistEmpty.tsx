"use client";

import { useTranslations } from "next-intl";

/**
 * Empty-state hint when the user has no watches yet. The
 * "popular packages" grid now lives in PopularPackages and is shown
 * permanently in the panel, so this component is just the prose.
 */
export function WatchlistEmpty() {
  const t = useTranslations("Dashboard");

  return (
    <div className="rounded-md border border-dashed border-[hsl(var(--border))] p-6 text-center space-y-2">
      <h3 className="font-medium text-sm">{t("watchlistEmptyTitle")}</h3>
      <p className="text-xs text-[hsl(var(--muted-foreground))]">
        {t("watchlistEmptyBodyShort")}
      </p>
    </div>
  );
}
