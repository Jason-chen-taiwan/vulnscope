"use client";

import { useTranslations } from "next-intl";

/**
 * Empty state shown when the user has no watches yet. Suggests two
 * concrete packages to try (npm/next, Debian/openssl) so the user
 * has something to click rather than freeze at an empty input.
 */
export function WatchlistEmpty() {
  const t = useTranslations("Dashboard");
  return (
    <div className="rounded-md border border-dashed border-[hsl(var(--border))] p-6 text-center space-y-2">
      <h3 className="font-medium text-sm">{t("watchlistEmptyTitle")}</h3>
      <p className="text-xs text-[hsl(var(--muted-foreground))]">
        {t("watchlistEmptyBody", {
          sample1: "npm/next",
          sample2: "Debian/openssl",
        })}
      </p>
    </div>
  );
}
