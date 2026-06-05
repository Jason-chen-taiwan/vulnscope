"use client";

import { useTranslations } from "next-intl";

import type { PopularPackage } from "./types";

/**
 * Always-visible suggestion grid. Lives next to the search box so
 * users can discover something to watch even after they've already
 * added a few items. Clicking one fires a CustomEvent the
 * WatchlistAddSearch listens for — pre-fills the picker and skips
 * straight to the version-select stage.
 */
export function PopularPackages({
  popular,
  disabled,
}: {
  popular: PopularPackage[];
  disabled?: boolean;
}) {
  const t = useTranslations("Dashboard");
  if (popular.length === 0) return null;

  function pick(p: PopularPackage) {
    if (disabled) return;
    window.dispatchEvent(
      new CustomEvent("vulnscope:watchlist:pick", {
        detail: { ecosystem: p.ecosystem, name: p.name },
      }),
    );
  }

  return (
    <div className="space-y-2">
      <p className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wide">
        {t("popularHeading")}
      </p>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
        {popular.map((p) => (
          <button
            key={`${p.ecosystem}/${p.name}`}
            type="button"
            onClick={() => pick(p)}
            disabled={disabled}
            className="rounded-md border border-[hsl(var(--border))] p-2 text-left text-xs hover:bg-[hsl(var(--accent))] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <div className="font-mono uppercase text-[10px] text-[hsl(var(--muted-foreground))]">
              {p.ecosystem}
            </div>
            <div className="font-mono truncate">{p.name}</div>
            <div className="text-[10px] text-[hsl(var(--muted-foreground))]">
              {p.kev_count > 0 && (
                <span className="text-orange-600 font-medium">
                  {p.kev_count} KEV ·{" "}
                </span>
              )}
              {t("popularCveCount", { n: p.cve_count })}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
