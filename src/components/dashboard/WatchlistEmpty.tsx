"use client";

import { useTranslations } from "next-intl";

import type { PopularPackage } from "./types";

/**
 * Empty state shown when the user has no watches yet. Surfaces a
 * short "popular packages" grid pulled from each major ecosystem on
 * the server side — clicking one writes it into the search input
 * (via a custom event the search component listens for) so the
 * user goes through the same add-with-version flow.
 *
 * Falls back to a static prose hint if the popular query failed.
 */
export function WatchlistEmpty({ popular }: { popular: PopularPackage[] }) {
  const t = useTranslations("Dashboard");

  function pick(p: PopularPackage) {
    // The search component listens on window for this event and
    // pre-fills + auto-picks the package. Simpler than threading
    // refs through three component layers.
    window.dispatchEvent(
      new CustomEvent("vulnscope:watchlist:pick", {
        detail: { ecosystem: p.ecosystem, name: p.name },
      }),
    );
  }

  return (
    <div className="rounded-md border border-dashed border-[hsl(var(--border))] p-6 space-y-4">
      <div className="text-center space-y-2">
        <h3 className="font-medium text-sm">{t("watchlistEmptyTitle")}</h3>
        <p className="text-xs text-[hsl(var(--muted-foreground))]">
          {t("watchlistEmptyBody")}
        </p>
      </div>

      {popular.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wide">
            {t("popularHeading")}
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {popular.map((p) => (
              <button
                key={`${p.ecosystem}/${p.name}`}
                type="button"
                onClick={() => pick(p)}
                className="rounded-md border border-[hsl(var(--border))] p-2 text-left text-xs hover:bg-[hsl(var(--accent))]"
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
      )}
    </div>
  );
}
