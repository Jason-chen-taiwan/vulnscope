"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";

import { WatchlistAddSearch } from "./WatchlistAddSearch";
import { WatchlistRow } from "./WatchlistRow";
import { WatchlistEmpty } from "./WatchlistEmpty";
import { WatchlistUpsell } from "./WatchlistUpsell";
import { PopularPackages } from "./PopularPackages";
import type { ClientWatchlistRow, PopularPackage } from "./types";

interface Props {
  initialItems: ClientWatchlistRow[];
  isPro: boolean;
  freeLimit: number;
  proLimit: number;
  popular: PopularPackage[];
}

/**
 * Root client component for the dashboard watchlist. Receives
 * initial server-fetched data so first paint has no spinner, then
 * owns state for add/remove mutations.
 */
export function WatchlistPanel({
  initialItems,
  isPro,
  freeLimit,
  proLimit,
  popular,
}: Props) {
  const t = useTranslations("Dashboard");
  const [items, setItems] = useState<ClientWatchlistRow[]>(initialItems);
  const [limitReached, setLimitReached] = useState(false);

  const used = items.length;
  const limit = isPro ? proLimit : freeLimit;
  const atLimit = used >= limit;

  function onAdded(row: ClientWatchlistRow) {
    setItems((prev) => {
      if (prev.some((r) => r.id === row.id)) return prev;
      return [row, ...prev];
    });
    setLimitReached(false);
  }

  function onRemoved(id: string) {
    setItems((prev) => prev.filter((r) => r.id !== id));
    setLimitReached(false);
  }

  return (
    <section className="rounded-lg border border-[hsl(var(--border))] p-5 space-y-4">
      <header className="flex items-baseline justify-between gap-3 flex-wrap">
        <h2 className="text-lg font-semibold">{t("watchlistTitle")}</h2>
        <span className="text-xs text-[hsl(var(--muted-foreground))]">
          {t("usage", { used, limit })}
        </span>
      </header>

      <WatchlistAddSearch
        onAdded={onAdded}
        onLimitReached={() => setLimitReached(true)}
        disabled={atLimit}
      />

      <PopularPackages popular={popular} disabled={atLimit} />

      {limitReached && !isPro && <WatchlistUpsell />}
      {limitReached && isPro && (
        <div className="rounded-md border border-orange-500/50 bg-orange-500/10 p-3 text-xs">
          {t("proLimitBody", { limit: proLimit })}
        </div>
      )}

      {items.length === 0 ? (
        <WatchlistEmpty />
      ) : (
        <ul className="space-y-2">
          {items.map((row) => (
            <WatchlistRow key={row.id} row={row} onRemoved={onRemoved} />
          ))}
        </ul>
      )}
    </section>
  );
}
