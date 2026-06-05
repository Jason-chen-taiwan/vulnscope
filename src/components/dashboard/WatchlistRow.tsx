"use client";

import { useState, useTransition } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { Link } from "@/i18n/navigation";

import { SeverityBadge, KevBadge } from "@/components/SeverityBadge";
import { EpssBadge } from "@/components/EpssBadge";

import type { ClientWatchlistRow } from "./types";

interface Props {
  row: ClientWatchlistRow;
  onRemoved: (id: string) => void;
}

/**
 * One row in the dashboard watchlist. Header shows ecosystem +
 * package name (linked to the full package page); body shows the
 * top 3 most-recent CVEs with severity/KEV/EPSS chips. Trailing
 * button removes the watch.
 */
export function WatchlistRow({ row, onRemoved }: Props) {
  const t = useTranslations("Dashboard");
  const format = useFormatter();
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function remove() {
    setError(null);
    startTransition(async () => {
      try {
        const r = await fetch(`/api/v1/watchlist/${row.id}`, { method: "DELETE" });
        if (!r.ok && r.status !== 404) {
          setError(t("removeError"));
          return;
        }
        // 404 = already gone; treat as success so client state catches up.
        onRemoved(row.id);
      } catch {
        setError(t("removeError"));
      }
    });
  }

  return (
    <li className="rounded-md border border-[hsl(var(--border))] p-3 flex flex-col gap-2">
      <div className="flex items-baseline gap-3">
        <span className="text-xs font-mono uppercase text-[hsl(var(--muted-foreground))] shrink-0">
          {row.ecosystem}
        </span>
        <Link
          href={`/package/${encodeURIComponent(row.ecosystem)}/${encodeURIComponent(
            row.packageName,
          )}`}
          className="font-mono text-sm truncate flex-1 hover:underline"
        >
          {row.packageName}
        </Link>
        <button
          type="button"
          aria-label={t("remove")}
          title={t("remove")}
          disabled={pending}
          onClick={remove}
          className="text-xs text-[hsl(var(--muted-foreground))] hover:text-red-500 disabled:opacity-50"
        >
          {pending ? "…" : "✕"}
        </button>
      </div>

      {row.latestCves.length === 0 ? (
        <p className="text-xs text-[hsl(var(--muted-foreground))]">{t("noCvesYet")}</p>
      ) : (
        <ul className="space-y-1.5">
          {row.latestCves.map((cve) => (
            <li key={cve.cve_id} className="flex items-baseline gap-2 text-xs">
              <Link
                href={`/cve/${cve.cve_id}`}
                className="font-mono shrink-0 hover:underline"
              >
                {cve.cve_id}
              </Link>
              <SeverityBadge severity={cve.severity} score={cve.base_score} />
              <KevBadge kev={cve.kev} />
              <EpssBadge score={cve.epss_score} />
              {cve.published_at && (
                <span className="text-[hsl(var(--muted-foreground))] ml-auto shrink-0">
                  {format.relativeTime(new Date(cve.published_at))}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}

      {error && <p className="text-xs text-red-500">{error}</p>}
    </li>
  );
}
