"use client";

import { useEffect, useRef, useState, useTransition } from "react";
import { useTranslations } from "next-intl";

import type { ClientWatchlistRow } from "./types";

interface Suggestion {
  ecosystem: string;
  name: string;
  cve_count: number;
}

interface Props {
  onAdded: (row: ClientWatchlistRow) => void;
  onLimitReached: () => void;
  disabled?: boolean;
}

/**
 * Autocomplete input for adding a package to the watchlist. Reuses
 * the /api/v1/packages/autocomplete endpoint and the keyboard +
 * click-outside patterns from src/components/HeaderSearch.tsx.
 *
 * Selecting a suggestion POSTs to /api/v1/watchlist directly instead
 * of navigating. The parent panel handles state updates via the
 * `onAdded` / `onLimitReached` callbacks.
 */
export function WatchlistAddSearch({ onAdded, onLimitReached, disabled }: Props) {
  const t = useTranslations("Dashboard");
  const [q, setQ] = useState("");
  const [items, setItems] = useState<Suggestion[]>([]);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const term = q.trim();
    if (term.length < 2) {
      setItems([]);
      setOpen(false);
      return;
    }
    const id = setTimeout(async () => {
      try {
        const r = await fetch(
          `/api/v1/packages/autocomplete?q=${encodeURIComponent(term)}&limit=8`,
        );
        const j = await r.json();
        setItems(j.data ?? []);
        setOpen(true);
        setActive(-1);
      } catch {
        /* ignore */
      }
    }, 120);
    return () => clearTimeout(id);
  }, [q]);

  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  function selectSuggestion(s: Suggestion) {
    setError(null);
    setOpen(false);
    setQ("");
    startTransition(async () => {
      try {
        const r = await fetch("/api/v1/watchlist", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            ecosystem: s.ecosystem,
            packageName: s.name,
          }),
        });
        if (r.status === 402) {
          onLimitReached();
          return;
        }
        if (!r.ok) {
          setError(t("addError"));
          return;
        }
        const body = await r.json();
        // The API returns just the watchlist row; we need to fetch
        // the latest-CVE summary to render properly. Easiest: GET
        // the full list back, find our row. (One extra round-trip
        // when adding, but keeps the row shape consistent.)
        const listR = await fetch("/api/v1/watchlist");
        const listJson = await listR.json();
        const fresh = (listJson.data as ClientWatchlistRow[]).find(
          (row) => row.id === body.data.id,
        );
        if (fresh) onAdded(fresh);
      } catch {
        setError(t("addError"));
      }
    });
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (!open || items.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(items.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter" && active >= 0) {
      e.preventDefault();
      selectSuggestion(items[active]);
    } else if (e.key === "Escape") {
      setOpen(false);
    }
  }

  return (
    <div className="space-y-1.5">
      <div ref={wrapRef} className="relative">
        <input
          type="search"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={onKeyDown}
          disabled={disabled || pending}
          autoComplete="off"
          placeholder={t("addPlaceholder")}
          className="w-full rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-red-500 disabled:opacity-50"
        />
        {open && items.length > 0 && (
          <ul className="absolute left-0 right-0 top-full mt-1 z-50 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] shadow-lg max-h-80 overflow-y-auto">
            {items.map((s, i) => (
              <li
                key={`${s.ecosystem}/${s.name}`}
                onMouseDown={(e) => {
                  e.preventDefault();
                  selectSuggestion(s);
                }}
                onMouseEnter={() => setActive(i)}
                className={`flex items-baseline gap-2 px-3 py-1.5 text-sm cursor-pointer ${
                  i === active ? "bg-[hsl(var(--muted))]" : ""
                }`}
              >
                <span className="text-xs font-mono uppercase text-[hsl(var(--muted-foreground))] w-16 shrink-0">
                  {s.ecosystem}
                </span>
                <span className="font-mono flex-1 min-w-0 truncate">{s.name}</span>
                <span className="text-xs text-[hsl(var(--muted-foreground))] shrink-0">
                  {s.cve_count}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
      {error && <p className="text-xs text-red-500">{error}</p>}
    </div>
  );
}
