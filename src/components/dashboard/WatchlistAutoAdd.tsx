"use client";

import { useEffect, useRef, useState } from "react";

/**
 * Reads `?intent=watchlist&pkg={ecosystem}/{name}` from the URL on
 * mount and POSTs the package to /api/v1/watchlist, then strips the
 * query string so a refresh doesn't re-trigger the add.
 *
 * This is the landing target for the AddToWatchlistCTA → sign-in →
 * dashboard flow. Lives in OSS (the watchlist API is OSS-aware via
 * pro-bridge) so the URL pattern works even before the Pro CTA loads.
 *
 * useRef gate: React 18 strict mode double-invokes effects in dev,
 * which would fire the POST twice. The API is idempotent on duplicate
 * (eco, name, version) so the second one is harmless, but we still
 * avoid the noise.
 */
export function WatchlistAutoAdd({ onAdded }: { onAdded?: () => void }) {
  const [state, setState] = useState<"idle" | "adding" | "added" | "limit" | "error">("idle");
  const fired = useRef(false);

  useEffect(() => {
    if (fired.current) return;
    const url = new URL(window.location.href);
    const intent = url.searchParams.get("intent");
    const pkg = url.searchParams.get("pkg");
    if (intent !== "watchlist" || !pkg) return;

    const slash = pkg.indexOf("/");
    if (slash <= 0) return;
    const ecosystem = pkg.slice(0, slash);
    const name = pkg.slice(slash + 1);
    fired.current = true;

    setState("adding");
    (async () => {
      try {
        const r = await fetch("/api/v1/watchlist", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ ecosystem, packageName: name, version: null }),
        });
        if (r.status === 402) setState("limit");
        else if (!r.ok) setState("error");
        else {
          setState("added");
          onAdded?.();
        }
      } catch {
        setState("error");
      } finally {
        // Strip intent/pkg so a refresh doesn't re-fire the add.
        url.searchParams.delete("intent");
        url.searchParams.delete("pkg");
        const newUrl = url.pathname + (url.search ? url.search : "") + url.hash;
        window.history.replaceState({}, "", newUrl);
      }
    })();
  }, [onAdded]);

  if (state === "idle") return null;
  const bg =
    state === "added"
      ? "bg-green-600/10 text-green-700 dark:text-green-400 border-green-600/30"
      : state === "limit"
        ? "bg-amber-600/10 text-amber-700 dark:text-amber-400 border-amber-600/30"
        : state === "error"
          ? "bg-red-600/10 text-red-700 dark:text-red-400 border-red-600/30"
          : "bg-[hsl(var(--muted))] text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]";
  const text =
    state === "adding"
      ? "Adding the package you came in for…"
      : state === "added"
        ? "✓ Added to your watchlist."
        : state === "limit"
          ? "You've hit the free 5-package limit. Upgrade to Pro to add more."
          : "Couldn't add that package. Try again from the dashboard search below.";
  return (
    <div className={`rounded-md border px-3 py-2 text-sm ${bg}`} role="status">
      {text}
    </div>
  );
}
