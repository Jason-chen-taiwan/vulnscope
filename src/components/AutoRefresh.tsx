"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

/**
 * Re-run the current route's server component every `interval` ms while
 * mounted. Pass `enabled={false}` to opt out (e.g. when nothing is
 * actively changing). Unmounting clears the timer, so navigating away
 * never causes a hijack like <meta http-equiv='refresh'> would.
 */
export function AutoRefresh({
  enabled = true,
  intervalMs = 10_000,
}: {
  enabled?: boolean;
  intervalMs?: number;
}) {
  const router = useRouter();
  useEffect(() => {
    if (!enabled) return;
    const id = setInterval(() => router.refresh(), intervalMs);
    return () => clearInterval(id);
  }, [router, enabled, intervalMs]);
  return null;
}
