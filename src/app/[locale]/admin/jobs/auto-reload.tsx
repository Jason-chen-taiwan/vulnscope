"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

/**
 * Polls the current route every 5 seconds while mounted so the
 * /admin/jobs page picks up live progress without manual reload.
 *
 * Why not <meta http-equiv="refresh">? Next.js client-side navigation
 * keeps the previous page's <head> elements around across route changes
 * for a few hundred ms while the new page hydrates. The meta refresh
 * would then yank the user back to /admin/jobs when they tried to leave.
 *
 * router.refresh() is a Next-native API that re-runs the server component
 * (so we get fresh DB rows) without a full page reload, and the timer is
 * tied to component mount — navigating away unmounts and cancels it.
 */
export function JobsAutoReload() {
  const router = useRouter();
  useEffect(() => {
    const id = setInterval(() => router.refresh(), 5000);
    return () => clearInterval(id);
  }, [router]);
  return null;
}
