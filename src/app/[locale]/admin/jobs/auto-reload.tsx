"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

/**
 * Polls the current route every 10 seconds (while the tab is visible)
 * so the /admin/jobs page picks up live progress without manual reload.
 *
 * Why not <meta http-equiv="refresh">? Next.js client-side navigation
 * keeps the previous page's <head> elements around across route changes
 * for a few hundred ms while the new page hydrates. The meta refresh
 * would then yank the user back to /admin/jobs when they tried to leave.
 *
 * router.refresh() is a Next-native API that re-runs the server component
 * (so we get fresh DB rows) without a full page reload, and the timer is
 * tied to component mount — navigating away unmounts and cancels it.
 *
 * Visibility-aware: when the tab goes to the background we pause the
 * timer. Browsers already throttle background timers but this is
 * explicit (and stops contributing to rate-limit headroom for users
 * who leave the tab open all day). Resumes the moment the tab is
 * visible again, and does an immediate refresh on resume so the
 * dashboard catches up.
 *
 * The previous 5s cadence × an open background tab × N admins = a
 * surprising amount of router.refresh() traffic that all funnels
 * through the page_view rate-limit bucket. 10s + visibility-aware
 * keeps the steady state polite without making the live progress
 * feel laggy.
 */
const POLL_INTERVAL_MS = 10_000;

export function JobsAutoReload() {
  const router = useRouter();
  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | null = null;

    function start() {
      if (timer) return;
      timer = setInterval(() => router.refresh(), POLL_INTERVAL_MS);
    }
    function stop() {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    }
    function onVisibilityChange() {
      if (document.visibilityState === "visible") {
        // Catch up immediately when the user returns to the tab, then
        // resume the steady-state cadence.
        router.refresh();
        start();
      } else {
        stop();
      }
    }

    if (document.visibilityState === "visible") start();
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
      stop();
    };
  }, [router]);
  return null;
}
