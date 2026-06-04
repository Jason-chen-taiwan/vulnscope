"use client";

import { useEffect, useState } from "react";
import dynamic from "next/dynamic";

/**
 * Header auth widget. Lazy-mounted on the client only, because
 * better-auth/react initializes React internals at module-load time
 * which crashes SSR (Cannot read properties of null (reading 'useRef')).
 *
 * We render a 16px placeholder during SSR + first paint so the header
 * doesn't shift when the real widget hydrates.
 */
const Inner = dynamic(() => import("./AuthHeaderWidgetInner").then((m) => m.AuthHeaderWidgetInner), {
  ssr: false,
  loading: () => (
    <span
      aria-label="Loading session"
      className="inline-block h-4 w-4 rounded-full bg-[hsl(var(--muted))] animate-pulse"
    />
  ),
});

export function AuthHeaderWidget() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) {
    return (
      <span
        aria-label="Loading session"
        className="inline-block h-4 w-4 rounded-full bg-[hsl(var(--muted))] animate-pulse"
      />
    );
  }
  return <Inner />;
}
