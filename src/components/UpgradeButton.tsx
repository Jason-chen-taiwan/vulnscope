"use client";

import { useState, useTransition } from "react";

/**
 * Pricing-page CTA for the Pro tier.
 *
 * Three states:
 *   - Already on Pro → link to /dashboard
 *   - Not signed in → 401 from /api/v1/billing/checkout → redirect
 *     to GitHub OAuth and bounce back to /pricing
 *   - Signed in, not paying → POST opens Polar checkout in same tab
 *
 * We deliberately do not auto-detect "is signed in" on the server
 * (would require a Pro-bridge call on every pricing render); instead,
 * we let the API tell us with a 401, and react accordingly. Keeps the
 * pricing page cacheable for anonymous traffic later.
 */
export function UpgradeButton({ alreadyPro }: { alreadyPro: boolean }) {
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  if (alreadyPro) {
    return (
      <a
        href="/dashboard"
        className="block w-full rounded-md bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] text-center py-2 text-sm font-medium hover:opacity-90"
      >
        You&apos;re on Pro — open dashboard →
      </a>
    );
  }

  return (
    <div className="space-y-2">
      <button
        type="button"
        disabled={pending}
        onClick={() => {
          setError(null);
          startTransition(async () => {
            try {
              const res = await fetch("/api/v1/billing/checkout", {
                method: "POST",
                headers: { "content-type": "application/json" },
              });
              if (res.status === 401) {
                // Not signed in — bounce to /sign-in with a return URL
                // so they come back here and can complete checkout.
                window.location.href = "/sign-in?next=/pricing";
                return;
              }
              if (!res.ok) {
                const body = await res.json().catch(() => ({}));
                throw new Error(body.error ?? `HTTP ${res.status}`);
              }
              const { url } = await res.json();
              window.location.href = url;
            } catch (e) {
              setError(e instanceof Error ? e.message : "Something went wrong");
            }
          });
        }}
        className="block w-full rounded-md bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] text-center py-2 text-sm font-medium hover:opacity-90 disabled:opacity-50"
      >
        {pending ? "Opening checkout…" : "Get Pro for $9/mo"}
      </button>
      {error && (
        <p className="text-xs text-red-500 dark:text-red-400">{error}</p>
      )}
      <p className="text-xs text-center text-[hsl(var(--muted-foreground))]">
        Sign in with GitHub or Google to continue.
      </p>
    </div>
  );
}
