"use client";

import { useState } from "react";

import { useSession, signOut } from "@/lib/auth-client";

/**
 * Header widget shown next to the language switcher.
 *
 * Three states:
 *   - loading: small pulsing dot so the layout doesn't jump
 *   - signed out: "Sign in" link to /sign-in
 *   - signed in: tiny avatar + sign-out button on hover/focus
 *
 * Stays small (no full dropdown menu) — the only Pro action is
 * "sign out" today; once we add /dashboard we can expand this.
 */
export function AuthHeaderWidget() {
  const { data: session, isPending } = useSession();
  const [signingOut, setSigningOut] = useState(false);

  if (isPending) {
    return (
      <span
        aria-label="Loading session"
        className="inline-block h-4 w-4 rounded-full bg-[hsl(var(--muted))] animate-pulse"
      />
    );
  }

  if (!session?.user) {
    return (
      <a
        href="/sign-in"
        className="text-sm font-medium text-[hsl(var(--foreground))] hover:underline"
      >
        Sign in
      </a>
    );
  }

  const user = session.user;
  const initial = (user.name || user.email || "?")[0].toUpperCase();

  return (
    <div className="flex items-center gap-2">
      {user.image ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={user.image}
          alt={user.name || user.email}
          className="h-6 w-6 rounded-full border border-[hsl(var(--border))]"
        />
      ) : (
        <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-[hsl(var(--muted))] text-xs font-semibold">
          {initial}
        </span>
      )}
      <span
        className="hidden sm:inline text-sm text-[hsl(var(--muted-foreground))] max-w-[10ch] truncate"
        title={user.email}
      >
        {user.name || user.email}
      </span>
      <button
        type="button"
        disabled={signingOut}
        onClick={async () => {
          setSigningOut(true);
          await signOut();
          // Reload to clear any server-rendered "isPro" state in
          // /pricing and other pages.
          window.location.assign("/");
        }}
        className="text-xs text-[hsl(var(--muted-foreground))] underline hover:text-[hsl(var(--foreground))] disabled:opacity-50"
      >
        {signingOut ? "…" : "Sign out"}
      </button>
    </div>
  );
}
