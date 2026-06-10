"use client";

import dynamic from "next/dynamic";

/**
 * Client wrapper that lazy-mounts SignInButtons (which depends on
 * better-auth/react and must not run during SSR). Next.js disallows
 * `ssr: false` in Server Components — so the trick is to do the
 * dynamic-import from another client component.
 */
const SignInButtons = dynamic(
  () => import("./SignInButtons").then((m) => m.SignInButtons),
  {
    ssr: false,
    loading: () => (
      <div className="space-y-3">
        <div className="h-11 rounded-md bg-[hsl(var(--muted))] animate-pulse" />
        <div className="h-11 rounded-md bg-[hsl(var(--muted))] animate-pulse" />
      </div>
    ),
  },
);

export function SignInPanel({ callbackURL }: { callbackURL?: string }) {
  // Don't spread `callbackURL={undefined}` — that would override
  // SignInButtons' default and send users to undefined instead of /pricing.
  return callbackURL ? <SignInButtons callbackURL={callbackURL} /> : <SignInButtons />;
}
