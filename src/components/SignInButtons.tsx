"use client";

import { useState } from "react";

import { signIn } from "@/lib/auth-client";

/**
 * Two-button OAuth sign-in panel. Used on /sign-in and inline
 * elsewhere (e.g. pricing page redirect target).
 *
 * Both providers route to the same Better Auth endpoint; we just pass
 * a different `provider` string. The callback URL defaults to the
 * current host's `/dashboard` once we ship it; for now we send the
 * user back to /pricing so they can complete checkout.
 */
export function SignInButtons({ callbackURL = "/pricing" }: { callbackURL?: string }) {
  const [pendingProvider, setPendingProvider] = useState<
    "github" | "google" | null
  >(null);
  const [error, setError] = useState<string | null>(null);

  async function go(provider: "github" | "google") {
    setError(null);
    setPendingProvider(provider);
    try {
      await signIn.social({ provider, callbackURL });
      // signIn.social() navigates the browser; we won't reach here
      // unless something went very wrong (network error, blocked
      // popup, etc).
    } catch (e) {
      setError(e instanceof Error ? e.message : "Sign-in failed");
      setPendingProvider(null);
    }
  }

  return (
    <div className="space-y-3">
      <button
        type="button"
        disabled={!!pendingProvider}
        onClick={() => go("github")}
        className="w-full flex items-center justify-center gap-2 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] py-2.5 text-sm font-medium hover:bg-[hsl(var(--accent))] disabled:opacity-50"
      >
        <GitHubIcon />
        {pendingProvider === "github" ? "Redirecting…" : "Continue with GitHub"}
      </button>

      <button
        type="button"
        disabled={!!pendingProvider}
        onClick={() => go("google")}
        className="w-full flex items-center justify-center gap-2 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] py-2.5 text-sm font-medium hover:bg-[hsl(var(--accent))] disabled:opacity-50"
      >
        <GoogleIcon />
        {pendingProvider === "google" ? "Redirecting…" : "Continue with Google"}
      </button>

      {error && (
        <p className="text-xs text-red-500 dark:text-red-400 text-center">
          {error}
        </p>
      )}
    </div>
  );
}

function GitHubIcon() {
  return (
    <svg
      className="h-5 w-5"
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.92.58.11.79-.25.79-.56v-1.94c-3.2.7-3.87-1.54-3.87-1.54-.52-1.33-1.28-1.69-1.28-1.69-1.05-.72.08-.71.08-.71 1.16.08 1.78 1.2 1.78 1.2 1.03 1.77 2.71 1.26 3.37.96.1-.75.4-1.27.73-1.56-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.47.11-3.06 0 0 .97-.31 3.18 1.18a11.07 11.07 0 0 1 5.79 0c2.21-1.49 3.18-1.18 3.18-1.18.63 1.59.23 2.77.11 3.06.74.81 1.19 1.84 1.19 3.1 0 4.42-2.69 5.39-5.25 5.68.41.36.78 1.07.78 2.16v3.2c0 .31.21.68.8.56C20.21 21.39 23.5 17.08 23.5 12 23.5 5.65 18.35.5 12 .5z" />
    </svg>
  );
}

function GoogleIcon() {
  return (
    <svg
      className="h-5 w-5"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <path
        fill="#4285F4"
        d="M22.5 12.27c0-.79-.07-1.55-.2-2.27H12v4.3h5.9c-.25 1.36-1.02 2.51-2.18 3.28v2.72h3.52c2.06-1.9 3.26-4.7 3.26-8.03z"
      />
      <path
        fill="#34A853"
        d="M12 23c2.94 0 5.4-.97 7.2-2.64l-3.52-2.72c-.97.65-2.22 1.04-3.68 1.04-2.83 0-5.23-1.91-6.09-4.48H2.27v2.81C4.06 20.5 7.74 23 12 23z"
      />
      <path
        fill="#FBBC05"
        d="M5.91 14.2A6.99 6.99 0 0 1 5.55 12c0-.77.13-1.51.36-2.2V6.99H2.27A11 11 0 0 0 1 12c0 1.78.43 3.46 1.27 4.99l3.64-2.79z"
      />
      <path
        fill="#EA4335"
        d="M12 5.32c1.6 0 3.03.55 4.16 1.62l3.12-3.12C17.39 2.05 14.93 1 12 1 7.74 1 4.06 3.5 2.27 6.99l3.64 2.81C6.77 7.23 9.17 5.32 12 5.32z"
      />
    </svg>
  );
}
