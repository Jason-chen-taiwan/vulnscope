import { setRequestLocale } from "next-intl/server";

import { Link } from "@/i18n/navigation";
import { SignInPanel } from "@/components/SignInPanel";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Sign in — VulnScope",
  description:
    "Sign in to VulnScope with GitHub or Google. OAuth-only — we never see or store a password.",
};

export default async function SignInPage({
  params,
  searchParams,
}: {
  params: Promise<{ locale: string }>;
  searchParams: Promise<{ callbackURL?: string }>;
}) {
  const { locale } = await params;
  const { callbackURL } = await searchParams;
  setRequestLocale(locale);

  // Defence against open-redirect: only honor same-origin paths.
  // OAuth providers will reject absolute foreign URLs anyway, but
  // catching it here keeps the post-sign-in landing predictable.
  const safeCallback =
    callbackURL && callbackURL.startsWith("/") && !callbackURL.startsWith("//")
      ? callbackURL
      : undefined;

  return (
    <div className="max-w-md mx-auto py-12 space-y-8">
      <header className="space-y-2 text-center">
        <h1 className="text-3xl font-bold tracking-tight">Sign in</h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          OAuth only — we never see or store your password.
        </p>
      </header>

      <SignInPanel callbackURL={safeCallback} />

      <p className="text-xs text-center text-[hsl(var(--muted-foreground))]">
        New here? Signing in with GitHub or Google creates your account
        automatically.{" "}
        <Link href="/pricing" className="underline">
          See plans
        </Link>
        .
      </p>
    </div>
  );
}
