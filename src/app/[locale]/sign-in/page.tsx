import { setRequestLocale } from "next-intl/server";

import { Link } from "@/i18n/navigation";
import { SignInButtons } from "@/components/SignInButtons";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Sign in — VulnScope",
  description:
    "Sign in to VulnScope with GitHub or Google. OAuth-only — we never see or store a password.",
};

export default async function SignInPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  setRequestLocale(locale);

  return (
    <div className="max-w-md mx-auto py-12 space-y-8">
      <header className="space-y-2 text-center">
        <h1 className="text-3xl font-bold tracking-tight">Sign in</h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          OAuth only — we never see or store your password.
        </p>
      </header>

      <SignInButtons />

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
