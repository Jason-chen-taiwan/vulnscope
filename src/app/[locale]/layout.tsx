import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { NextIntlClientProvider, hasLocale } from "next-intl";
import { getMessages, getTranslations, setRequestLocale } from "next-intl/server";
import { HeaderSearch } from "@/components/HeaderSearch";
import { LangSwitcher } from "@/components/LangSwitcher";
import { Link } from "@/i18n/navigation";
import { routing } from "@/i18n/routing";
import "./globals.css";

export function generateStaticParams() {
  return routing.locales.map((locale) => ({ locale }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const t = await getTranslations({ locale, namespace: "Meta" });
  return {
    title: { default: t("title"), template: "%s · VulnScope" },
    description: t("description"),
    applicationName: "VulnScope",
    openGraph: {
      type: "website",
      siteName: "VulnScope",
      title: t("title"),
      description: t("description"),
    },
    twitter: {
      card: "summary_large_image",
      title: "VulnScope",
      description: t("description"),
    },
  };
}

async function Footer({ locale }: { locale: string }) {
  const tf = await getTranslations({ locale, namespace: "Footer" });
  // Split the template string and interleave React nodes ourselves so we
  // never hand functions to the NextIntlClientProvider boundary.
  const template = tf("dataFrom", { osv: "__OSV__", kev: "__KEV__", epss: "__EPSS__" });
  const parts: React.ReactNode[] = [];
  const re = /(__OSV__|__KEV__|__EPSS__)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(template)) !== null) {
    if (m.index > last) parts.push(template.slice(last, m.index));
    parts.push(
      m[1] === "__OSV__" ? (
        <a key="osv" href="https://osv.dev" className="underline" target="_blank" rel="noreferrer">OSV.dev</a>
      ) : m[1] === "__KEV__" ? (
        <a key="kev" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" className="underline" target="_blank" rel="noreferrer">CISA KEV</a>
      ) : (
        <a key="epss" href="https://www.first.org/epss/" className="underline" target="_blank" rel="noreferrer">FIRST EPSS</a>
      ),
    );
    last = m.index + m[1].length;
  }
  if (last < template.length) parts.push(template.slice(last));
  return (
    <>
      <span>{parts}</span>
      <span className="ml-auto flex gap-3">
        <Link href="/admin/jobs" className="underline">{tf("syncStatus")}</Link>
        <a href="https://github.com/Jason-chen-taiwan/vulnscope" className="underline" target="_blank" rel="noreferrer">{tf("github")}</a>
      </span>
    </>
  );
}

export default async function LocaleLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  if (!hasLocale(routing.locales, locale)) notFound();
  setRequestLocale(locale);
  const messages = await getMessages();
  const t = await getTranslations({ locale, namespace: "Nav" });

  return (
    <html lang={locale}>
      <body>
        <NextIntlClientProvider locale={locale} messages={messages}>
          <header className="border-b border-[hsl(var(--border))]">
            <nav className="mx-auto max-w-6xl px-4 py-3 flex items-center gap-6">
              <Link href="/" className="font-semibold text-lg no-underline" title={t("home")}>
                Vuln<span className="text-red-600">·</span>Scope
              </Link>
              <HeaderSearch />
              <Link href="/" className="text-sm text-[hsl(var(--muted-foreground))] no-underline">{t("home")}</Link>
              <Link href="/packages" className="text-sm text-[hsl(var(--muted-foreground))] no-underline">{t("packages")}</Link>
              <Link href={{ pathname: "/search", query: { kev: "true" } }} className="text-sm text-[hsl(var(--muted-foreground))] no-underline">{t("kev")}</Link>
              <Link href={{ pathname: "/search", query: { severity: "CRITICAL" } }} className="text-sm text-[hsl(var(--muted-foreground))] no-underline">{t("critical")}</Link>
              <Link href="/admin/jobs" className="text-sm text-[hsl(var(--muted-foreground))] no-underline" title={t("jobsTitle")}>{t("jobs")}</Link>
              <LangSwitcher />
            </nav>
          </header>
          <main className="mx-auto max-w-6xl px-4 py-6">{children}</main>
          <footer className="mx-auto max-w-6xl px-4 py-10 text-xs text-[hsl(var(--muted-foreground))] flex flex-wrap gap-x-4 gap-y-1">
            <Footer locale={locale} />
          </footer>
        </NextIntlClientProvider>
      </body>
    </html>
  );
}
