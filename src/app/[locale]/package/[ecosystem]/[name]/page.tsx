import type { Metadata } from "next";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link } from "@/i18n/navigation";
import { notFound } from "next/navigation";
import { getPackageMetadata, getPackageWithCves } from "@/lib/queries";
import { KevBadge, SeverityBadge } from "@/components/SeverityBadge";
import { VersionChecker } from "@/components/VersionChecker";
import { describeRange } from "@/lib/version-match";
import { normalizePypiName } from "@/lib/osv";
import { summarize } from "@/lib/summary";

export const dynamic = "force-dynamic";

const SITE = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";

// Default cap for the CVE list. 100 covers >99% of packages
// completely; the remaining (chromium / linux kernel / openssl)
// show a "Show all" link that re-renders with limit removed.
const DEFAULT_CVE_LIMIT = 100;

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string; ecosystem: string; name: string }>;
}): Promise<Metadata> {
  const { locale, ecosystem: ecoRaw, name: nameRaw } = await params;
  const ecosystem = decodeURIComponent(ecoRaw);
  const rawName = decodeURIComponent(nameRaw);
  const name = ecosystem === "PyPI" ? normalizePypiName(rawName) : rawName;
  const meta = await getPackageMetadata(ecosystem, name);
  if (!meta) return { title: `${ecosystem}/${name}`, robots: { index: false } };
  const title = `${ecosystem}/${name} — ${meta.cve_count} CVEs`;
  const desc = `Every CVE affecting ${ecosystem}/${name}, with version ranges, EPSS scores, and CISA KEV flags.`;
  const pkgPath = `/package/${encodeURIComponent(ecosystem)}/${encodeURIComponent(name)}`;
  return {
    title,
    description: desc,
    alternates: {
      canonical: `${SITE}/${locale}${pkgPath}`,
      languages: {
        en: `${SITE}/en${pkgPath}`,
        "zh-TW": `${SITE}/zh${pkgPath}`,
        "x-default": `${SITE}/en${pkgPath}`,
      },
    },
    openGraph: { title, description: desc, type: "article" },
    twitter: { card: "summary_large_image", title, description: desc },
  };
}

export default async function PackagePage({
  params,
  searchParams,
}: {
  params: Promise<{ locale: string; ecosystem: string; name: string }>;
  searchParams: Promise<{ all?: string }>;
}) {
  const { locale, ecosystem: ecoRaw, name: nameRaw } = await params;
  const sp = await searchParams;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "Package" });
  const ecosystem = decodeURIComponent(ecoRaw);
  const rawName = decodeURIComponent(nameRaw);
  const name = ecosystem === "PyPI" ? normalizePypiName(rawName) : rawName;

  const showAll = sp.all === "1";
  const limit = showAll ? undefined : DEFAULT_CVE_LIMIT;

  // Two parallel fetches: full CVE bundle for render + metadata for
  // the true total count. We only count truncation when
  // bundle.cves.length === DEFAULT_CVE_LIMIT and the actual count
  // is higher.
  const [bundle, meta] = await Promise.all([
    getPackageWithCves(ecosystem, name, limit),
    getPackageMetadata(ecosystem, name),
  ]);
  if (!bundle || !meta) notFound();

  const totalCves = meta.cve_count;
  const truncated = !showAll && totalCves > bundle.cves.length;

  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
  for (const c of bundle.cves) {
    const k = c.severity ?? "NONE";
    counts[k] = (counts[k] ?? 0) + 1;
  }

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-2xl font-bold">
          <span className="text-sm font-mono font-normal text-[hsl(var(--muted-foreground))]">
            pkg:{bundle.package.ecosystem}/
          </span>
          <span className="font-mono">{bundle.package.name}</span>
        </h1>
        <div className="flex flex-wrap gap-3 text-sm">
          <span>{t("totalCve", { n: totalCves })}</span>
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => (
            counts[s] > 0 ? (
              <span key={s} className="flex items-center gap-1">
                <SeverityBadge severity={s} />
                <span>{counts[s]}</span>
              </span>
            ) : null
          ))}
        </div>
      </header>

      <VersionChecker ecosystem={bundle.package.ecosystem} name={bundle.package.name} />

      <section>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[hsl(var(--muted-foreground))] mb-2">
          {t("vulns")}
        </h2>
        {bundle.cves.length === 0 ? (
          <p className="text-sm text-[hsl(var(--muted-foreground))]">{t("noCves")}</p>
        ) : (
          <>
            <ul className="divide-y divide-[hsl(var(--border))] rounded-lg border border-[hsl(var(--border))]">
              {bundle.cves.map((c) => (
                <li key={`${c.cve_id}-${c.ranges_json?.[0]?.events?.[0]?.introduced ?? ""}`} className="px-4 py-3 space-y-1">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <SeverityBadge severity={c.severity} score={c.base_score} />
                    <Link href={`/cve/${c.cve_id}`} className="font-mono font-medium no-underline">{c.cve_id}</Link>
                    <KevBadge kev={c.kev} />
                    <span className="flex-1 min-w-0 text-sm text-[hsl(var(--muted-foreground))] truncate">
                      {summarize(c.summary, c.description) ?? t("noSummary")}
                    </span>
                  </div>
                  {c.ranges_json && c.ranges_json.length > 0 && (
                    <div className="ml-1 font-mono text-xs text-[hsl(var(--muted-foreground))]">
                      {c.ranges_json.map((r) => describeRange(r)).filter(Boolean).join("  |  ")}
                    </div>
                  )}
                </li>
              ))}
            </ul>
            {truncated && (
              <div className="mt-3 text-center">
                <Link
                  href={{
                    pathname: `/package/${bundle.package.ecosystem}/${bundle.package.name}`,
                    query: { all: "1" },
                  }}
                  className="inline-block rounded-md border border-[hsl(var(--border))] px-4 py-2 text-sm no-underline hover:bg-[hsl(var(--muted))]"
                >
                  {t("showAll", { n: totalCves })}
                </Link>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}
