import type { Metadata } from "next";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link } from "@/i18n/navigation";
import { notFound } from "next/navigation";
import { getPackageWithCves } from "@/lib/queries";
import { KevBadge, SeverityBadge } from "@/components/SeverityBadge";
import { VersionChecker } from "@/components/VersionChecker";
import { describeRange } from "@/lib/version-match";
import { normalizePypiName } from "@/lib/osv";

export const dynamic = "force-dynamic";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string; ecosystem: string; name: string }>;
}): Promise<Metadata> {
  const { ecosystem: ecoRaw, name: nameRaw } = await params;
  const ecosystem = decodeURIComponent(ecoRaw);
  const rawName = decodeURIComponent(nameRaw);
  const name = ecosystem === "PyPI" ? normalizePypiName(rawName) : rawName;
  const bundle = await getPackageWithCves(ecosystem, name);
  if (!bundle) return { title: `${ecosystem}/${name}`, robots: { index: false } };
  const title = `${ecosystem}/${name} — ${bundle.cves.length} CVEs`;
  const desc = `Every CVE affecting ${ecosystem}/${name}, with version ranges, EPSS scores, and CISA KEV flags.`;
  return {
    title,
    description: desc,
    openGraph: { title, description: desc, type: "article" },
    twitter: { card: "summary_large_image", title, description: desc },
  };
}

export default async function PackagePage({
  params,
}: {
  params: Promise<{ locale: string; ecosystem: string; name: string }>;
}) {
  const { locale, ecosystem: ecoRaw, name: nameRaw } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "Package" });
  const ecosystem = decodeURIComponent(ecoRaw);
  const rawName = decodeURIComponent(nameRaw);
  const name = ecosystem === "PyPI" ? normalizePypiName(rawName) : rawName;

  const bundle = await getPackageWithCves(ecosystem, name);
  if (!bundle) notFound();

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
          <span>{t("totalCve", { n: bundle.cves.length })}</span>
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
          <ul className="divide-y divide-[hsl(var(--border))] rounded-lg border border-[hsl(var(--border))]">
            {bundle.cves.map((c) => (
              <li key={`${c.cve_id}-${c.ranges_json?.[0]?.events?.[0]?.introduced ?? ""}`} className="px-4 py-3 space-y-1">
                <div className="flex flex-wrap items-baseline gap-2">
                  <SeverityBadge severity={c.severity} score={c.base_score} />
                  <Link href={`/cve/${c.cve_id}`} className="font-mono font-medium no-underline">{c.cve_id}</Link>
                  <KevBadge kev={c.kev} />
                  <span className="flex-1 min-w-0 text-sm text-[hsl(var(--muted-foreground))] truncate">
                    {c.summary ?? t("noSummary")}
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
        )}
      </section>
    </div>
  );
}
