import type { Metadata } from "next";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link } from "@/i18n/navigation";
import { getTopPackagesAllEcos } from "@/lib/insights";

export const dynamic = "force-dynamic";
export const revalidate = 3600;

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  const t = await getTranslations({ locale, namespace: "Insights.topPackages" });
  return {
    title: t("title"),
    description: t("blurb"),
    openGraph: { title: t("title"), description: t("blurb") },
  };
}

export default async function Page({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "Insights" });
  const dateLocale = locale === "zh" ? "zh-TW" : "en";
  const rows = await getTopPackagesAllEcos(100);

  return (
    <article className="space-y-4">
      <header>
        <h1 className="text-2xl font-bold tracking-tight">{t("topPackages.title")}</h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">{t("topPackages.blurb")}</p>
        <p className="text-xs text-[hsl(var(--muted-foreground))] mt-1">
          {t("lastUpdated", { date: new Date().toLocaleString(dateLocale) })}
        </p>
      </header>
      <table className="w-full text-sm">
        <thead className="text-xs uppercase text-[hsl(var(--muted-foreground))]">
          <tr>
            <th className="text-right py-1 pr-3">{t("topPackages.col.rank")}</th>
            <th className="text-left py-1 pr-3">{t("topPackages.col.ecosystem")}</th>
            <th className="text-left py-1 pr-3">{t("topPackages.col.package")}</th>
            <th className="text-right py-1 pr-3">{t("topPackages.col.cves")}</th>
            <th className="text-right py-1 pr-3">{t("topPackages.col.kev")}</th>
            <th className="text-right py-1">{t("topPackages.col.epssMax")}</th>
          </tr>
        </thead>
        <tbody className="font-mono text-xs">
          {rows.map((r, i) => (
            <tr key={`${r.ecosystem}/${r.name}`} className="border-t border-[hsl(var(--border))]">
              <td className="py-1 pr-3 text-right text-[hsl(var(--muted-foreground))]">{i + 1}</td>
              <td className="py-1 pr-3 uppercase text-xs text-[hsl(var(--muted-foreground))]">{r.ecosystem}</td>
              <td className="py-1 pr-3">
                <Link
                  href={`/package/${encodeURIComponent(r.ecosystem)}/${encodeURIComponent(r.name)}`}
                  className="no-underline"
                >
                  {r.name}
                </Link>
              </td>
              <td className="py-1 pr-3 text-right">{r.cve_count}</td>
              <td className="py-1 pr-3 text-right font-bold text-[hsl(15,82%,30%)]">
                {r.kev_count > 0 ? r.kev_count : "—"}
              </td>
              <td className="py-1 text-right">
                {r.max_epss !== null ? (r.max_epss * 100).toFixed(1) + "%" : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </article>
  );
}
