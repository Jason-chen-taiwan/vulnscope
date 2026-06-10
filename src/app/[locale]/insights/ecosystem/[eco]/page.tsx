import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link } from "@/i18n/navigation";
import { getEcosystemDeepDive, INSIGHT_ECOSYSTEMS, type InsightEcosystem } from "@/lib/insights";
import { RssSubscribeButton } from "@/components/RssSubscribeButton";

export const dynamic = "force-dynamic";
export const revalidate = 3600;

export async function generateStaticParams() {
  return INSIGHT_ECOSYSTEMS.map((eco) => ({ eco }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string; eco: string }>;
}): Promise<Metadata> {
  const { locale, eco } = await params;
  const t = await getTranslations({ locale, namespace: "Insights.ecosystemDeepDive" });
  const rssHref = `/feed/ecosystem/${encodeURIComponent(eco)}`;
  return {
    title: t("title", { eco }),
    description: t("blurb", { eco }),
    alternates: {
      types: { "application/rss+xml": [{ url: rssHref, title: t("title", { eco }) }] },
    },
  };
}

export default async function Page({
  params,
}: {
  params: Promise<{ locale: string; eco: string }>;
}) {
  const { locale, eco } = await params;
  setRequestLocale(locale);
  if (!(INSIGHT_ECOSYSTEMS as readonly string[]).includes(eco)) notFound();
  const t = await getTranslations({ locale, namespace: "Insights" });
  const dateLocale = locale === "zh" ? "zh-TW" : "en";
  const rows = await getEcosystemDeepDive(eco as InsightEcosystem, 300);
  const rssHref = `/feed/ecosystem/${encodeURIComponent(eco)}`;

  return (
    <article className="space-y-4">
      <header>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <h1 className="text-2xl font-bold tracking-tight">{t("ecosystemDeepDive.title", { eco })}</h1>
          <RssSubscribeButton href={rssHref} label={t("subscribeRss")} />
        </div>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">{t("ecosystemDeepDive.blurb", { eco })}</p>
        <p className="text-xs text-[hsl(var(--muted-foreground))] mt-1">
          {t("lastUpdated", { date: new Date().toLocaleString(dateLocale) })}
        </p>
      </header>
      <table className="w-full text-sm">
        <thead className="text-xs uppercase text-[hsl(var(--muted-foreground))]">
          <tr>
            <th className="text-right py-1 pr-3">{t("topPackages.col.rank")}</th>
            <th className="text-left py-1 pr-3">{t("topPackages.col.package")}</th>
            <th className="text-right py-1 pr-3">{t("topPackages.col.cves")}</th>
            <th className="text-right py-1 pr-3">{t("topPackages.col.kev")}</th>
            <th className="text-right py-1">{t("topPackages.col.epssMax")}</th>
          </tr>
        </thead>
        <tbody className="font-mono text-xs">
          {rows.map((r, i) => (
            <tr key={r.name} className="border-t border-[hsl(var(--border))]">
              <td className="py-1 pr-3 text-right text-[hsl(var(--muted-foreground))]">{i + 1}</td>
              <td className="py-1 pr-3">
                <Link href={`/package/${encodeURIComponent(eco)}/${encodeURIComponent(r.name)}`} className="no-underline">
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
