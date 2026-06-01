import type { Metadata } from "next";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link } from "@/i18n/navigation";
import { getKevCatalog } from "@/lib/insights";
import { SeverityBadge } from "@/components/SeverityBadge";
import { EpssBadge } from "@/components/EpssBadge";
import { summarize } from "@/lib/summary";

export const dynamic = "force-dynamic";
export const revalidate = 3600;

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  const t = await getTranslations({ locale, namespace: "Insights.kevCatalog" });
  return { title: t("title"), description: t("blurb") };
}

export default async function Page({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "Insights" });
  const dateLocale = locale === "zh" ? "zh-TW" : "en";
  const rows = (await getKevCatalog(500)) as Array<{
    cve_id: string;
    summary: string | null;
    description: string | null;
    kev_added_at: Date | null;
    epss_score: number | null;
    severity: string | null;
    base_score: number | null;
  }>;

  return (
    <article className="space-y-4">
      <header>
        <h1 className="text-2xl font-bold tracking-tight">{t("kevCatalog.title")}</h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">{t("kevCatalog.blurb")}</p>
        <p className="text-xs text-[hsl(var(--muted-foreground))] mt-1">
          {t("lastUpdated", { date: new Date().toLocaleString(dateLocale) })}
        </p>
      </header>
      <ul className="divide-y divide-[hsl(var(--border))] rounded-lg border border-[hsl(var(--border))]">
        {rows.map((r) => (
          <li key={r.cve_id} className="px-4 py-2 flex flex-wrap items-baseline gap-2">
            <SeverityBadge severity={r.severity} score={r.base_score} />
            <Link href={`/cve/${r.cve_id}`} className="font-mono font-medium no-underline">{r.cve_id}</Link>
            <EpssBadge score={r.epss_score} />
            <span className="flex-1 min-w-0 text-sm text-[hsl(var(--muted-foreground))] truncate">
              {summarize(r.summary, r.description) ?? ""}
            </span>
            {r.kev_added_at && (
              <time className="text-xs font-mono text-[hsl(var(--muted-foreground))] shrink-0">
                {new Date(r.kev_added_at).toLocaleDateString(dateLocale)}
              </time>
            )}
          </li>
        ))}
      </ul>
    </article>
  );
}
