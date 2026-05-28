import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link } from "@/i18n/navigation";
import { INSIGHT_ECOSYSTEMS } from "@/lib/insights";

export const dynamic = "force-dynamic";

export default async function InsightsIndex({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "Insights" });

  const cards = [
    { href: "/insights/most-vulnerable-packages", title: t("topPackages.title"), blurb: t("topPackages.blurb") },
    { href: "/insights/cisa-kev-catalog", title: t("kevCatalog.title"), blurb: t("kevCatalog.blurb") },
    { href: "/insights/epss-rising", title: t("epssRising.title"), blurb: t("epssRising.blurb") },
    ...INSIGHT_ECOSYSTEMS.map((eco) => ({
      href: `/insights/ecosystem/${eco}`,
      title: t("ecosystemDeepDive.title", { eco }),
      blurb: t("ecosystemDeepDive.blurb", { eco }),
    })),
  ];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">{t("subtitle")}</p>
      </header>
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {cards.map((c) => (
          <Link
            key={c.href}
            href={c.href as Parameters<typeof Link>[0]["href"]}
            className="block rounded-lg border border-[hsl(var(--border))] p-4 hover:bg-[hsl(var(--muted))] no-underline"
          >
            <h2 className="font-semibold mb-1">{c.title}</h2>
            <p className="text-xs text-[hsl(var(--muted-foreground))]">{c.blurb}</p>
          </Link>
        ))}
      </div>
    </div>
  );
}
