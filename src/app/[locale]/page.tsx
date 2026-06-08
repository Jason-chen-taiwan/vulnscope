import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link } from "@/i18n/navigation";
import { getDashboardStats, getRecentKev, getRecentVulns, getTopPackages } from "@/lib/queries";
import { getFreshness, isIngestRunning } from "@/lib/sync-jobs";
import { summarize } from "@/lib/summary";
import { KevBadge, SeverityBadge } from "@/components/SeverityBadge";
import { AutoRefresh } from "@/components/AutoRefresh";

export const dynamic = "force-dynamic";

const FEATURED_ECOSYSTEMS = ["Debian", "Maven", "npm", "PyPI", "Go", "Alpine"];

export default async function Home({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "Home" });
  // The first 5 calls are heterogeneous (one each) → safe to parallelise.
  // The 6 getTopPackages calls all hit the same shape of aggregate on
  // affected/vulnerabilities and were observed (2026-06-08) stacking up
  // in pg_stat_activity to 30+ seconds during ingest because they all
  // compete for the same buffer-cache pages. Running them sequentially
  // costs ~6 × 200ms = 1.2s in the warm-cache case but stays responsive
  // (no event-loop pileup, no pg pool starvation) during ingest. Each
  // call hits an in-memory cache (60s) anyway so once one user has
  // warmed up the page, subsequent renders are 0ms regardless of order.
  const [stats, kev, recent, freshness, ingestRunning] = await Promise.all([
    getDashboardStats(),
    getRecentKev(8),
    getRecentVulns(15),
    getFreshness(),
    isIngestRunning(),
  ]);
  const topByEco: Record<string, Awaited<ReturnType<typeof getTopPackages>>> = {};
  for (const eco of FEATURED_ECOSYSTEMS) {
    topByEco[eco] = await getTopPackages(eco, 8);
  }
  const oldest = freshness
    .filter((f) => f.finished_at)
    .map((f) => new Date(f.finished_at!).getTime())
    .reduce((min, ti) => Math.min(min, ti), Date.now());
  const oldestAgeH = (Date.now() - oldest) / 3600_000;

  const dateLocale = locale === "zh" ? "zh-TW" : "en";

  return (
    <div className="space-y-8">
      {/* Live-update the homepage while ingest is in flight, so the
          "most-vulnerable packages" cards fill in as new ecosystems
          finish without manual reload. 15-second cadence is enough —
          ingest writes happen in bursts, not in milliseconds. */}
      <AutoRefresh enabled={ingestRunning} intervalMs={15_000} />
      <section>
        <h1 className="text-2xl font-bold tracking-tight mb-2">VulnScope</h1>
        <p className="text-[hsl(var(--muted-foreground))]">{t("tagline")}</p>
        <FreshnessLine oldestAgeH={oldestAgeH} freshness={freshness} ingestRunning={ingestRunning} t={t} />
      </section>

      <section className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label={t("stats.totalCves")} value={stats.vuln_total} locale={dateLocale} />
        <StatCard label={t("stats.packagesTracked")} value={stats.package_total} locale={dateLocale} />
        <StatCard label={t("stats.inKev")} value={stats.kev_total} locale={dateLocale} highlight />
        <StatCard label={t("stats.critical")} value={stats.critical_total} locale={dateLocale} />
      </section>

      <section className="grid lg:grid-cols-2 gap-6">
        <Card title={t("recentKev")} href={{ pathname: "/search", query: { kev: "true" } }} linkLabel={t("seeAllKev")}>
          <ul className="divide-y divide-[hsl(var(--border))]">
            {kev.map((k) => (
              <li key={k.cve_id} className="py-2 flex gap-3 items-baseline">
                <Link href={`/cve/${k.cve_id}`} className="font-mono text-sm no-underline">{k.cve_id}</Link>
                <span className="text-sm text-[hsl(var(--muted-foreground))] flex-1 truncate">
                  {summarize(k.summary, k.description) ?? t("noSummary")}
                </span>
                {k.kev_added_at && (
                  <time className="text-xs text-[hsl(var(--muted-foreground))]">
                    {new Date(k.kev_added_at).toLocaleDateString(dateLocale)}
                  </time>
                )}
              </li>
            ))}
          </ul>
        </Card>

        <Card title={t("recentPublished")} href="/search" linkLabel={t("browseAll")}>
          <ul className="divide-y divide-[hsl(var(--border))]">
            {recent.map((r) => (
              <li key={r.cve_id} className="py-2 flex gap-3 items-baseline">
                <SeverityBadge severity={r.severity} score={r.base_score} />
                <Link href={`/cve/${r.cve_id}`} className="font-mono text-sm no-underline">{r.cve_id}</Link>
                <KevBadge kev={r.kev} />
                <span className="text-sm text-[hsl(var(--muted-foreground))] flex-1 truncate">
                  {summarize(r.summary, r.description) ?? t("noSummary")}
                </span>
                {r.published_at && (
                  <time className="text-xs text-[hsl(var(--muted-foreground))]">
                    {new Date(r.published_at).toLocaleDateString(dateLocale)}
                  </time>
                )}
              </li>
            ))}
          </ul>
        </Card>
      </section>

      <section>
        <div className="flex items-baseline justify-between mb-3">
          <h2 className="text-lg font-semibold">{t("mostVulnerable")}</h2>
          <Link href="/packages" className="text-xs text-[hsl(var(--muted-foreground))] no-underline">
            {t("browseAllPackages")}
          </Link>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {FEATURED_ECOSYSTEMS.map((eco) => (
            <div key={eco} className="rounded-lg border border-[hsl(var(--border))] p-3">
              <div className="flex items-baseline justify-between mb-2">
                <h3 className="text-sm font-semibold font-mono">{eco}</h3>
                <Link href={{ pathname: "/packages", query: { ecosystem: eco } }} className="text-xs text-[hsl(var(--muted-foreground))] no-underline">
                  {t("ecoAll")}
                </Link>
              </div>
              <ul className="space-y-0.5 text-sm">
                {topByEco[eco].map((p) => (
                  <li key={p.name} className="flex items-baseline gap-2">
                    <Link
                      href={`/package/${encodeURIComponent(p.ecosystem)}/${encodeURIComponent(p.name)}`}
                      className="font-mono no-underline truncate flex-1 min-w-0"
                    >
                      {p.name}
                    </Link>
                    <span className="text-xs text-[hsl(var(--muted-foreground))] shrink-0">{p.cve_count}</span>
                    {p.kev_count > 0 && (
                      <span className="text-[10px] font-bold text-[hsl(15,82%,30%)] shrink-0">{p.kev_count}🚨</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function FreshnessLine({
  oldestAgeH,
  freshness,
  ingestRunning,
  t,
}: {
  oldestAgeH: number;
  freshness: { source: string; finished_at: Date | null; status: string }[];
  ingestRunning: boolean;
  t: Awaited<ReturnType<typeof getTranslations<"Home">>>;
}) {
  if (freshness.length === 0) {
    const txt = t("freshnessNone", { link: "__LINK__" });
    const [before, after] = txt.split("__LINK__");
    return (
      <p className="mt-2 text-xs text-yellow-600">
        {before}
        <Link href="/admin/jobs" className="underline">/admin/jobs</Link>
        {after}
      </p>
    );
  }
  const ageLabel = oldestAgeH < 1
    ? t("freshnessAgeMin", { n: Math.round(oldestAgeH * 60) })
    : oldestAgeH < 48
    ? t("freshnessAgeHour", { n: Number(oldestAgeH.toFixed(1)) })
    : t("freshnessAgeDay", { n: Math.floor(oldestAgeH / 24) });
  const color = oldestAgeH < 26 ? "text-green-600" : oldestAgeH < 72 ? "text-yellow-600" : "text-red-600";
  const failed = freshness.filter((f) => f.status === "failed").length;
  return (
    <p className="mt-2 text-xs text-[hsl(var(--muted-foreground))]">
      <span className={color}>● </span>
      {t("freshnessLine", { age: ageLabel })}
      {ingestRunning && (
        <span className="ml-2 text-yellow-600 animate-pulse">· {t("ingestInFlight")}</span>
      )}
      {failed > 0 && <span className="text-red-600 ml-2">· {t("freshnessFailing", { n: failed })}</span>}
      <Link href="/admin/jobs" className="ml-3 underline">{t("viewSyncJobs")}</Link>
    </p>
  );
}

function StatCard({ label, value, highlight, locale }: { label: string; value: number; highlight?: boolean; locale: string }) {
  return (
    <div
      className={`rounded-lg border border-[hsl(var(--border))] p-4 ${highlight ? "bg-red-50 dark:bg-red-950/30" : ""}`}
    >
      <div className="text-xs uppercase tracking-wide text-[hsl(var(--muted-foreground))]">{label}</div>
      <div className="mt-1 text-2xl font-bold font-mono">{value.toLocaleString(locale)}</div>
    </div>
  );
}

function Card({
  title,
  href,
  linkLabel,
  children,
}: {
  title: string;
  href: React.ComponentProps<typeof Link>["href"];
  linkLabel: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-[hsl(var(--border))] p-4">
      <div className="flex items-baseline justify-between mb-2">
        <h3 className="font-semibold">{title}</h3>
        <Link href={href} className="text-xs text-[hsl(var(--muted-foreground))] no-underline">
          {linkLabel}
        </Link>
      </div>
      {children}
    </div>
  );
}
