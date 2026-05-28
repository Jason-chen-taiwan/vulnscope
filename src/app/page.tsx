import Link from "next/link";
import { getDashboardStats, getRecentKev, getRecentVulns, getTopPackages } from "@/lib/queries";
import { KevBadge, SeverityBadge } from "@/components/SeverityBadge";

export const dynamic = "force-dynamic";

const FEATURED_ECOSYSTEMS = ["Debian", "Maven", "npm", "PyPI", "Go", "Alpine"];

export default async function Home() {
  const [stats, kev, recent, ...top] = await Promise.all([
    getDashboardStats(),
    getRecentKev(8),
    getRecentVulns(15),
    ...FEATURED_ECOSYSTEMS.map((eco) => getTopPackages(eco, 8)),
  ]);
  const topByEco: Record<string, Awaited<ReturnType<typeof getTopPackages>>> = {};
  FEATURED_ECOSYSTEMS.forEach((eco, i) => (topByEco[eco] = top[i]));

  return (
    <div className="space-y-8">
      <section>
        <h1 className="text-2xl font-bold tracking-tight mb-2">VulnScope</h1>
        <p className="text-[hsl(var(--muted-foreground))]">
          Package-centric vulnerability lookup. Type a package name or CVE ID above, or click a card.
        </p>
      </section>

      <section className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Total CVEs" value={stats.vuln_total} />
        <StatCard label="Packages tracked" value={stats.package_total} />
        <StatCard label="In CISA KEV" value={stats.kev_total} highlight />
        <StatCard label="Critical (any)" value={stats.critical_total} />
      </section>

      <section className="grid lg:grid-cols-2 gap-6">
        <Card title="🚨 Recent CISA KEV additions" href="/search?kev=true" linkLabel="See all KEV →">
          <ul className="divide-y divide-[hsl(var(--border))]">
            {kev.map((k) => (
              <li key={k.cve_id} className="py-2 flex gap-3 items-baseline">
                <Link href={`/cve/${k.cve_id}`} className="font-mono text-sm no-underline">
                  {k.cve_id}
                </Link>
                <span className="text-sm text-[hsl(var(--muted-foreground))] flex-1 truncate">
                  {k.summary ?? "(no summary)"}
                </span>
                {k.kev_added_at && (
                  <time className="text-xs text-[hsl(var(--muted-foreground))]">
                    {new Date(k.kev_added_at).toLocaleDateString()}
                  </time>
                )}
              </li>
            ))}
          </ul>
        </Card>

        <Card title="📰 Recently published" href="/search" linkLabel="Browse all →">
          <ul className="divide-y divide-[hsl(var(--border))]">
            {recent.map((r) => (
              <li key={r.cve_id} className="py-2 flex gap-3 items-baseline">
                <SeverityBadge severity={r.severity} score={r.base_score} />
                <Link href={`/cve/${r.cve_id}`} className="font-mono text-sm no-underline">
                  {r.cve_id}
                </Link>
                <KevBadge kev={r.kev} />
                <span className="text-sm text-[hsl(var(--muted-foreground))] flex-1 truncate">
                  {r.summary ?? "(no summary)"}
                </span>
                {r.published_at && (
                  <time className="text-xs text-[hsl(var(--muted-foreground))]">
                    {new Date(r.published_at).toLocaleDateString()}
                  </time>
                )}
              </li>
            ))}
          </ul>
        </Card>
      </section>

      <section>
        <div className="flex items-baseline justify-between mb-3">
          <h2 className="text-lg font-semibold">Most-vulnerable packages</h2>
          <Link href="/packages" className="text-xs text-[hsl(var(--muted-foreground))] no-underline">
            Browse all packages →
          </Link>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {FEATURED_ECOSYSTEMS.map((eco) => (
            <div key={eco} className="rounded-lg border border-[hsl(var(--border))] p-3">
              <div className="flex items-baseline justify-between mb-2">
                <h3 className="text-sm font-semibold font-mono">{eco}</h3>
                <Link href={`/packages?ecosystem=${encodeURIComponent(eco)}`} className="text-xs text-[hsl(var(--muted-foreground))] no-underline">
                  all →
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

function StatCard({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <div
      className={`rounded-lg border border-[hsl(var(--border))] p-4 ${highlight ? "bg-red-50 dark:bg-red-950/30" : ""}`}
    >
      <div className="text-xs uppercase tracking-wide text-[hsl(var(--muted-foreground))]">{label}</div>
      <div className="mt-1 text-2xl font-bold font-mono">{value.toLocaleString()}</div>
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
  href: string;
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
