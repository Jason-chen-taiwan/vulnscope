import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link, redirect } from "@/i18n/navigation";
import { searchVulns } from "@/lib/queries";
import { KevBadge, SeverityBadge } from "@/components/SeverityBadge";
import { EpssBadge } from "@/components/EpssBadge";

export const dynamic = "force-dynamic";

interface Props {
  params: Promise<{ locale: string }>;
  searchParams: Promise<{
    q?: string;
    severity?: string;
    kev?: string;
    ecosystem?: string;
    page?: string;
  }>;
}

export default async function SearchPage({ params, searchParams }: Props) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "Search" });
  const sp = await searchParams;
  const q = (sp.q ?? "").trim();

  if (/^CVE-\d{4}-\d+$/i.test(q)) {
    redirect({ href: `/cve/${q.toUpperCase()}`, locale });
  }

  const severity = sp.severity ? sp.severity.split(",") : undefined;
  const ecosystem = sp.ecosystem ? sp.ecosystem.split(",") : undefined;
  const kev = sp.kev === "true";
  const page = parseInt(sp.page ?? "1", 10) || 1;
  const pageSize = 25;
  const dateLocale = locale === "zh" ? "zh-TW" : "en";

  const { items, total } = await searchVulns({ q, severity, ecosystem, kev, page, pageSize });
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-4">
      <header className="flex items-baseline gap-3">
        <h1 className="text-xl font-bold">{t("title")}</h1>
        <span className="text-sm text-[hsl(var(--muted-foreground))]">
          {t("results", { n: total })}
          {q && (
            <>
              {" "}{t("for")} <span className="font-mono">&quot;{q}&quot;</span>
            </>
          )}
        </span>
      </header>

      <Filters sp={sp} t={t} />

      {items.length === 0 ? (
        <p className="text-[hsl(var(--muted-foreground))]">{t("noResults")}</p>
      ) : (
        <ul className="divide-y divide-[hsl(var(--border))] rounded-lg border border-[hsl(var(--border))]">
          {items.map((v) => (
            <li key={v.cve_id} className="px-4 py-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <SeverityBadge severity={v.severity} score={v.base_score} />
              <Link href={`/cve/${v.cve_id}`} className="font-mono font-medium no-underline">{v.cve_id}</Link>
              <KevBadge kev={v.kev} />
              <EpssBadge score={v.epss_score} />
              <span className="flex-1 min-w-0 text-sm text-[hsl(var(--muted-foreground))] truncate">
                {v.summary ?? ""}
              </span>
              {v.published_at && (
                <time className="text-xs text-[hsl(var(--muted-foreground))] font-mono shrink-0">
                  {new Date(v.published_at).toLocaleDateString(dateLocale)}
                </time>
              )}
            </li>
          ))}
        </ul>
      )}

      {totalPages > 1 && <Pagination sp={sp} page={page} totalPages={totalPages} t={t} />}
    </div>
  );
}

function Filters({
  sp,
  t,
}: {
  sp: { q?: string; severity?: string; kev?: string; ecosystem?: string };
  t: Awaited<ReturnType<typeof getTranslations<"Search">>>;
}) {
  const sev = (sp.severity ?? "").split(",").filter(Boolean);
  const eco = (sp.ecosystem ?? "").split(",").filter(Boolean);

  function toggle(arr: string[], v: string) {
    return arr.includes(v) ? arr.filter((x) => x !== v).join(",") : [...arr, v].join(",");
  }
  function paramsWith(overrides: Record<string, string>): string {
    const params = new URLSearchParams();
    if (sp.q) params.set("q", sp.q);
    if (sp.severity) params.set("severity", sp.severity);
    if (sp.kev) params.set("kev", sp.kev);
    if (sp.ecosystem) params.set("ecosystem", sp.ecosystem);
    for (const [k, v] of Object.entries(overrides)) {
      if (v) params.set(k, v);
      else params.delete(k);
    }
    return params.toString();
  }

  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <span className="text-[hsl(var(--muted-foreground))]">{t("severity")}</span>
      {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => {
        const active = sev.includes(s);
        return (
          <a
            key={s}
            href={`?${paramsWith({ severity: toggle(sev, s), page: "1" })}`}
            className={`rounded px-2 py-0.5 no-underline border ${
              active ? "bg-zinc-900 text-white border-zinc-900 dark:bg-white dark:text-zinc-900 dark:border-white" : "border-[hsl(var(--border))]"
            }`}
          >
            {s}
          </a>
        );
      })}
      <span className="mx-2 text-[hsl(var(--border))]">|</span>
      <span className="text-[hsl(var(--muted-foreground))]">{t("ecosystem")}</span>
      {["npm", "PyPI", "Maven", "Debian", "Alpine"].map((e) => {
        const active = eco.includes(e);
        return (
          <a
            key={e}
            href={`?${paramsWith({ ecosystem: toggle(eco, e), page: "1" })}`}
            className={`rounded px-2 py-0.5 no-underline border ${
              active ? "bg-zinc-900 text-white border-zinc-900 dark:bg-white dark:text-zinc-900 dark:border-white" : "border-[hsl(var(--border))]"
            }`}
          >
            {e}
          </a>
        );
      })}
      <span className="mx-2 text-[hsl(var(--border))]">|</span>
      <a
        href={`?${paramsWith({ kev: sp.kev === "true" ? "" : "true", page: "1" })}`}
        className={`rounded px-2 py-0.5 no-underline border ${
          sp.kev === "true" ? "bg-[hsl(15,82%,30%)] text-white border-transparent" : "border-[hsl(var(--border))]"
        }`}
      >
        {t("kevOnly")}
      </a>
    </div>
  );
}

function Pagination({
  sp,
  page,
  totalPages,
  t,
}: {
  sp: { q?: string; severity?: string; kev?: string; ecosystem?: string };
  page: number;
  totalPages: number;
  t: Awaited<ReturnType<typeof getTranslations<"Search">>>;
}) {
  const base = new URLSearchParams();
  if (sp.q) base.set("q", sp.q);
  if (sp.severity) base.set("severity", sp.severity);
  if (sp.kev) base.set("kev", sp.kev);
  if (sp.ecosystem) base.set("ecosystem", sp.ecosystem);
  const prev = new URLSearchParams(base);
  prev.set("page", String(Math.max(1, page - 1)));
  const next = new URLSearchParams(base);
  next.set("page", String(Math.min(totalPages, page + 1)));
  return (
    <div className="flex items-center gap-3 text-sm">
      {page > 1 && <a href={`?${prev}`} className="no-underline">{t("prev")}</a>}
      <span className="text-[hsl(var(--muted-foreground))]">{t("pageOf", { page, total: totalPages })}</span>
      {page < totalPages && <a href={`?${next}`} className="no-underline">{t("next")}</a>}
    </div>
  );
}
