import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link } from "@/i18n/navigation";
import { browsePackages } from "@/lib/queries";

export const dynamic = "force-dynamic";

const KNOWN_ECOSYSTEMS = [
  "npm", "PyPI", "Maven", "Go", "RubyGems", "Packagist", "crates.io",
  "NuGet", "Hex", "Hackage", "Debian", "Alpine", "Bitnami",
];

interface Props {
  params: Promise<{ locale: string }>;
  searchParams: Promise<{
    q?: string;
    ecosystem?: string;
    sort?: "cves" | "name";
    page?: string;
  }>;
}

export default async function PackagesPage({ params, searchParams }: Props) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "Packages" });
  const sp = await searchParams;
  const page = parseInt(sp.page ?? "1", 10) || 1;
  const pageSize = 50;
  const { items, total } = await browsePackages({
    q: sp.q,
    ecosystem: sp.ecosystem,
    sort: sp.sort ?? "cves",
    page,
    pageSize,
  });
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          {t("subtitle", { n: total, eco: KNOWN_ECOSYSTEMS.length })}
        </p>
      </header>

      <form className="flex flex-wrap items-center gap-2">
        <input
          type="search"
          name="q"
          defaultValue={sp.q ?? ""}
          placeholder={t("filterPlaceholder")}
          className="flex-1 min-w-[200px] rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-red-500"
        />
        <select
          name="ecosystem"
          defaultValue={sp.ecosystem ?? ""}
          className="rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-3 py-1.5 text-sm"
        >
          <option value="">{t("allEcosystems")}</option>
          {KNOWN_ECOSYSTEMS.map((e) => (
            <option key={e} value={e}>{e}</option>
          ))}
        </select>
        <select
          name="sort"
          defaultValue={sp.sort ?? "cves"}
          className="rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-3 py-1.5 text-sm"
        >
          <option value="cves">{t("sortCves")}</option>
          <option value="name">{t("sortName")}</option>
        </select>
        <button
          type="submit"
          className="rounded-md bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 px-4 py-1.5 text-sm font-medium"
        >
          {t("apply")}
        </button>
      </form>

      <ul className="divide-y divide-[hsl(var(--border))] rounded-lg border border-[hsl(var(--border))]">
        {items.length === 0 && (
          <li className="px-4 py-3 text-sm text-[hsl(var(--muted-foreground))]">{t("noMatches")}</li>
        )}
        {items.map((p) => (
          <li key={`${p.ecosystem}/${p.name}`} className="px-4 py-2 flex items-baseline gap-3">
            <span className="text-xs font-mono uppercase w-20 shrink-0 text-[hsl(var(--muted-foreground))]">
              {p.ecosystem}
            </span>
            <Link
              href={`/package/${encodeURIComponent(p.ecosystem)}/${encodeURIComponent(p.name)}`}
              className="flex-1 min-w-0 font-mono no-underline truncate"
            >
              {p.name}
            </Link>
            <span className="text-xs font-mono text-[hsl(var(--muted-foreground))] shrink-0">
              {t("cveCount", { n: p.cve_count })}
            </span>
            {p.kev_count > 0 && (
              <span className="text-xs font-mono font-bold text-[hsl(15,82%,30%)] shrink-0">
                {p.kev_count} KEV
              </span>
            )}
          </li>
        ))}
      </ul>

      {totalPages > 1 && <Pagination sp={sp} page={page} totalPages={totalPages} t={t} />}
    </div>
  );
}

function Pagination({
  sp,
  page,
  totalPages,
  t,
}: {
  sp: { q?: string; ecosystem?: string; sort?: string };
  page: number;
  totalPages: number;
  t: Awaited<ReturnType<typeof getTranslations<"Packages">>>;
}) {
  const tSearch = (k: "prev" | "next" | "pageOf") => {
    if (k === "prev") return "← Prev";
    if (k === "next") return "Next →";
    return `Page ${page} of ${totalPages}`;
  };
  void tSearch;
  void t;
  const base = new URLSearchParams();
  if (sp.q) base.set("q", sp.q);
  if (sp.ecosystem) base.set("ecosystem", sp.ecosystem);
  if (sp.sort) base.set("sort", sp.sort);
  const prev = new URLSearchParams(base);
  prev.set("page", String(Math.max(1, page - 1)));
  const next = new URLSearchParams(base);
  next.set("page", String(Math.min(totalPages, page + 1)));
  return (
    <div className="flex items-center gap-3 text-sm">
      {page > 1 && <a href={`?${prev}`} className="no-underline">← Prev</a>}
      <span className="text-[hsl(var(--muted-foreground))]">
        Page {page} of {totalPages}
      </span>
      {page < totalPages && <a href={`?${next}`} className="no-underline">Next →</a>}
    </div>
  );
}
