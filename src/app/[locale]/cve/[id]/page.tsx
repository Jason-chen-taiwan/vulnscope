import type { Metadata } from "next";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link } from "@/i18n/navigation";
import { notFound } from "next/navigation";
import { getCveBundle, getCveById, resolveToCveId } from "@/lib/queries";
import { redirect } from "next/navigation";
import { KevBadge, SeverityBadge } from "@/components/SeverityBadge";
import { EpssBadge } from "@/components/EpssBadge";
import { describeRange } from "@/lib/version-match";
import type { OsvRange } from "@/lib/osv";

/**
 * Best-effort external URL for an advisory alias. We only link to
 * sources where the URL scheme is stable and deterministic — others
 * (DLA, USN with date-suffix) don't round-trip cleanly so we just
 * display them without a link.
 */
function aliasExternalUrl(alias: string, source: string): string | null {
  switch (source) {
    case "ghsa":
      return `https://github.com/advisories/${alias}`;
    case "dsa":
      return `https://security-tracker.debian.org/tracker/${alias}`;
    case "rhsa":
      return `https://access.redhat.com/errata/${alias}`;
    case "usn":
      return `https://ubuntu.com/security/notices/${alias}`;
    default:
      return null;
  }
}

export const dynamic = "force-dynamic";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string; id: string }>;
}): Promise<Metadata> {
  const { id } = await params;
  const cveId = decodeURIComponent(id).toUpperCase();
  if (!/^CVE-\d{4}-\d+$/.test(cveId)) return { title: cveId };
  const vuln = await getCveById(cveId);
  if (!vuln) return { title: cveId, robots: { index: false } };
  const summary = vuln.summary?.slice(0, 80) ?? "";
  const title = summary ? `${cveId} — ${summary}` : cveId;
  const desc = vuln.description?.slice(0, 200) ?? vuln.summary ?? cveId;
  return {
    title,
    description: desc,
    openGraph: { title, description: desc, type: "article" },
    twitter: { card: "summary_large_image", title, description: desc },
  };
}

export default async function CvePage({
  params,
}: {
  params: Promise<{ locale: string; id: string }>;
}) {
  const { locale, id } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "Cve" });
  const dateLocale = locale === "zh" ? "zh-TW" : "en";
  const raw = decodeURIComponent(id);

  // Non-CVE identifier (GHSA, DSA, ALPINE, ...): resolve to canonical
  // CVE and 301 there. Keeps URLs canonical and lets bookmarks survive.
  if (!/^CVE-\d{4}-\d+$/i.test(raw)) {
    const resolved = await resolveToCveId(raw);
    if (resolved) redirect(`/${locale}/cve/${resolved}`);
    notFound();
  }

  const cveId = raw.toUpperCase();
  const bundle = await getCveBundle(cveId);
  if (!bundle) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-mono">{cveId}</h1>
        <p className="text-[hsl(var(--muted-foreground))]">{t("notInDb")}</p>
        <a
          className="underline"
          href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
          target="_blank"
          rel="noreferrer noopener"
        >
          {t("lookupNvd", { id: cveId })}
        </a>
      </div>
    );
  }

  const { vuln, scores, affected, refs, aliases, exploits } = bundle as {
    vuln: typeof bundle.vuln;
    scores: typeof bundle.scores;
    affected: typeof bundle.affected;
    refs: typeof bundle.refs;
    aliases: { alias: string; source: string }[];
    exploits: { url: string; source: string; description: string | null }[];
  };
  const topScore = scores.find((s: { base_score: number | null }) => s.base_score !== null);

  return (
    <article className="space-y-6">
      <header className="space-y-2">
        <div className="flex flex-wrap items-baseline gap-3">
          <h1 className="text-2xl font-bold font-mono">{vuln.cve_id}</h1>
          {topScore && <SeverityBadge severity={topScore.severity} score={topScore.base_score} />}
          <KevBadge kev={vuln.kev} />
          <EpssBadge score={vuln.epss_score} percentile={vuln.epss_percentile} />
        </div>
        {vuln.summary && <p className="text-lg">{vuln.summary}</p>}
        <div className="text-xs text-[hsl(var(--muted-foreground))] flex flex-wrap gap-4">
          {vuln.published_at && <span>{t("published", { date: new Date(vuln.published_at).toLocaleDateString(dateLocale) })}</span>}
          {vuln.modified_at && <span>{t("modified", { date: new Date(vuln.modified_at).toLocaleDateString(dateLocale) })}</span>}
          {vuln.kev_added_at && (
            <span className="text-[hsl(15,82%,30%)] font-medium">
              {t("addedToKev", { date: new Date(vuln.kev_added_at).toLocaleDateString(dateLocale) })}
            </span>
          )}
        </div>
        {aliases.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 text-xs pt-1">
            <span className="text-[hsl(var(--muted-foreground))]">{t("alsoKnownAs")}</span>
            {aliases.map((a) => {
              const href = aliasExternalUrl(a.alias, a.source);
              const className =
                "font-mono rounded border border-[hsl(var(--border))] px-1.5 py-0.5";
              return href ? (
                <a
                  key={a.alias}
                  href={href}
                  target="_blank"
                  rel="noreferrer noopener"
                  className={`${className} hover:bg-[hsl(var(--muted))] underline-offset-2 hover:underline`}
                  title={a.source.toUpperCase()}
                >
                  {a.alias}
                </a>
              ) : (
                <span key={a.alias} className={className} title={a.source.toUpperCase()}>
                  {a.alias}
                </span>
              );
            })}
          </div>
        )}
      </header>

      {vuln.description && (
        <section>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[hsl(var(--muted-foreground))] mb-2">
            {t("description")}
          </h2>
          <p className="whitespace-pre-wrap">{vuln.description}</p>
        </section>
      )}

      <section>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[hsl(var(--muted-foreground))] mb-2">
          {t("affectedPackages", { n: affected.length })}
        </h2>
        {affected.length === 0 ? (
          <p className="text-sm text-[hsl(var(--muted-foreground))]">{t("noPackageMapping")}</p>
        ) : (
          <ul className="divide-y divide-[hsl(var(--border))] rounded-lg border border-[hsl(var(--border))]">
            {affected.map((a: {
              ecosystem: string;
              name: string;
              ranges_json: OsvRange[];
              versions_json: string[] | null;
            }) => (
              <li key={`${a.ecosystem}/${a.name}`} className="px-4 py-3 flex flex-wrap items-baseline gap-2">
                <Link href={`/package/${a.ecosystem}/${a.name}`} className="no-underline font-medium">
                  <span className="font-mono text-xs text-[hsl(var(--muted-foreground))]">{a.ecosystem}/</span>
                  <span className="font-mono">{a.name}</span>
                </Link>
                <span className="text-sm text-[hsl(var(--muted-foreground))] font-mono">
                  {a.ranges_json.map((r) => describeRange(r)).filter(Boolean).join("  |  ")}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {scores.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[hsl(var(--muted-foreground))] mb-2">
            {t("cvssScores")}
          </h2>
          <table className="text-sm w-full">
            <thead className="text-xs uppercase text-[hsl(var(--muted-foreground))]">
              <tr>
                <th className="text-left py-1">{t("source")}</th>
                <th className="text-left py-1">{t("version")}</th>
                <th className="text-left py-1">{t("severityCol")}</th>
                <th className="text-left py-1">{t("vector")}</th>
              </tr>
            </thead>
            <tbody className="font-mono text-xs">
              {scores.map((s: { source: string; version: string; severity: string | null; base_score: number | null; vector: string | null }, i: number) => (
                <tr key={i} className="border-t border-[hsl(var(--border))]">
                  <td className="py-1 pr-3">{s.source}</td>
                  <td className="py-1 pr-3">CVSS {s.version}</td>
                  <td className="py-1 pr-3">
                    <SeverityBadge severity={s.severity} score={s.base_score} />
                  </td>
                  <td className="py-1 break-all">{s.vector ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {exploits.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold uppercase tracking-wide mb-2 text-[hsl(15,82%,30%)]">
            {t("exploitsAvailable", { n: exploits.length })}
          </h2>
          <ul className="space-y-1 text-sm">
            {exploits.slice(0, 25).map((e) => (
              <li key={e.url} className="flex items-baseline gap-2">
                <span className="text-[10px] uppercase font-mono w-20 shrink-0 text-[hsl(var(--muted-foreground))]">
                  {e.source}
                </span>
                <a
                  href={e.url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="break-all"
                >
                  {e.url}
                </a>
              </li>
            ))}
            {exploits.length > 25 && (
              <li className="text-xs text-[hsl(var(--muted-foreground))]">
                {t("moreExploits", { n: exploits.length - 25 })}
              </li>
            )}
          </ul>
        </section>
      )}

      {refs.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[hsl(var(--muted-foreground))] mb-2">
            {t("references", { n: refs.length })}
          </h2>
          <ul className="space-y-1 text-sm">
            {refs.slice(0, 50).map((r: { url: string; type: string | null }) => (
              <li key={r.url} className="flex items-baseline gap-2">
                <span className="text-[10px] uppercase font-mono w-16 shrink-0 text-[hsl(var(--muted-foreground))]">
                  {r.type ?? "WEB"}
                </span>
                <a href={r.url} target="_blank" rel="noreferrer noopener" className="break-all">
                  {r.url}
                </a>
              </li>
            ))}
            {refs.length > 50 && (
              <li className="text-xs text-[hsl(var(--muted-foreground))]">{t("moreRefs", { n: refs.length - 50 })}</li>
            )}
          </ul>
        </section>
      )}
    </article>
  );
}
