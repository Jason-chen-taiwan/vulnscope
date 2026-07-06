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

// Literal classnames so Tailwind's JIT keeps them. Don't template these.
const SEVERITY_BAR: Record<string, string> = {
  CRITICAL: "border-l-red-600",
  HIGH: "border-l-orange-600",
  MEDIUM: "border-l-yellow-500",
  LOW: "border-l-green-600",
  NONE: "border-l-zinc-300",
};

const SEVERITY_TEXT: Record<string, string> = {
  CRITICAL: "text-red-600",
  HIGH: "text-orange-600",
  MEDIUM: "text-yellow-600",
  LOW: "text-green-600",
  NONE: "text-zinc-500",
};

function splitUrl(url: string): { host: string; path: string } {
  try {
    const u = new URL(url);
    const path = `${u.pathname}${u.search}${u.hash}`;
    return { host: u.host, path: path === "/" ? "" : path };
  } catch {
    return { host: url, path: "" };
  }
}

export const dynamic = "force-dynamic";

const SITE = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string; id: string }>;
}): Promise<Metadata> {
  const { locale, id } = await params;
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
    alternates: {
      canonical: `${SITE}/${locale}/cve/${cveId}`,
      languages: {
        en: `${SITE}/en/cve/${cveId}`,
        "zh-TW": `${SITE}/zh/cve/${cveId}`,
        "x-default": `${SITE}/en/cve/${cveId}`,
      },
    },
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
  const sevKey = topScore?.severity ?? "NONE";
  const barClass = SEVERITY_BAR[sevKey] ?? SEVERITY_BAR.NONE;
  const sevTextClass = SEVERITY_TEXT[sevKey] ?? SEVERITY_TEXT.NONE;

  const cardClass =
    "rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-5";
  const sectionTitleClass = "text-base font-semibold mb-3";

  // JSON-LD for AI search citation. CVE has no official schema.org type;
  // TechArticle + Thing.additionalProperty for the three numbers (CVSS / EPSS /
  // KEV) gives crawlers a machine-readable surface they can extract from.
  // Schema.org validator: https://validator.schema.org/
  const ldProps: Array<{ "@type": "PropertyValue"; name: string; value: string | number | boolean }> = [];
  if (topScore?.base_score !== null && topScore?.base_score !== undefined) {
    ldProps.push({ "@type": "PropertyValue", name: "CVSS", value: topScore.base_score });
  }
  if (vuln.epss_score !== null && vuln.epss_score !== undefined) {
    ldProps.push({ "@type": "PropertyValue", name: "EPSS", value: vuln.epss_score });
  }
  ldProps.push({ "@type": "PropertyValue", name: "KEV", value: vuln.kev });
  const ld = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    headline: vuln.summary ? `${vuln.cve_id}: ${vuln.summary}` : vuln.cve_id,
    datePublished: vuln.published_at ?? undefined,
    dateModified: vuln.modified_at ?? undefined,
    description: vuln.description ?? vuln.summary ?? vuln.cve_id,
    inLanguage: locale === "zh" ? "zh-TW" : "en",
    url: `${SITE}/${locale}/cve/${vuln.cve_id}`,
    author: { "@type": "Organization", name: "VulnScope", url: SITE },
    publisher: { "@type": "Organization", name: "VulnScope", url: SITE },
    about: {
      "@type": "Thing",
      name: vuln.cve_id,
      identifier: vuln.cve_id,
      additionalProperty: ldProps,
    },
  };

  return (
    <article className="space-y-6">
      <script
        type="application/ld+json"
        // JSON.stringify is safe here — all values are either pre-validated
        // CVE IDs / numbers / dates, or DB text already escaped by React when
        // rendered elsewhere on the page. </script> closure escape is the only
        // residual risk and JSON.stringify doesn't emit it.
        dangerouslySetInnerHTML={{ __html: JSON.stringify(ld) }}
      />
      {/* Severity Hero */}
      <section
        className={`rounded-lg border border-[hsl(var(--border))] border-l-4 ${barClass} bg-[hsl(var(--background))] p-5`}
      >
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0 flex-1 space-y-2">
            <h1 className="text-2xl font-bold font-mono break-all">{vuln.cve_id}</h1>
            {vuln.summary && (
              <p className="text-lg leading-snug text-[hsl(var(--foreground))]">{vuln.summary}</p>
            )}
          </div>
          {topScore && (
            <div className="shrink-0 sm:text-right">
              <div className={`text-5xl font-bold font-mono leading-none ${sevTextClass}`}>
                {topScore.base_score?.toFixed(1) ?? "—"}
              </div>
              <div className={`mt-1 text-xs font-bold uppercase tracking-wide ${sevTextClass}`}>
                {topScore.severity ?? "—"}
              </div>
              <div className="mt-0.5 text-[10px] uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
                CVSS {topScore.version}
              </div>
            </div>
          )}
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <KevBadge kev={vuln.kev} />
          <EpssBadge score={vuln.epss_score} percentile={vuln.epss_percentile} />
        </div>
      </section>

      <div className="grid gap-6 lg:grid-cols-[1fr_280px]">
        {/* Main column */}
        <main className="min-w-0 space-y-6">
          {vuln.description && (
            <section className={cardClass}>
              <h2 className={sectionTitleClass}>{t("description")}</h2>
              <p className="whitespace-pre-wrap leading-relaxed">{vuln.description}</p>
            </section>
          )}

          {/* SEO Q&A sections. Renders identical info to the structured
              data above, but as plain HTML so featured-snippet extractors
              (Google AI Overview, Perplexity, Bing answer cards) have a
              direct H2-question → A pattern to grab. Order intentional:
              "What is" → "How to fix" → "Is exploited" matches the most
              common long-tail search intents for CVE pages. */}
          {!vuln.description && vuln.summary === null && (
            <section className={cardClass}>
              <h2 className={sectionTitleClass}>{t("whatIsTitle", { id: cveId })}</h2>
              <p className="leading-relaxed">{t("whatIsNoSummary", { id: cveId })}</p>
            </section>
          )}

          <section className={cardClass}>
            <h2 className={sectionTitleClass}>{t("howToFixTitle", { id: cveId })}</h2>
            {affected.length === 0 ? (
              <p className="leading-relaxed">{t("howToFixNoMapping")}</p>
            ) : (
              (() => {
                // Per-package smallest fixed version walking the OSV
                // events[] form. We don't validate ranges against a
                // specific user version here — that's what
                // VersionChecker on the package page is for. We just
                // surface the public "this version onward is patched"
                // signal so search snippets and LLM summarisers can
                // extract a concrete remediation step.
                const fixes = affected.map((a) => {
                  let fixedAt: string | null = null;
                  for (const r of a.ranges_json) {
                    for (const ev of r.events ?? []) {
                      if (ev.fixed) {
                        fixedAt = ev.fixed;
                        break;
                      }
                    }
                    if (fixedAt) break;
                  }
                  return { ecosystem: a.ecosystem, name: a.name, fixedAt };
                });
                const hasAnyFix = fixes.some((f) => f.fixedAt !== null);
                return (
                  <>
                    <p className="leading-relaxed mb-3">
                      {hasAnyFix ? t("howToFixIntro", { id: cveId }) : t("howToFixNoFix")}
                    </p>
                    <ul className="space-y-1.5 text-sm">
                      {fixes.map((f) => (
                        <li key={`${f.ecosystem}/${f.name}`} className="flex flex-wrap items-baseline gap-2">
                          <Link
                            href={`/package/${f.ecosystem}/${f.name}`}
                            className="font-mono no-underline"
                          >
                            <span className="text-xs text-[hsl(var(--muted-foreground))]">{f.ecosystem}/</span>
                            <span>{f.name}</span>
                          </Link>
                          <span className="text-[hsl(var(--muted-foreground))]">—</span>
                          <span>
                            {f.fixedAt
                              ? t("fixUpgradeTo", { version: f.fixedAt })
                              : t("fixNoneListed")}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </>
                );
              })()
            )}
          </section>

          <section className={cardClass}>
            <h2 className={sectionTitleClass}>{t("isExploitedTitle", { id: cveId })}</h2>
            <p className="leading-relaxed">
              {vuln.kev
                ? t("isExploitedKev", { id: cveId })
                : vuln.epss_score !== null && vuln.epss_score !== undefined
                  ? vuln.epss_score >= 0.5
                    ? t("isExploitedEpssHigh", { id: cveId, percent: (vuln.epss_score * 100).toFixed(1) })
                    : vuln.epss_score >= 0.05
                      ? t("isExploitedEpssMed", { id: cveId, percent: (vuln.epss_score * 100).toFixed(1) })
                      : t("isExploitedEpssLow", { id: cveId, percent: (vuln.epss_score * 100).toFixed(1) })
                  : t("isExploitedUnknown", { id: cveId })}
            </p>
          </section>

          <section className={cardClass}>
            <h2 className={sectionTitleClass}>{t("affectedPackages", { n: affected.length })}</h2>
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
                  <li
                    key={`${a.ecosystem}/${a.name}`}
                    className="flex flex-wrap items-center gap-2 px-4 py-3 hover:bg-[hsl(var(--muted))]"
                  >
                    <Link href={`/package/${a.ecosystem}/${a.name}`} className="no-underline font-medium">
                      <span className="font-mono text-xs text-[hsl(var(--muted-foreground))]">{a.ecosystem}/</span>
                      <span className="font-mono">{a.name}</span>
                    </Link>
                    <span className="flex-1 min-w-0 text-sm text-[hsl(var(--muted-foreground))] font-mono">
                      {a.ranges_json.map((r) => describeRange(r)).filter(Boolean).join("  |  ")}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {scores.length > 0 && (
            <section className={cardClass}>
              <h2 className={sectionTitleClass}>{t("cvssScores")}</h2>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-xs uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
                    <tr>
                      <th className="text-left py-2 pr-3 font-medium">{t("source")}</th>
                      <th className="text-left py-2 pr-3 font-medium">{t("version")}</th>
                      <th className="text-left py-2 pr-3 font-medium">{t("severityCol")}</th>
                      <th className="text-left py-2 font-medium">{t("vector")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scores.map((s: { source: string; version: string; severity: string | null; base_score: number | null; vector: string | null }, i: number) => (
                      <tr key={i} className="border-t border-[hsl(var(--border))]">
                        <td className="py-2 pr-3 font-mono text-xs">{s.source}</td>
                        <td className="py-2 pr-3 font-mono text-xs whitespace-nowrap">CVSS {s.version}</td>
                        <td className="py-2 pr-3">
                          <SeverityBadge severity={s.severity} score={s.base_score} />
                        </td>
                        <td className="py-2 font-mono text-xs break-all text-[hsl(var(--muted-foreground))]">
                          {s.vector ?? ""}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {exploits.length > 0 && (
            <section className={`${cardClass} border-l-4 border-l-red-600`}>
              <h2 className={`${sectionTitleClass} text-red-600`}>
                {t("exploitsAvailable", { n: exploits.length })}
              </h2>
              <ul className="divide-y divide-[hsl(var(--border))] rounded-lg border border-[hsl(var(--border))]">
                {exploits.slice(0, 25).map((e) => {
                  const { host, path } = splitUrl(e.url);
                  return (
                    <li key={e.url} className="hover:bg-[hsl(var(--muted))]">
                      <a
                        href={e.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="flex items-baseline gap-3 px-4 py-2 no-underline"
                        title={e.url}
                      >
                        <span className="w-20 shrink-0 font-mono text-[10px] uppercase text-[hsl(var(--muted-foreground))]">
                          {e.source}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-sm">
                          <span className="font-medium">{host}</span>
                          {path && <span className="text-[hsl(var(--muted-foreground))]">{path}</span>}
                        </span>
                      </a>
                    </li>
                  );
                })}
                {exploits.length > 25 && (
                  <li className="px-4 py-2 text-xs text-[hsl(var(--muted-foreground))]">
                    {t("moreExploits", { n: exploits.length - 25 })}
                  </li>
                )}
              </ul>
            </section>
          )}

          {refs.length > 0 && (
            <section className={cardClass}>
              <h2 className={sectionTitleClass}>{t("references", { n: refs.length })}</h2>
              <ul className="divide-y divide-[hsl(var(--border))] rounded-lg border border-[hsl(var(--border))]">
                {refs.slice(0, 50).map((r: { url: string; type: string | null }) => {
                  const { host, path } = splitUrl(r.url);
                  return (
                    <li key={r.url} className="hover:bg-[hsl(var(--muted))]">
                      <a
                        href={r.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="flex items-baseline gap-3 px-4 py-2 no-underline"
                        title={r.url}
                      >
                        <span className="w-16 shrink-0 font-mono text-[10px] uppercase text-[hsl(var(--muted-foreground))]">
                          {r.type ?? "WEB"}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-sm">
                          <span className="font-medium">{host}</span>
                          {path && <span className="text-[hsl(var(--muted-foreground))]">{path}</span>}
                        </span>
                      </a>
                    </li>
                  );
                })}
                {refs.length > 50 && (
                  <li className="px-4 py-2 text-xs text-[hsl(var(--muted-foreground))]">
                    {t("moreRefs", { n: refs.length - 50 })}
                  </li>
                )}
              </ul>
            </section>
          )}
        </main>

        {/* Sidebar */}
        <aside className="space-y-6 lg:sticky lg:top-6 lg:self-start">
          <section className={cardClass}>
            <h2 className="text-xs font-semibold uppercase tracking-wide text-[hsl(var(--muted-foreground))] mb-3">
              {t("metadata")}
            </h2>
            <dl className="space-y-2 text-sm">
              {vuln.published_at && (
                <div className="flex justify-between gap-3">
                  <dt className="text-[hsl(var(--muted-foreground))]">{t("publishedLabel")}</dt>
                  <dd className="font-mono text-xs">
                    {new Date(vuln.published_at).toLocaleDateString(dateLocale)}
                  </dd>
                </div>
              )}
              {vuln.modified_at && (
                <div className="flex justify-between gap-3">
                  <dt className="text-[hsl(var(--muted-foreground))]">{t("modifiedLabel")}</dt>
                  <dd className="font-mono text-xs">
                    {new Date(vuln.modified_at).toLocaleDateString(dateLocale)}
                  </dd>
                </div>
              )}
              {vuln.kev_added_at && (
                <div className="flex justify-between gap-3">
                  <dt className="font-medium text-[hsl(15,82%,30%)]">{t("kevAddedLabel")}</dt>
                  <dd className="font-mono text-xs text-[hsl(15,82%,30%)]">
                    {new Date(vuln.kev_added_at).toLocaleDateString(dateLocale)}
                  </dd>
                </div>
              )}
            </dl>
          </section>

          {aliases.length > 0 && (
            <section className={cardClass}>
              <h2 className="text-xs font-semibold uppercase tracking-wide text-[hsl(var(--muted-foreground))] mb-3">
                {t("alsoKnownAs")}
              </h2>
              <ul className="flex flex-col gap-1.5">
                {aliases.map((a) => {
                  const href = aliasExternalUrl(a.alias, a.source);
                  const inner = (
                    <span className="flex items-baseline justify-between gap-2">
                      <span className="font-mono text-sm break-all">{a.alias}</span>
                      <span className="shrink-0 text-[10px] uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
                        {a.source}
                      </span>
                    </span>
                  );
                  return href ? (
                    <li key={a.alias}>
                      <a
                        href={href}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="block rounded border border-[hsl(var(--border))] px-2 py-1 no-underline hover:bg-[hsl(var(--muted))]"
                      >
                        {inner}
                      </a>
                    </li>
                  ) : (
                    <li
                      key={a.alias}
                      className="rounded border border-[hsl(var(--border))] px-2 py-1"
                    >
                      {inner}
                    </li>
                  );
                })}
              </ul>
            </section>
          )}
        </aside>
      </div>
    </article>
  );
}
