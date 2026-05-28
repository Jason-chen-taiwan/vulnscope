import Link from "next/link";
import { notFound } from "next/navigation";
import { getCveBundle } from "@/lib/queries";
import { KevBadge, SeverityBadge } from "@/components/SeverityBadge";
import { EpssBadge } from "@/components/EpssBadge";
import { describeRange } from "@/lib/version-match";
import type { OsvRange } from "@/lib/osv";

export const dynamic = "force-dynamic";

export default async function CvePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const cveId = decodeURIComponent(id).toUpperCase();
  if (!/^CVE-\d{4}-\d+$/.test(cveId)) notFound();

  const bundle = await getCveBundle(cveId);
  if (!bundle) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-mono">{cveId}</h1>
        <p className="text-[hsl(var(--muted-foreground))]">
          Not in this database (Phase 0 covers npm + PyPI via OSV + CISA KEV).
        </p>
        <a
          className="underline"
          href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
          target="_blank"
          rel="noreferrer noopener"
        >
          Look up {cveId} on NVD ↗
        </a>
      </div>
    );
  }

  const { vuln, scores, affected, refs } = bundle;
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
          {vuln.published_at && <span>Published: {new Date(vuln.published_at).toLocaleDateString()}</span>}
          {vuln.modified_at && <span>Modified: {new Date(vuln.modified_at).toLocaleDateString()}</span>}
          {vuln.kev_added_at && <span className="text-[hsl(15,82%,30%)] font-medium">Added to CISA KEV: {new Date(vuln.kev_added_at).toLocaleDateString()}</span>}
        </div>
      </header>

      {vuln.description && (
        <section>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[hsl(var(--muted-foreground))] mb-2">
            Description
          </h2>
          <p className="whitespace-pre-wrap">{vuln.description}</p>
        </section>
      )}

      <section>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[hsl(var(--muted-foreground))] mb-2">
          Affected packages ({affected.length})
        </h2>
        {affected.length === 0 ? (
          <p className="text-sm text-[hsl(var(--muted-foreground))]">No package mapping in OSV.</p>
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
                  {a.versions_json && a.versions_json.length > 0 && !a.ranges_json?.length && (
                    <span>exact: {a.versions_json.join(", ")}</span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {scores.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[hsl(var(--muted-foreground))] mb-2">
            CVSS scores
          </h2>
          <table className="text-sm w-full">
            <thead className="text-xs uppercase text-[hsl(var(--muted-foreground))]">
              <tr>
                <th className="text-left py-1">Source</th>
                <th className="text-left py-1">Version</th>
                <th className="text-left py-1">Severity</th>
                <th className="text-left py-1">Vector</th>
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

      {refs.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[hsl(var(--muted-foreground))] mb-2">
            References ({refs.length})
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
              <li className="text-xs text-[hsl(var(--muted-foreground))]">… {refs.length - 50} more</li>
            )}
          </ul>
        </section>
      )}
    </article>
  );
}
