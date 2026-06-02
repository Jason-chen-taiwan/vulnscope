import "server-only";
import type { VulnListItem } from "@/lib/queries";

const SITE = "https://vulnscope-tw.fly.dev";

function escapeXml(s: string | null | undefined): string {
  if (!s) return "";
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function summarize(item: VulnListItem): string {
  const s = (item.summary ?? "").trim();
  if (s) return s;
  const d = (item.description ?? "").trim();
  if (!d) return "(no summary)";
  const firstSentence = d.split(/[.\n]/, 1)[0];
  return firstSentence.length > 280 ? firstSentence.slice(0, 280) + "…" : firstSentence;
}

export interface FeedMeta {
  title: string;
  description: string;
  /** Path portion the feed lives at, e.g. "/feed/all.xml". */
  selfHref: string;
}

export function renderRss(items: VulnListItem[], meta: FeedMeta): string {
  const now = new Date().toUTCString();
  const entries = items
    .map((it) => {
      const link = `${SITE}/en/cve/${it.cve_id}`;
      const pub = it.published_at ? new Date(it.published_at).toUTCString() : now;
      const sev = it.severity ? `[${it.severity}] ` : "";
      const kev = it.kev ? "[KEV] " : "";
      const scoreTag =
        it.base_score != null ? ` (CVSS ${it.base_score.toFixed(1)})` : "";
      const title = escapeXml(`${kev}${sev}${it.cve_id}${scoreTag}`);
      const desc = escapeXml(summarize(it));
      // CVE IDs are stable, globally unique permalinks — use as guid.
      return `    <item>
      <title>${title}</title>
      <link>${link}</link>
      <guid isPermaLink="true">${link}</guid>
      <pubDate>${pub}</pubDate>
      <description>${desc}</description>
    </item>`;
    })
    .join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${escapeXml(meta.title)}</title>
    <link>${SITE}</link>
    <atom:link href="${SITE}${meta.selfHref}" rel="self" type="application/rss+xml" />
    <description>${escapeXml(meta.description)}</description>
    <language>en</language>
    <lastBuildDate>${now}</lastBuildDate>
    <generator>VulnScope</generator>
${entries}
  </channel>
</rss>`;
}
