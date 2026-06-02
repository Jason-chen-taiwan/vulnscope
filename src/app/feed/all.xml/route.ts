import { searchVulns } from "@/lib/queries";
import { renderRss } from "@/lib/rss";

// Feeds are unauthenticated and built from a single indexed query —
// cache hard (10 min) to absorb any feed-reader storm. force-dynamic
// is required because Next would otherwise try to prerender this at
// build time, when the DB isn't reachable from the Docker builder.
export const dynamic = "force-dynamic";
export const revalidate = 600;

export async function GET() {
  const { items } = await searchVulns({ page: 1, pageSize: 50 });
  const xml = renderRss(items, {
    title: "VulnScope — all CVEs",
    description: "Newest CVEs across all ecosystems, with KEV and CVSS context.",
    selfHref: "/feed/all.xml",
  });
  return new Response(xml, {
    headers: {
      "content-type": "application/rss+xml; charset=utf-8",
      "cache-control": "public, max-age=600, stale-while-revalidate=1200",
    },
  });
}
