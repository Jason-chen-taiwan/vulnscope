import type { NextRequest } from "next/server";
import { searchVulns } from "@/lib/queries";
import { renderRss } from "@/lib/rss";

export const revalidate = 600;

// OSV's canonical ecosystem strings — accept lowercase forms in the
// URL and map back. Anything else 404s rather than returning an empty
// feed (which would silently swallow typos).
const ECOSYSTEM_MAP: Record<string, string> = {
  npm: "npm",
  pypi: "PyPI",
  maven: "Maven",
  go: "Go",
  rubygems: "RubyGems",
  packagist: "Packagist",
  crates: "crates.io",
  "crates.io": "crates.io",
  nuget: "NuGet",
  hex: "Hex",
  hackage: "Hackage",
  debian: "Debian",
  alpine: "Alpine",
  bitnami: "Bitnami",
};

export const GET = async (
  _req: NextRequest,
  ctx: { params: Promise<{ ecosystem: string }> },
) => {
  const { ecosystem: raw } = await ctx.params;
  const ecosystem = ECOSYSTEM_MAP[raw.toLowerCase()];
  if (!ecosystem) {
    return new Response("Unknown ecosystem", { status: 404 });
  }
  const { items } = await searchVulns({
    ecosystem: [ecosystem],
    page: 1,
    pageSize: 50,
  });
  const xml = renderRss(items, {
    title: `VulnScope — ${ecosystem} CVEs`,
    description: `Newest ${ecosystem} ecosystem vulnerabilities.`,
    selfHref: `/feed/ecosystem/${raw.toLowerCase()}`,
  });
  return new Response(xml, {
    headers: {
      "content-type": "application/rss+xml; charset=utf-8",
      "cache-control": "public, max-age=600, stale-while-revalidate=1200",
    },
  });
};
