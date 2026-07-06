import type { NextRequest } from "next/server";
import { searchVulns } from "@/lib/queries";
import { renderRss } from "@/lib/rss";

export const revalidate = 600;

const LEVELS: Record<string, string[]> = {
  critical: ["CRITICAL"],
  // "high" is interpreted as "high-and-up" — the common subscription
  // intent ("page me on the bad ones") covers both.
  high: ["CRITICAL", "HIGH"],
  medium: ["MEDIUM"],
  low: ["LOW"],
  kev: [], // sentinel: handled below as kev=true filter
};

export const GET = async (
    _req: NextRequest,
    ctx: { params: Promise<{ level: string }> },
  ) => {
  const { level } = await ctx.params;
  const lower = level.toLowerCase();
  if (!(lower in LEVELS)) {
    return new Response("Unknown severity", { status: 404 });
  }

  const { items } = await searchVulns(
    lower === "kev"
      ? { kev: true, page: 1, pageSize: 50 }
      : { severity: LEVELS[lower], page: 1, pageSize: 50 },
  );

  const titleTag =
    lower === "kev" ? "CISA KEV catalog" : `${lower.toUpperCase()}-severity`;
  const xml = renderRss(items, {
    title: `VulnScope — ${titleTag} CVEs`,
    description:
      lower === "kev"
        ? "CVEs known to be exploited in the wild (CISA KEV)."
        : `Newest ${lower} severity CVEs across all ecosystems.`,
    selfHref: `/feed/severity/${lower}`,
  });
  return new Response(xml, {
    headers: {
      "content-type": "application/rss+xml; charset=utf-8",
      "cache-control": "public, max-age=600, stale-while-revalidate=1200",
    },
  });
};
