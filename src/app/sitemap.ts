import type { MetadataRoute } from "next";
import { pool } from "@/db/client";
import { routing } from "@/i18n/routing";
import { INSIGHT_ECOSYSTEMS } from "@/lib/insights";

// Always render at request time — the DB isn't available at `next build`
// (we don't ship a DB inside the Docker image).
export const dynamic = "force-dynamic";

const SITE = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";

/**
 * Multi-language sitemap. Google's per-file URL cap is 50,000; we stay
 * well below by limiting CVE entries to the highest-signal subset (in KEV
 * or top EPSS) and capping package entries.
 */
export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const out: MetadataRoute.Sitemap = [];

  // Static and template pages, per locale.
  const staticPaths = [
    "",
    "/packages",
    "/insights",
    "/insights/most-vulnerable-packages",
    "/insights/cisa-kev-catalog",
    "/insights/epss-rising",
    ...INSIGHT_ECOSYSTEMS.map((eco) => `/insights/ecosystem/${eco}`),
  ];
  for (const path of staticPaths) {
    for (const locale of routing.locales) {
      out.push({ url: `${SITE}/${locale}${path}`, changeFrequency: "daily", priority: 0.7 });
    }
  }

  // CVE + package URLs come from the DB. If the DB isn't reachable
  // (e.g. cold-start race), still return the static entries — a partial
  // sitemap is better than a 500.
  try {
    const { rows: cves } = await pool.query<{ cve_id: string; modified_at: Date | null }>(
      `SELECT cve_id, modified_at
         FROM vulnerabilities
        WHERE kev = true OR epss_score >= 0.05
        ORDER BY epss_score DESC NULLS LAST
        LIMIT 20000`,
    );
    for (const r of cves) {
      for (const locale of routing.locales) {
        out.push({
          url: `${SITE}/${locale}/cve/${r.cve_id}`,
          lastModified: r.modified_at ?? undefined,
          changeFrequency: "weekly",
          priority: 0.6,
        });
      }
    }

    // Pre-aggregate from affected first, JOIN packages by PK after.
    // Same pattern as browsePackages — driving from packages forced a
    // full 120k-row scan of affected per page request.
    const { rows: pkgs } = await pool.query<{ ecosystem: string; name: string }>(
      `WITH agg AS (
         SELECT package_id, COUNT(DISTINCT cve_id) AS cve_count
           FROM affected
          GROUP BY package_id
       )
       SELECT p.ecosystem, p.name
         FROM agg
         JOIN packages p ON p.id = agg.package_id
        ORDER BY agg.cve_count DESC
        LIMIT 5000`,
    );
    for (const r of pkgs) {
      for (const locale of routing.locales) {
        out.push({
          url: `${SITE}/${locale}/package/${encodeURIComponent(r.ecosystem)}/${encodeURIComponent(r.name)}`,
          changeFrequency: "weekly",
          priority: 0.6,
        });
      }
    }
  } catch (e) {
    console.warn("[sitemap] DB unavailable, returning static entries only:", (e as Error).message);
  }
  return out;
}
