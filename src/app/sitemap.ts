import type { MetadataRoute } from "next";
import { pool } from "@/db/client";
import { routing } from "@/i18n/routing";
import { INSIGHT_ECOSYSTEMS } from "@/lib/insights";

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

  // CVE pages — only those in KEV or with EPSS >= 5%. That's still the
  // long tail of "actually interesting" CVEs without blowing the cap.
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

  // Top packages by CVE count — search-worthy long-tail.
  const { rows: pkgs } = await pool.query<{ ecosystem: string; name: string }>(
    `SELECT p.ecosystem, p.name
       FROM packages p
       JOIN affected a ON a.package_id = p.id
      GROUP BY p.ecosystem, p.name
      ORDER BY COUNT(DISTINCT a.cve_id) DESC
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
  return out;
}
