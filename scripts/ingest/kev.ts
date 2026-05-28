/**
 * CISA KEV ingest.
 *
 * Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 * Single ~2MB JSON, ~1200 entries. Keyed on cveID.
 *
 * Strategy: for each KEV entry, UPSERT the vulnerabilities row to set
 * kev=true and kev_added_at. If the CVE isn't yet in our DB (because OSV
 * doesn't track it), we still create a stub row so the KEV signal isn't lost.
 */
import "./_shared";
import { fetch } from "undici";
import { db, pool } from "../../src/db/client";
import { vulnerabilities } from "../../src/db/schema";
import { sql } from "drizzle-orm";
import { done, logProgress, parseDate } from "./_shared";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
}
interface KevPayload {
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
}

async function main() {
  console.log(`[kev] fetching ${KEV_URL}`);
  const res = await fetch(KEV_URL);
  if (!res.ok) throw new Error(`KEV fetch failed: ${res.status}`);
  const payload = (await res.json()) as KevPayload;
  console.log(
    `[kev] catalogVersion=${payload.catalogVersion} count=${payload.count}`,
  );

  let i = 0;
  for (const e of payload.vulnerabilities) {
    const addedAt = parseDate(e.dateAdded);
    const summary = e.vulnerabilityName;
    const description = e.shortDescription;
    // Upsert: insert a stub if CVE not present; otherwise just flip kev flag
    // and fill description if we haven't got one yet from OSV.
    await db
      .insert(vulnerabilities)
      .values({
        cveId: e.cveID,
        sourceId: `kev:${payload.catalogVersion}`,
        summary,
        description,
        kev: true,
        kevAddedAt: addedAt,
      })
      .onConflictDoUpdate({
        target: vulnerabilities.cveId,
        set: {
          kev: true,
          kevAddedAt: sql`COALESCE(${vulnerabilities.kevAddedAt}, EXCLUDED.kev_added_at)`,
          summary: sql`COALESCE(${vulnerabilities.summary}, EXCLUDED.summary)`,
          description: sql`COALESCE(${vulnerabilities.description}, EXCLUDED.description)`,
        },
      });
    i++;
    if (i % 50 === 0) logProgress("kev", i, payload.count);
  }
  done("kev");

  const { rows } = await pool.query(
    "SELECT COUNT(*)::int AS c FROM vulnerabilities WHERE kev=true",
  );
  console.log(`[kev] vulnerabilities with kev=true: ${rows[0].c}`);
  await pool.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
