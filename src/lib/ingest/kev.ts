import "server-only";
import { fetch } from "undici";
import { sql } from "drizzle-orm";
import { db, pool } from "@/db/client";
import { vulnerabilities } from "@/db/schema";
import { startJob } from "@/lib/sync-jobs";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KevEntry {
  cveID: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
}
interface KevPayload {
  catalogVersion: string;
  count: number;
  vulnerabilities: KevEntry[];
}

function parseDate(s: string | undefined | null): Date | null {
  if (!s) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

export async function runKevIngest(): Promise<{ seen: number; changed: number }> {
  const job = await startJob("kev");
  let seen = 0;
  let changed = 0;
  try {
    const res = await fetch(KEV_URL);
    if (!res.ok) throw new Error(`KEV fetch failed: ${res.status}`);
    const payload = (await res.json()) as KevPayload;
    seen = payload.vulnerabilities.length;
    for (const e of payload.vulnerabilities) {
      const addedAt = parseDate(e.dateAdded);
      const r = await db
        .insert(vulnerabilities)
        .values({
          cveId: e.cveID,
          sourceId: `kev:${payload.catalogVersion}`,
          summary: e.vulnerabilityName,
          description: e.shortDescription,
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
        })
        .returning({ cveId: vulnerabilities.cveId });
      changed += r.length;
    }
    await job.finish({ seen, changed, error: null });
    return { seen, changed };
  } catch (err) {
    await job.finish({ seen, changed, error: err as Error });
    throw err;
  }
}

// Stand-alone CLI mode — `node ... kev.ts` works the same as before.
if (process.argv[1]?.endsWith("ingest/kev.ts") || process.argv[1]?.endsWith("ingest/kev.js")) {
  runKevIngest()
    .then((r) => {
      console.log(`[kev] seen=${r.seen} changed=${r.changed}`);
      return pool.end();
    })
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
