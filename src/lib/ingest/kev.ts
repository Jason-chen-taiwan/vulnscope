import "server-only";
import { fetch } from "undici";
import { sql } from "drizzle-orm";
import { ingestDb, ingestPool } from "@/db/ingest-pool";
import { vulnerabilities } from "@/db/schema";
import { startJob } from "@/lib/sync-jobs";
import { getMeta, setMeta } from "./meta";

const META_KEY = "kev:catalog_version";

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

export interface RunKevOptions {
  signal?: AbortSignal;
}

export async function runKevIngest(
  opts?: RunKevOptions,
): Promise<{ seen: number; changed: number }> {
  const job = await startJob("kev");
  let seen = 0;
  let changed = 0;
  try {
    const res = await fetch(KEV_URL, { signal: opts?.signal });
    if (!res.ok) throw new Error(`KEV fetch failed: ${res.status}`);
    const payload = (await res.json()) as KevPayload;
    seen = payload.vulnerabilities.length;
    // Incremental skip: CISA bumps catalogVersion only when the list
    // actually changes. If we've already ingested this version we still
    // want to record a success row, but we skip the per-entry upserts.
    const lastVersion = await getMeta(META_KEY);
    if (lastVersion === payload.catalogVersion) {
      await job.finish({ seen, changed: 0, error: null });
      return { seen, changed: 0 };
    }
    for (const e of payload.vulnerabilities) {
      if (opts?.signal?.aborted) throw new Error("aborted: kev");
      const addedAt = parseDate(e.dateAdded);
      const r = await ingestDb
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
    await setMeta(META_KEY, payload.catalogVersion);
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
      return ingestPool.end();
    })
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
