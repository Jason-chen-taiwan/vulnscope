import "server-only";
import { sql } from "drizzle-orm";
import { ingestDb, ingestPool } from "@/db/ingest-pool";
import { vulnerabilities } from "@/db/schema";
import { startJob } from "@/lib/sync-jobs";
import { getMeta, setMeta } from "./meta";
import { fetchKev, parseKevDate } from "./kev-core";

const META_KEY = "kev:catalog_version";

export interface RunKevOptions {
  signal?: AbortSignal;
}

/**
 * Postgres KEV ingest. Fetch/parse lives in ./kev-core.ts (shared with
 * the SQLite build); this wrapper does the Postgres upsert + job +
 * incremental-skip bookkeeping.
 */
export async function runKevIngest(
  opts?: RunKevOptions,
): Promise<{ seen: number; changed: number }> {
  const job = await startJob("kev");
  let seen = 0;
  let changed = 0;
  try {
    const payload = await fetchKev(opts?.signal);
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
      const addedAt = parseKevDate(e.dateAdded);
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
