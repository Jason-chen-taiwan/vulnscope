import "server-only";
import { ingestPool } from "@/db/ingest-pool";
import { startJob } from "@/lib/sync-jobs";
import { getMeta, setMeta } from "./meta";
import { streamEpss, type EpssRow } from "./epss-core";

const META_KEY = "epss:score_date";

export interface RunEpssOptions {
  signal?: AbortSignal;
}

/**
 * Postgres EPSS ingest. The fetch/gunzip/parse loop lives in
 * ./epss-core.ts (shared with the SQLite build); this wrapper supplies
 * the Postgres write path — a multi-VALUES `UPDATE ... FROM (VALUES ...)`
 * — plus job + incremental-skip bookkeeping.
 */
export async function runEpssIngest(
  opts?: RunEpssOptions,
): Promise<{ seen: number; changed: number }> {
  const job = await startJob("epss");
  let lastSeen = 0;
  let lastChanged = 0;
  const knownScoreDate = await getMeta(META_KEY);

  async function writeBatch(batch: EpssRow[], scoreDate: string): Promise<number> {
    const valuesSql: string[] = [];
    const params: unknown[] = [];
    let p = 0;
    for (const [c, s, pct] of batch) {
      params.push(c, s, pct);
      valuesSql.push(`($${++p}::text, $${++p}::numeric, $${++p}::numeric)`);
    }
    const sqlText = `
      UPDATE vulnerabilities v
         SET epss_score = src.s,
             epss_percentile = src.p,
             epss_updated_at = $${++p}::timestamptz
        FROM (VALUES ${valuesSql.join(",")}) AS src(cve, s, p)
       WHERE v.cve_id = src.cve
    `;
    params.push(scoreDate);
    const r = await ingestPool.query(sqlText, params);
    return r.rowCount ?? 0;
  }

  try {
    const result = await streamEpss({
      writeBatch,
      signal: opts?.signal,
      knownScoreDate,
      onProgress: (seen, changed) => {
        lastSeen = seen;
        lastChanged = changed;
        // Heartbeat so the orchestrator's 5-min idle-timeout doesn't reap
        // a healthy ingest. JobHandle.progress() is coalesced internally.
        job.progress({ seen, changed });
      },
    });
    if (!result.skipped && result.scoreDate) {
      await setMeta(META_KEY, result.scoreDate);
    }
    await job.finish({ seen: result.seen, changed: result.changed, error: null });
    return { seen: result.seen, changed: result.changed };
  } catch (err) {
    await job.finish({ seen: lastSeen, changed: lastChanged, error: err as Error });
    throw err;
  }
}
