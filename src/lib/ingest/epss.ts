import "server-only";
import { fetch } from "undici";
import { createGunzip } from "node:zlib";
import { Readable } from "node:stream";
import { createInterface } from "node:readline";
import { pool } from "@/db/client";
import { startJob } from "@/lib/sync-jobs";

const URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
// Cloudflare in front of FIRST.org occasionally hangs the gunzip stream
// without sending RST; without a timeout `for await (line of rl)` waits
// forever. The full file is ~10 MB / 330k rows; 5 minutes is generous.
const EPSS_TIMEOUT_MS = 5 * 60 * 1000;

export async function runEpssIngest(): Promise<{ seen: number; changed: number }> {
  const job = await startJob("epss");
  let processed = 0;
  let updated = 0;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(new Error("EPSS ingest timed out after 5 minutes")), EPSS_TIMEOUT_MS);
  try {
    const res = await fetch(URL, { redirect: "follow", signal: controller.signal });
    if (!res.ok || !res.body) throw new Error(`EPSS fetch failed: ${res.status}`);
    const gunzip = createGunzip();
    const src = Readable.fromWeb(res.body as never);
    // Forward stream errors to the controller so `for await` rejects
    // instead of hanging on a broken pipe.
    src.on("error", (e) => controller.abort(e));
    gunzip.on("error", (e) => controller.abort(e));
    src.pipe(gunzip);

    const rl = createInterface({ input: gunzip, crlfDelay: Infinity });
    controller.signal.addEventListener("abort", () => {
      rl.close();
      gunzip.destroy();
      src.destroy();
    });
    const BATCH = 1000;
    let header: string[] | null = null;
    let batch: [string, string, string][] = [];
    let scoreDate: string | null = null;

    async function flush() {
      if (batch.length === 0) return;
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
      params.push(scoreDate ?? new Date().toISOString());
      const r = await pool.query(sqlText, params);
      updated += r.rowCount ?? 0;
      batch = [];
    }

    for await (const line of rl) {
      if (line.startsWith("#")) {
        const m = line.match(/score_date:([^,\s]+)/);
        if (m) scoreDate = m[1];
        continue;
      }
      if (!header) {
        header = line.split(",");
        continue;
      }
      const cols = line.split(",");
      if (cols.length < 3) continue;
      batch.push([cols[0], cols[1], cols[2]]);
      processed++;
      if (batch.length >= BATCH) await flush();
    }
    await flush();
    await job.finish({ seen: processed, changed: updated, error: null });
    return { seen: processed, changed: updated };
  } catch (err) {
    await job.finish({ seen: processed, changed: updated, error: err as Error });
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}
