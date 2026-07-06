/**
 * EPSS feed READ + TRANSFORM core (DB-agnostic).
 *
 * Shared by the Postgres ingest (src/lib/ingest/epss.ts) and the SQLite
 * build (scripts/build-sqlite.ts). This module deliberately does NOT
 * import `server-only` or the pg pool, so it's safe to load from the
 * tsx-driven build script. The WRITE path is injected via `writeBatch`.
 *
 * Source: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
 * (FIRST.org's daily EPSS scores, ~330k rows / ~10 MB gzipped).
 */
import { fetch } from "undici";
import { createGunzip } from "node:zlib";
import { Readable } from "node:stream";
import { createInterface } from "node:readline";

const URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
// Cloudflare in front of FIRST.org occasionally hangs the gunzip stream
// without sending RST; without a timeout `for await (line of rl)` waits
// forever. The full file is ~10 MB / 330k rows; 5 minutes is generous.
const EPSS_TIMEOUT_MS = 5 * 60 * 1000;

/** One parsed CSV data row: [cve, epssScore, epssPercentile]. */
export type EpssRow = [cve: string, score: string, percentile: string];

export interface StreamEpssOptions {
  /**
   * Called once per batch (default 1000 rows) with the parsed rows and
   * the feed's score_date (ISO date string, used as epss_updated_at).
   * Return the number of vulnerability rows actually updated so the
   * caller can report `changed`.
   */
  writeBatch: (rows: EpssRow[], scoreDate: string) => number | Promise<number>;
  signal?: AbortSignal;
  /**
   * If the feed's score_date equals this, the stream stops early (nothing
   * new to ingest). Pass the last-ingested score_date; omit to always
   * ingest.
   */
  knownScoreDate?: string | null;
  onProgress?: (seen: number, changed: number) => void;
  batchSize?: number;
}

export interface StreamEpssResult {
  seen: number;
  changed: number;
  /** The feed's score_date, or null if never seen / skipped early. */
  scoreDate: string | null;
  /** True if the run stopped early because score_date matched knownScoreDate. */
  skipped: boolean;
}

/**
 * Downloads + parses the EPSS CSV, invoking `writeBatch` for each batch.
 * Contains ALL the streaming/gunzip/timeout logic that used to live in
 * epss.ts; the only thing pulled out is the DB write.
 */
export async function streamEpss(opts: StreamEpssOptions): Promise<StreamEpssResult> {
  const BATCH = opts.batchSize ?? 1000;
  let processed = 0;
  let updated = 0;
  const controller = new AbortController();
  const timeoutId = setTimeout(
    () => controller.abort(new Error("EPSS ingest timed out after 5 minutes")),
    EPSS_TIMEOUT_MS,
  );
  const fetchSignal = opts.signal
    ? AbortSignal.any([opts.signal, controller.signal])
    : controller.signal;
  try {
    const res = await fetch(URL, { redirect: "follow", signal: fetchSignal });
    if (!res.ok || !res.body) throw new Error(`EPSS fetch failed: ${res.status}`);
    const gunzip = createGunzip();
    const src = Readable.fromWeb(res.body as never);
    src.on("error", (e) => controller.abort(e));
    gunzip.on("error", (e) => controller.abort(e));
    src.pipe(gunzip);

    const rl = createInterface({ input: gunzip, crlfDelay: Infinity });
    controller.signal.addEventListener("abort", () => {
      rl.close();
      gunzip.destroy();
      src.destroy();
    });

    let header: string[] | null = null;
    let batch: EpssRow[] = [];
    let scoreDate: string | null = null;
    let skipRest = false;

    async function flush() {
      if (batch.length === 0) return;
      const n = await opts.writeBatch(batch, scoreDate ?? new Date().toISOString());
      updated += n;
      batch = [];
    }

    for await (const line of rl) {
      if (opts.signal?.aborted) throw new Error("aborted: epss");
      if (line.startsWith("#")) {
        const m = line.match(/score_date:([^,\s]+)/);
        if (m) {
          scoreDate = m[1];
          if (opts.knownScoreDate && opts.knownScoreDate === scoreDate) {
            skipRest = true;
            rl.close();
            break;
          }
        }
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
      if (batch.length >= BATCH) {
        await flush();
        opts.onProgress?.(processed, updated);
      }
    }
    if (!skipRest) await flush();
    return { seen: processed, changed: updated, scoreDate, skipped: skipRest };
  } finally {
    clearTimeout(timeoutId);
  }
}
