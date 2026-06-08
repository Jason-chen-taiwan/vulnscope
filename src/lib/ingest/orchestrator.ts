import "server-only";
import { runKevIngest } from "./kev";
import { runOsvIngest } from "./osv";
import { runEpssIngest } from "./epss";
import { runNvdIngest } from "./nvd";
import { runExploitsIngest } from "./exploits";
import { markTimedOut } from "@/lib/sync-jobs";
import { pool } from "@/db/client";

const ALL_ECOSYSTEMS = [
  "npm",
  "PyPI",
  "Maven",
  "Go",
  "RubyGems",
  "Packagist",
  "crates.io",
  "NuGet",
  "Hex",
  "Hackage",
  "Debian",
  "Alpine",
  "Bitnami",
];

/**
 * Operators can restrict which ecosystems the scheduler refreshes via
 * INGEST_ECOSYSTEMS env (comma-separated). Useful when the DB has size
 * constraints (e.g. Neon free tier @ 500 MB) — limiting to npm/PyPI/Maven
 * keeps the footprint under ~200 MB while still covering the bulk of
 * "what package am I using" questions.
 */
export const DEFAULT_ECOSYSTEMS = process.env.INGEST_ECOSYSTEMS
  ? process.env.INGEST_ECOSYSTEMS.split(",").map((s) => s.trim()).filter(Boolean)
  : ALL_ECOSYSTEMS;

export interface RefreshResult {
  startedAt: Date;
  finishedAt: Date;
  durationMs: number;
  steps: { source: string; ok: boolean; seen?: number; changed?: number; error?: string }[];
}

/**
 * Heartbeat-based timeout instead of wall-clock. A source is killed
 * only if `sync_jobs.last_heartbeat_at` for THIS attempt hasn't
 * advanced in IDLE_TIMEOUT_MS. As long as progress() keeps flushing
 * (which JobHandle does ~once/sec during hot ingest), the source
 * runs as long as it needs to — npm with 220k records can take 2
 * hours on Fly shared-cpu-1x and that's fine.
 *
 * Why the switch: wall-clock 5min was killing legitimately-progressing
 * sources (osv:PyPI/Maven/Go all hit "exceeded 300000ms" on 2026-06-08
 * even though their RSS was flat and last_heartbeat was current).
 * Heartbeat-based timeout kills only true hangs (e.g. download stuck,
 * pg connection dead, infinite loop), not "slow but progressing".
 *
 * Defense in depth, unchanged:
 *   (1) JS-level AbortSignal — cooperative cancel at chunk boundaries
 *   (2) Pool statement_timeout (5min) — server-side kill of stuck queries
 *   (3) HARD_CAP_MS absolute cap — guards against pathological loops
 *       that somehow keep flushing heartbeat but never finish (e.g. a
 *       paused upstream that yields one record every 4min).
 *
 * Tunables:
 *   IDLE_TIMEOUT_MS — max time without a heartbeat before kill
 *   HEARTBEAT_POLL_MS — how often we ask pg "is it still alive?"
 *   HARD_CAP_MS — absolute upper bound regardless of heartbeat
 */
const IDLE_TIMEOUT_MS = 5 * 60_000;
const HEARTBEAT_POLL_MS = 30_000;
const HARD_CAP_MS: Record<string, number> = {
  // nvd is rate-limited by upstream (5 req / 30s anonymous) and walks
  // potentially thousands of CVEs; 90min is the observed worst case
  // with a 500-CVE batch under cold cache. Kept distinct from osv.
  nvd: 90 * 60_000,
};
const DEFAULT_HARD_CAP_MS = 4 * 60 * 60_000; // 4h — generous for npm cold runs
function hardCapFor(source: string): number {
  return HARD_CAP_MS[source] ?? DEFAULT_HARD_CAP_MS;
}

/**
 * Run `fn(signal)` and abort it if EITHER:
 *   (a) the sync_jobs row for `label` started at/after `attemptStart`
 *       has had no heartbeat in IDLE_TIMEOUT_MS, OR
 *   (b) wall-clock has exceeded HARD_CAP_MS for this source.
 *
 * Polls last_heartbeat_at every HEARTBEAT_POLL_MS. Sources call
 * JobHandle.progress() which updates that column at most once/sec,
 * so a healthy ingest writes a fresh timestamp well within the poll
 * window. If progress() flushes fail or stop being called, idle
 * elapsed grows past the threshold and we abort.
 *
 * The signal is forwarded to fn for cooperative cancellation
 * (chunk-boundary checks in OSV; per-record checks in others).
 * Cancellation does NOT cancel in-flight pg queries — pool's
 * statement_timeout handles that layer.
 */
async function withHeartbeatTimeout<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  label: string,
  attemptStart: Date,
): Promise<T> {
  const ctrl = new AbortController();
  const hardCap = hardCapFor(label);
  const wallStart = Date.now();
  let lastSeenHeartbeat = attemptStart.getTime();

  // Best-effort heartbeat poller. Uses the WEB pool (not ingest pool)
  // because the ingest pool's 3 slots are likely held by the very
  // source we're monitoring — going via the busy pool would deadlock
  // the poller waiting for a slot that the zombie won't release.
  const poller = setInterval(async () => {
    try {
      const r = await pool.query<{ last_heartbeat_at: Date | null }>(
        `SELECT last_heartbeat_at FROM sync_jobs
          WHERE source = $1 AND started_at >= $2
          ORDER BY id DESC LIMIT 1`,
        [label, attemptStart],
      );
      const hb = r.rows[0]?.last_heartbeat_at?.getTime();
      if (hb && hb > lastSeenHeartbeat) lastSeenHeartbeat = hb;

      const idleMs = Date.now() - lastSeenHeartbeat;
      const wallMs = Date.now() - wallStart;
      if (idleMs > IDLE_TIMEOUT_MS) {
        ctrl.abort(new Error(`idle-timeout: ${label} no heartbeat for ${Math.round(idleMs / 1000)}s`));
      } else if (wallMs > hardCap) {
        ctrl.abort(new Error(`hard-cap: ${label} exceeded ${Math.round(hardCap / 1000)}s wall-clock`));
      }
    } catch {
      // Heartbeat lookup failures shouldn't kill the ingest — the
      // ingest itself is likely fine; pg might be momentarily busy.
    }
  }, HEARTBEAT_POLL_MS);

  try {
    return await Promise.race([
      fn(ctrl.signal),
      new Promise<never>((_, reject) => {
        ctrl.signal.addEventListener("abort", () => {
          // ctrl.abort(reason) puts the reason on signal.reason;
          // surface that if present, fall back to a generic message.
          const reason = (ctrl.signal as AbortSignal & { reason?: unknown }).reason;
          const msg = reason instanceof Error ? reason.message : `timeout: ${label}`;
          reject(new Error(msg));
        });
      }),
    ]);
  } finally {
    clearInterval(poller);
  }
}

/**
 * Run a full refresh: KEV, then each OSV ecosystem, then EPSS, then NVD
 * backfill, then exploits backfill.
 *
 * Each source runs independently — a failure in one (including a
 * timeout) does not abort the others. This matches the SRE principle
 * from PRD §12.3: never let a single upstream outage break the whole UI.
 *
 * Orchestrator deliberately uses the web pool (via sync-jobs.markTimedOut)
 * because the ingest pool's 3 slots might be held by the zombie source we
 * just timed out — going via web pool ensures the failure marker lands.
 */
export async function runFullRefresh(options?: {
  ecosystems?: string[];
  skipOsv?: boolean;
}): Promise<RefreshResult> {
  const startedAt = new Date();
  const ecosystems = options?.ecosystems ?? DEFAULT_ECOSYSTEMS;
  const steps: RefreshResult["steps"] = [];

  async function attempt(
    label: string,
    fn: (signal: AbortSignal) => Promise<{ seen: number; changed: number }>,
  ) {
    const t0 = Date.now();
    const attemptStart = new Date();
    try {
      const r = await withHeartbeatTimeout(fn, label, attemptStart);
      steps.push({ source: label, ok: true, seen: r.seen, changed: r.changed });
      console.log(`[refresh] ${label}: ok seen=${r.seen} changed=${r.changed} (${Date.now() - t0}ms)`);
    } catch (e) {
      const msg = (e as Error).message;
      // Heartbeat-timeout or hard-cap both mean the source was killed
      // externally; mark the zombie sync_jobs row failed via the web pool.
      const timedOut = msg.startsWith("idle-timeout:") || msg.startsWith("hard-cap:") || msg.startsWith("timeout:");
      steps.push({ source: label, ok: false, error: msg });
      console.error(`[refresh] ${label}: FAILED ${msg}`);
      if (timedOut) {
        // The zombie source is still in-flight and holds its own JobHandle.
        // markTimedOut goes via the WEB pool so it lands even if the
        // ingest pool's 3 slots are starved by the zombie. The zombie's
        // eventual finish() will no-op against the now-failed row
        // (`WHERE status='running'` guard in sync-jobs.ts).
        //
        // Cosmetic race: if the zombie's pg query completes and its
        // finish() lands BEFORE this markTimedOut, the row will show
        // `success` while RefreshResult.steps shows `failed`. The work
        // actually completed; only the two surfaces disagree. Acceptable.
        try {
          await markTimedOut(label, attemptStart, msg);
        } catch (markErr) {
          console.error(`[refresh] ${label}: markTimedOut failed`, markErr);
        }
      }
    }
  }

  await attempt("kev", (signal) => runKevIngest({ signal }));
  if (!options?.skipOsv) {
    for (const eco of ecosystems) {
      await attempt(`osv:${eco}`, (signal) => runOsvIngest(eco, { signal }));
    }
  }
  await attempt("epss", (signal) => runEpssIngest({ signal }));
  // NVD backfill runs last. It only touches CVEs that have no CVSS
  // score after OSV ingest, capped at 500/run to respect NVD's 5-req-
  // per-30-second anonymous quota (~55 min worst case). Even if this
  // hits the cap, the next refresh continues filling.
  await attempt("nvd", (signal) => runNvdIngest({ signal }));
  // Exploits backfill: only ~80ms latency per CVE, capped at 400/run.
  // Worst case ~80s of HTTP work, but in steady state most CVEs are
  // already mapped and we skip them via the LEFT JOIN filter.
  await attempt("exploits", (signal) => runExploitsIngest({ signal }));

  const finishedAt = new Date();
  return {
    startedAt,
    finishedAt,
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    steps,
  };
}
