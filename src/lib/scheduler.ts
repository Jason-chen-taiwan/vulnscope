import "server-only";
import { runFullRefresh } from "./ingest/orchestrator";

// Lazy pool accessor avoids a circular import when this module is loaded
// from db/client via a boot side-effect.
async function getPool() {
  const mod = await import("@/db/client");
  return mod.pool;
}

/**
 * In-process daily refresh scheduler.
 *
 * Why in-process instead of cron / systemd / GitHub Actions:
 *   - A self-hostable CVE tool that needs daily data shouldn't make the
 *     operator set up out-of-band cron just to stay correct.
 *   - The Next.js server is always-on in any sane deployment.
 *   - In dev, we'd rather have stale-by-default and explicit refresh.
 *
 * Boots once per server process via `instrumentation.ts`. Idempotent: a
 * second invocation in the same process is a no-op.
 *
 * Disable via `SCHEDULER_DISABLED=1` env (useful for dev, tests, CI).
 */
const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24h
const STARTUP_DELAY_MS = 10 * 1000; // wait 10s after boot before first run
const REAPER_INTERVAL_MS = 10 * 60 * 1000; // sweep stale running jobs every 10 min

declare global {
  // eslint-disable-next-line no-var
  var __vulnscope_scheduler_started: boolean | undefined;
  // eslint-disable-next-line no-var
  var __vulnscope_refresh_in_flight: boolean | undefined;
}

/**
 * Whether the scheduled tick should skip this round.
 * Only used by the automatic timer; manual /api/v1/admin/refresh always runs.
 *
 * Two skip conditions:
 *   1. Another 'refresh' row is currently `running` and was started
 *      within the last 2 hours. Catches the "fly machine restarted
 *      mid-ingest and now both the new and old refresh are racing"
 *      case (the original cause of multiple refresh rows piling up).
 *   2. A 'refresh' marked `success` within the half-interval window.
 *      The normal "we just refreshed, don't run again so soon" path.
 */
async function shouldSkipScheduled(): Promise<string | null> {
  if (globalThis.__vulnscope_refresh_in_flight) return "previous refresh still in flight";
  try {
    const pool = await getPool();

    // (1) A live in-flight refresh — even from a previous process. Anything
    // older than 2 hours is treated as dead (matches reaper threshold below).
    const live = await pool.query(
      `SELECT 1 FROM sync_jobs
        WHERE source = 'refresh' AND status = 'running'
          AND started_at > now() - interval '2 hours'
        LIMIT 1`,
    );
    if (live.rows.length > 0) return "another refresh is already in flight";

    // (2) Recently finished refresh.
    const halfWindow = Math.floor(REFRESH_INTERVAL_MS / 2 / 1000);
    const recent = await pool.query(
      `SELECT 1 FROM sync_jobs
        WHERE source = 'refresh' AND status = 'success'
          AND finished_at > now() - ($1 || ' seconds')::interval
        LIMIT 1`,
      [String(halfWindow)],
    );
    if (recent.rows.length > 0) return `full refresh completed within last ${halfWindow}s`;
  } catch {
    // DB issues will surface via runFullRefresh's own error handling.
  }
  return null;
}

async function reapStaleJobs() {
  // Heartbeat-based reaper. Each ingest writes last_heartbeat_at on
  // startJob() and on every progress() flush (~once/sec during hot
  // parse), so "no heartbeat for >5min" is a tight, source-agnostic
  // signal that the worker died. This replaces the prior 2h started_at
  // threshold, which had two failure modes:
  //   1. Ingests that hung silently before the first progress() call
  //      (e.g. download stalled — actual 2026-06-05 osv:npm incident)
  //      sat at status='running' for hours before getting reaped.
  //   2. The reaper itself runs from a live Node process via setInterval.
  //      When the process died mid-ingest, no one was around to run it,
  //      so orphan rows persisted until the next manual server boot.
  //   We can't fix (2) without an external cron, but a tighter threshold
  //   means the orphan window on next boot is bounded by minutes not hours.
  // COALESCE handles pre-migration rows whose heartbeat is NULL.
  try {
    const pool = await getPool();
    // Two reaper passes. The refresh row and child rows have different
    // liveness signals so they need different thresholds.
    //
    //  - **child sources** (kev, osv:*, epss, nvd, exploits) write
    //    last_heartbeat_at every flush (~1/sec during a hot ingest).
    //    Threshold: 5 min without a heartbeat → reap.
    //
    //  - **refresh** is the orchestrator wrapper that holds open while
    //    child ingests run; it doesn't write its own heartbeat, so the
    //    5 min signal would misfire whenever a single child took longer
    //    than 5 min. tick()'s in-process 3 h watchdog clears the in-
    //    flight flag, but if the Node process dies the watchdog never
    //    fires and the row stays `running` forever — observed in
    //    production 2026-06-08 (three stuck refresh rows from 2-3.5h
    //    ago that made shouldSkipScheduled() refuse every subsequent
    //    tick because they still looked "in flight"). Threshold: 3 h
    //    since started_at → reap. Matches the watchdog so DB state and
    //    process state agree.
    await pool.query(
      `UPDATE sync_jobs
          SET status = 'failed',
              finished_at = now(),
              error_message = COALESCE(error_message, 'reaped: no heartbeat for >5min')
        WHERE status = 'running'
          AND source <> 'refresh'
          AND COALESCE(last_heartbeat_at, started_at) < now() - interval '5 minutes'`,
    );
    await pool.query(
      `UPDATE sync_jobs
          SET status = 'failed',
              finished_at = now(),
              error_message = COALESCE(error_message, 'reaped: refresh exceeded 3h watchdog')
        WHERE status = 'running'
          AND source = 'refresh'
          AND started_at < now() - interval '3 hours'`,
    );
  } catch {
    /* ignore — DB might not be ready yet */
  }
}

/**
 * One-shot, boot-time cleanup of orphaned `refresh` rows. See
 * startScheduler() for the rationale. Separate from reapStaleJobs()
 * because the threshold logic differs: at boot we have proof the
 * old refresh is dead (the in-memory flag just reset), so age
 * doesn't matter. Periodic reaper still uses the 3h threshold
 * because mid-run it can't tell a live refresh apart from a stuck
 * one without that grace period.
 */
async function clearOrphanedRefreshesOnBoot() {
  try {
    const pool = await getPool();
    await pool.query(
      `UPDATE sync_jobs
          SET status = 'failed',
              finished_at = now(),
              error_message = COALESCE(error_message, 'reaped: orphaned across worker restart')
        WHERE status = 'running' AND source = 'refresh'`,
    );
  } catch {
    /* ignore */
  }
}

export function startScheduler() {
  if (process.env.SCHEDULER_DISABLED === "1") {
    console.log("[scheduler] disabled via SCHEDULER_DISABLED=1");
    return;
  }
  if (globalThis.__vulnscope_scheduler_started) return;
  globalThis.__vulnscope_scheduler_started = true;

  const intervalH = REFRESH_INTERVAL_MS / 3600 / 1000;
  console.log(`[scheduler] daily refresh active (every ${intervalH}h, first run in ${STARTUP_DELAY_MS / 1000}s)`);

  // On boot, do an aggressive sweep: any refresh row left in `running`
  // is an orphan by definition because the in-process flag
  // (__vulnscope_refresh_in_flight) lives in memory and was just reset
  // when the worker started. Without this, after a worker crash /
  // deploy the next tick sees the old refresh row, shouldSkipScheduled
  // returns "another refresh is already in flight" forever, and the
  // dashboard fills up — observed 2026-06-08 with three stuck rows
  // accumulating across restarts. The periodic reaper afterwards uses
  // the standard 3h threshold; this one-shot boot cleanup uses no age
  // threshold because the boot itself is the evidence of orphanhood.
  void reapStaleJobs();
  void clearOrphanedRefreshesOnBoot();
  setInterval(() => void reapStaleJobs(), REAPER_INTERVAL_MS);
  // Stagger the first run so a fresh `pnpm dev` doesn't immediately spike CPU.
  setTimeout(() => {
    void tick();
    setInterval(() => void tick(), REFRESH_INTERVAL_MS);
  }, STARTUP_DELAY_MS);
}

export async function tick(opts?: { manual?: boolean }): Promise<void> {
  // Sweep orphans before each tick so manual /api/v1/admin/refresh calls
  // (and the auto timer) start from a clean slate even if the prior
  // server process died without clearing its rows.
  await reapStaleJobs();
  if (!opts?.manual) {
    const reason = await shouldSkipScheduled();
    if (reason) {
      console.log(`[scheduler] skipping refresh: ${reason}`);
      return;
    }
  }
  if (globalThis.__vulnscope_refresh_in_flight) {
    console.log("[scheduler] refresh already in flight; not starting another");
    return;
  }
  globalThis.__vulnscope_refresh_in_flight = true;
  const pool = await getPool();
  const { rows } = await pool.query(
    `INSERT INTO sync_jobs (source, status) VALUES ('refresh', 'running') RETURNING id`,
  );
  const refreshJobId = rows[0].id as number;
  // Defense-in-depth: even if every individual ingest's timeout fails,
  // the whole refresh is bounded so the in-flight flag and sync_jobs row
  // are always reset. 3 hours is well above the longest legitimate run
  // (~2 hours for Debian + npm under load).
  const REFRESH_HARD_TIMEOUT_MS = 3 * 60 * 60 * 1000;
  let watchdog: NodeJS.Timeout | null = setTimeout(() => {
    console.error(`[scheduler] refresh exceeded ${REFRESH_HARD_TIMEOUT_MS / 1000}s — releasing in-flight flag`);
    globalThis.__vulnscope_refresh_in_flight = false;
    pool.query(
      `UPDATE sync_jobs SET finished_at=now(), status='failed',
                            error_message='watchdog: orchestrator exceeded hard timeout'
        WHERE id=$1 AND status='running'`,
      [refreshJobId],
    ).catch(() => {});
  }, REFRESH_HARD_TIMEOUT_MS);
  try {
    const r = await runFullRefresh();
    const failed = r.steps.filter((s) => !s.ok);
    console.log(
      `[scheduler] refresh done in ${(r.durationMs / 1000).toFixed(1)}s — ` +
        `${r.steps.length - failed.length}/${r.steps.length} sources ok` +
        (failed.length ? `, failed: ${failed.map((f) => f.source).join(", ")}` : ""),
    );
    await pool.query(
      `UPDATE sync_jobs
          SET finished_at = now(),
              status = $2,
              records_seen = $3,
              records_changed = $4,
              error_message = $5
        WHERE id = $1`,
      [
        refreshJobId,
        failed.length === 0 ? "success" : failed.length === r.steps.length ? "failed" : "success",
        r.steps.reduce((a, s) => a + (s.seen ?? 0), 0),
        r.steps.reduce((a, s) => a + (s.changed ?? 0), 0),
        failed.length ? `failed sources: ${failed.map((f) => f.source).join(", ")}` : null,
      ],
    );
  } catch (e) {
    console.error("[scheduler] refresh crashed:", e);
    await pool.query(
      `UPDATE sync_jobs SET finished_at=now(), status='failed', error_message=$2 WHERE id=$1`,
      [refreshJobId, (e as Error).message],
    );
  } finally {
    if (watchdog) clearTimeout(watchdog);
    watchdog = null;
    globalThis.__vulnscope_refresh_in_flight = false;
  }
}
