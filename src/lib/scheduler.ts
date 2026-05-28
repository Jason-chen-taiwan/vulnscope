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
 * Skip criteria: a "refresh" sentinel row marked success less than
 * half the refresh interval ago. We write that row after every full
 * orchestrator run completes (regardless of which sources individually
 * failed) so the dedupe is a single, cheap query.
 */
async function shouldSkipScheduled(): Promise<string | null> {
  if (globalThis.__vulnscope_refresh_in_flight) return "previous refresh still in flight";
  try {
    const pool = await getPool();
    const halfWindow = Math.floor(REFRESH_INTERVAL_MS / 2 / 1000);
    const { rows } = await pool.query(
      `SELECT 1 FROM sync_jobs
        WHERE source = 'refresh' AND status = 'success'
          AND finished_at > now() - ($1 || ' seconds')::interval
        LIMIT 1`,
      [String(halfWindow)],
    );
    if (rows.length > 0) return `full refresh completed within last ${halfWindow}s`;
  } catch {
    // DB issues will surface via runFullRefresh's own error handling.
  }
  return null;
}

async function reapStaleJobs() {
  // Only reap jobs that are genuinely stuck — i.e. older than a full
  // OSV ingest could legitimately take. The slowest single ingest in
  // practice (OSV npm) is ~5 minutes; the orchestrator's full run is
  // ~30 minutes. Anything still 'running' after 2 hours is dead.
  //
  // Earlier this was 30 minutes which mis-reaped legitimate in-flight
  // ingests when fly secrets changes caused machine restarts.
  try {
    const pool = await getPool();
    await pool.query(
      `UPDATE sync_jobs
          SET status = 'failed',
              finished_at = now(),
              error_message = COALESCE(error_message, 'reaped: stale running job on boot')
        WHERE status = 'running'
          AND started_at < now() - interval '2 hours'`,
    );
  } catch {
    /* ignore — DB might not be ready yet */
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

  void reapStaleJobs();
  // Stagger the first run so a fresh `pnpm dev` doesn't immediately spike CPU.
  setTimeout(() => {
    void tick();
    setInterval(() => void tick(), REFRESH_INTERVAL_MS);
  }, STARTUP_DELAY_MS);
}

export async function tick(opts?: { manual?: boolean }): Promise<void> {
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
    globalThis.__vulnscope_refresh_in_flight = false;
  }
}
