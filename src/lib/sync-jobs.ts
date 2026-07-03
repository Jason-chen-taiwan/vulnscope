import { pool } from "@/db/client";

export interface JobHandle {
  id: number;
  source: string;
  /** Live progress update — call as records stream in. Fire-and-forget. */
  progress: (counts: { seen?: number; changed?: number }) => void;
  finish: (result: { changed?: number; seen?: number; error?: Error | null }) => Promise<void>;
}

export async function startJob(source: string): Promise<JobHandle> {
  const { rows } = await pool.query(
    `INSERT INTO sync_jobs (source, status, last_heartbeat_at)
       VALUES ($1, 'running', now()) RETURNING id`,
    [source],
  );
  const id = rows[0].id as number;

  // Progress UPDATEs at ingest hot-path frequency would flood the DB. We
  // coalesce them: at most one UPDATE per second, and only the latest
  // counts get flushed.
  let pendingSeen: number | null = null;
  let pendingChanged: number | null = null;
  let flushing = false;
  let lastFlush = 0;
  const FLUSH_INTERVAL_MS = 1000;

  async function flush() {
    if (flushing) return;
    if (pendingSeen === null && pendingChanged === null) return;
    flushing = true;
    const s = pendingSeen;
    const c = pendingChanged;
    pendingSeen = null;
    pendingChanged = null;
    try {
      // Heartbeat lands on every flush so the reaper can use a tight
      // "no heartbeat for N minutes" threshold instead of trusting
      // started_at alone (which can't tell hung-on-download apart from
      // a legitimately long ingest).
      await pool.query(
        `UPDATE sync_jobs SET records_seen = COALESCE($2, records_seen),
                              records_changed = COALESCE($3, records_changed),
                              last_heartbeat_at = now()
          WHERE id = $1`,
        [id, s, c],
      );
      lastFlush = Date.now();
    } catch {
      /* progress UPDATEs are best-effort */
    } finally {
      flushing = false;
    }
  }

  return {
    id,
    source,
    progress({ seen, changed }) {
      if (seen !== undefined) pendingSeen = seen;
      if (changed !== undefined) pendingChanged = changed;
      if (Date.now() - lastFlush >= FLUSH_INTERVAL_MS) void flush();
    },
    async finish({ changed, seen, error }) {
      // Final flush of pending counts before status transition.
      // The `status='running'` guard is first-write-wins: if the
      // orchestrator already marked this row failed via markTimedOut()
      // (zombie case), we no-op here instead of clobbering its decision.
      await pool.query(
        `UPDATE sync_jobs
            SET finished_at = now(),
                status = $2,
                records_seen = $3,
                records_changed = $4,
                error_message = $5
          WHERE id = $1 AND status = 'running'`,
        [id, error ? "failed" : "success", seen ?? null, changed ?? null, error?.message ?? null],
      );
    },
  };
}

/**
 * Mark an in-flight `running` row as `failed` from the outside (i.e.
 * the orchestrator decided this source timed out, but the source's
 * own JobHandle is held by a zombie task that won't return).
 *
 * Uses the web pool deliberately. The timeout case is exactly when
 * the ingest pool is most likely starved (zombie holding its 3 slots),
 * so going via the web pool ensures the failure marker actually lands.
 *
 * The `started_at >= since` predicate ensures we only touch the row
 * for the current attempt, not an unrelated older zombie that's still
 * `running` for legitimate reasons.
 *
 * The orchestrator's matching `markTimedOut` call runs FIRST in normal
 * cases. If a zombie races ahead and calls finish() between our
 * setTimeout firing and this UPDATE landing, the row will already be
 * `success` (or `failed` with the source's own error) — and our WHERE
 * matches 0 rows. Harmless: see "cosmetic race" comment in
 * orchestrator.ts. The work actually completed; only RefreshResult's
 * record of it disagrees.
 */
export async function markTimedOut(
  source: string,
  since: Date,
  message: string,
): Promise<void> {
  await pool.query(
    `UPDATE sync_jobs
        SET status = 'failed',
            finished_at = now(),
            error_message = $3
      WHERE source = $1
        AND status = 'running'
        AND started_at >= $2`,
    [source, since, message],
  );
}

export async function getRecentSyncJobs(limit = 50) {
  const { rows } = await pool.query(
    `SELECT id, source, started_at, finished_at, status,
            records_seen, records_changed, error_message
       FROM sync_jobs
       ORDER BY started_at DESC
       LIMIT $1`,
    [limit],
  );
  return rows;
}

export async function getLastSuccessfulRun(source: string): Promise<Date | null> {
  const { rows } = await pool.query(
    `SELECT finished_at FROM sync_jobs
      WHERE source = $1 AND status = 'success'
      ORDER BY finished_at DESC LIMIT 1`,
    [source],
  );
  return rows[0]?.finished_at ?? null;
}

// Short in-memory caches for the two homepage SSR calls. These were the
// only un-cached DB queries on /[locale]/page.tsx after ac38c88 — every
// homepage render hit sync_jobs twice. During ingest, sync_jobs is the
// busiest write target, so even these cheap SELECTs were stacking up
// behind row-level locks and contributing to the intermittent 503s.
// 10s TTL keeps "ingest in flight" indicator responsive (worst case the
// running badge appears 10s late) while removing per-pageview DB load.
let isIngestRunningCache: { at: number; value: boolean } | null = null;
let freshnessCache: { at: number; value: { source: string; finished_at: Date | null; status: string }[] } | null = null;
const SYNC_JOBS_CACHE_TTL_MS = 10_000;

/** True if any ingest is currently in flight (status='running'). Useful
 *  for pages that want to auto-refresh while data is moving. */
export async function isIngestRunning(): Promise<boolean> {
  const now = Date.now();
  if (isIngestRunningCache && now - isIngestRunningCache.at < SYNC_JOBS_CACHE_TTL_MS) {
    return isIngestRunningCache.value;
  }
  // Defensive: on a cold-start / empty D1 the sync_jobs read must never
  // 500 the (force-dynamic) homepage. Any failure resolves to a safe
  // "not running" default. SQL is already SQLite-compatible (no $n,
  // no Postgres-only syntax).
  try {
    const { rows } = await pool.query(
      `SELECT 1 FROM sync_jobs WHERE status='running' LIMIT 1`,
    );
    const value = rows.length > 0;
    isIngestRunningCache = { at: now, value };
    return value;
  } catch (err) {
    console.error("[sync-jobs] isIngestRunning failed, defaulting to false", err);
    return false;
  }
}

export async function getFreshness(): Promise<{
  source: string;
  finished_at: Date | null;
  status: string;
}[]> {
  const now = Date.now();
  if (freshnessCache && now - freshnessCache.at < SYNC_JOBS_CACHE_TTL_MS) {
    return freshnessCache.value;
  }
  // SQLite/D1 has no `DISTINCT ON`. To reproduce Postgres's "latest
  // finished row per source" we pick, per source, the row whose
  // finished_at is the group MAX. GROUP BY on the non-aggregated
  // `status` uses SQLite's bare-column rule: the value comes from the
  // row that supplied MAX(finished_at) (SQLite documents this for a
  // single MAX/MIN in the query), giving the same shape the homepage
  // consumes: one { source, finished_at, status } per source.
  //
  // Defensive: on a cold-start / empty-or-missing sync_jobs table this
  // must never 500 the homepage — any failure resolves to an empty list
  // (which FreshnessLine renders as the "no data yet" state).
  try {
    const { rows } = await pool.query<{
      source: string;
      finished_at: Date | null;
      status: string;
    }>(
      `SELECT source, MAX(finished_at) AS finished_at, status
         FROM sync_jobs
        WHERE finished_at IS NOT NULL
        GROUP BY source`,
    );
    freshnessCache = { at: now, value: rows };
    return rows;
  } catch (err) {
    console.error("[sync-jobs] getFreshness failed, defaulting to []", err);
    return [];
  }
}
