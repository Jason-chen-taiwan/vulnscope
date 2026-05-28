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
    `INSERT INTO sync_jobs (source, status) VALUES ($1, 'running') RETURNING id`,
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
      await pool.query(
        `UPDATE sync_jobs SET records_seen = COALESCE($2, records_seen),
                              records_changed = COALESCE($3, records_changed)
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
      await pool.query(
        `UPDATE sync_jobs
            SET finished_at = now(),
                status = $2,
                records_seen = $3,
                records_changed = $4,
                error_message = $5
          WHERE id = $1`,
        [id, error ? "failed" : "success", seen ?? null, changed ?? null, error?.message ?? null],
      );
    },
  };
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

/** True if any ingest is currently in flight (status='running'). Useful
 *  for pages that want to auto-refresh while data is moving. */
export async function isIngestRunning(): Promise<boolean> {
  const { rows } = await pool.query(
    `SELECT 1 FROM sync_jobs WHERE status='running' LIMIT 1`,
  );
  return rows.length > 0;
}

export async function getFreshness(): Promise<{
  source: string;
  finished_at: Date | null;
  status: string;
}[]> {
  const { rows } = await pool.query(
    `SELECT DISTINCT ON (source) source, finished_at, status
       FROM sync_jobs
       WHERE finished_at IS NOT NULL
       ORDER BY source, finished_at DESC`,
  );
  return rows;
}
