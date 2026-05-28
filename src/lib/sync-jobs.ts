import { pool } from "@/db/client";

export interface JobHandle {
  id: number;
  source: string;
  finish: (result: { changed?: number; seen?: number; error?: Error | null }) => Promise<void>;
}

export async function startJob(source: string): Promise<JobHandle> {
  const { rows } = await pool.query(
    `INSERT INTO sync_jobs (source, status) VALUES ($1, 'running') RETURNING id`,
    [source],
  );
  const id = rows[0].id as number;
  return {
    id,
    source,
    async finish({ changed, seen, error }) {
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
