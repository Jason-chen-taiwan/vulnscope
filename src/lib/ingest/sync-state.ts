/**
 * Per-source ingest watermark stored in a `sync_state` table.
 *
 * Used by the incremental OSV build to remember, per ecosystem, the newest
 * `modified` timestamp it has already ingested. The row is written into the
 * incremental SQLite and pushed to D1 by push-to-d1.sh (delta mode), so the
 * watermark advance is atomic with the data push.
 *
 * source key convention: `osv:<eco>` (e.g. `osv:npm`).
 */
import type Database from "better-sqlite3";

export const SYNC_STATE_DDL = `CREATE TABLE IF NOT EXISTS sync_state (
  source TEXT PRIMARY KEY,
  last_modified TEXT,
  updated_at TEXT
)`;

export function readWatermark(
  db: Database.Database,
  source: string,
): string | null {
  const row = db
    .prepare("SELECT last_modified FROM sync_state WHERE source = ?")
    .get(source) as { last_modified: string | null } | undefined;
  return row?.last_modified ?? null;
}

export function writeWatermark(
  db: Database.Database,
  source: string,
  lastModified: string,
  updatedAt: string,
): void {
  db.prepare(
    `INSERT INTO sync_state (source, last_modified, updated_at)
     VALUES (@source, @lastModified, @updatedAt)
     ON CONFLICT (source) DO UPDATE SET
       last_modified = excluded.last_modified,
       updated_at    = excluded.updated_at`,
  ).run({ source, lastModified, updatedAt });
}
