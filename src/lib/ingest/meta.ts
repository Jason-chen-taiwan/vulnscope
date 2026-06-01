import "server-only";
import { pool } from "@/db/client";

/**
 * Tiny key/value store backed by the `meta_kv` table. We use it to
 * remember upstream identifiers (Last-Modified headers, score_date,
 * catalogVersion) so the next ingest run can skip the whole download
 * when nothing changed on the source side.
 *
 * Keys are namespaced like `osv:npm:last_modified`, `kev:catalog_version`,
 * `epss:score_date`. Values are opaque strings.
 */
export async function getMeta(key: string): Promise<string | null> {
  const { rows } = await pool.query<{ value: string | null }>(
    `SELECT value FROM meta_kv WHERE key = $1`,
    [key],
  );
  return rows[0]?.value ?? null;
}

export async function setMeta(key: string, value: string): Promise<void> {
  await pool.query(
    `INSERT INTO meta_kv (key, value, updated_at)
     VALUES ($1, $2, now())
     ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value,
            updated_at = now()`,
    [key, value],
  );
}
