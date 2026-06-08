import "server-only";
import { ingestPool as pool } from "@/db/ingest-pool";

/**
 * Self-healing schema migrations for ingest-side tables.
 *
 * Background: this repo's migration story is half-manual — drizzle-kit
 * generates SQL into drizzle/, then somebody runs `pnpm db:migrate` by
 * hand. There's no startup migration runner in the Dockerfile, so a
 * fresh deploy of new schema would fail until someone SSHed in.
 *
 * For *ingest-internal* tables (aliases, future tables) we don't need
 * the drizzle journal — we just need the table to exist before the
 * first INSERT. Running `CREATE TABLE IF NOT EXISTS` at the start of
 * each ingest is cheap (one round-trip when the table exists) and
 * makes new ingest features self-deploying.
 *
 * Schema changes that touch *existing* tables (rename column, drop
 * column) still need a real migration — those are rare and dangerous
 * enough that doing them by hand is correct.
 */
let ensured = false;

// Arbitrary 64-bit id, picked once. pg_advisory_lock serializes the
// CREATE TABLE block across all processes/connections so two parallel
// ingests can't race the same DDL — pg's "CREATE TABLE IF NOT EXISTS"
// is not atomic at the catalog level and the loser can hit
// "duplicate key value violates unique constraint pg_type_typname_nsp_index"
// (observed in postgres.log 2026-06-05 09:23:27 when a doubled scheduler
// fired two osv ingests concurrently).
const ENSURE_SCHEMA_LOCK_ID = "8675309";

export async function ensureIngestSchema(): Promise<void> {
  if (ensured) return;
  const client = await pool.connect();
  try {
    await client.query(`SELECT pg_advisory_lock(${ENSURE_SCHEMA_LOCK_ID})`);
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS vuln_aliases (
          cve_id text NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
          alias  text NOT NULL,
          source text NOT NULL,
          PRIMARY KEY (cve_id, alias)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS uq_vuln_aliases_alias ON vuln_aliases(alias);
        CREATE INDEX IF NOT EXISTS idx_vuln_aliases_cve ON vuln_aliases(cve_id);
        ALTER TABLE sync_jobs ADD COLUMN IF NOT EXISTS last_heartbeat_at timestamptz;
      `);
    } finally {
      await client.query(`SELECT pg_advisory_unlock(${ENSURE_SCHEMA_LOCK_ID})`);
    }
  } finally {
    client.release();
  }
  ensured = true;
}
