/**
 * Dedicated pg pool for ingest jobs.
 *
 * Separate from the web pool (src/db/client.ts) so the two have
 * different SLOs:
 *
 *   web pool:    no statement_timeout, max 10 connections — long search
 *                queries and dashboard SSR are fine to take their time
 *   ingest pool: 5min statement_timeout, max 3 connections, 30s connect
 *                timeout — a single hot ingest can't drown the web pool,
 *                and a stuck pg query gets killed server-side. 60s
 *                wasn't enough once vulnerabilities had GIN+trgm
 *                indexes; a 1000-row INSERT with ON CONFLICT DO UPDATE
 *                hits index maintenance that legitimately needs 60-120s
 *                on Fly shared CPU under contention.
 *
 * Topology note: `statement_timeout` is sent as a Postgres startup
 * parameter on each connection. That works against a direct Postgres
 * server (Fly `<app>-db.internal:5432` is direct). It would NOT work
 * behind pgbouncer in transaction-pooling mode, which strips startup
 * parameters. If we ever migrate to Neon/Supabase with a pooler, the
 * timeout would silently no-op — switch to per-query `SET LOCAL
 * statement_timeout` inside an explicit transaction at that point.
 *
 * ensure-schema caveat: this pool is also used for schema bootstrap.
 * A future `CREATE INDEX CONCURRENTLY` or backfill on a 2M+ row table
 * would exceed 60s — run those ops via the web pool, or temporarily
 * lift the cap with a `SET LOCAL statement_timeout` inside a tx.
 */
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";

const connectionString =
  process.env.DATABASE_URL ??
  "postgres://vulnscope:vulnscope@127.0.0.1:55432/vulnscope";

declare global {
  // eslint-disable-next-line no-var
  var __pgIngestPool: Pool | undefined;
}

export const ingestPool =
  globalThis.__pgIngestPool ??
  new Pool({
    connectionString,
    max: 3,
    statement_timeout: 300_000,
    connectionTimeoutMillis: 30_000,
    application_name: "vulnscope-ingest",
  });

if (process.env.NODE_ENV !== "production") {
  globalThis.__pgIngestPool = ingestPool;
}

export const ingestDb = drizzle(ingestPool, { schema });
