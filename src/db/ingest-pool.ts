/**
 * Dedicated pg pool for ingest jobs.
 *
 * Separate from the web pool (src/db/client.ts) so the two have
 * different SLOs:
 *
 *   web pool:    no statement_timeout, max 10 connections — long search
 *                queries and dashboard SSR are fine to take their time
 *   ingest pool: 5min statement_timeout, max 2 connections, 30s connect
 *                timeout — a single hot ingest can't drown the web pool,
 *                and a stuck pg query gets killed server-side. 60s
 *                wasn't enough once vulnerabilities had GIN+trgm
 *                indexes; a 1000-row INSERT with ON CONFLICT DO UPDATE
 *                hits index maintenance that legitimately needs 60-120s
 *                on Fly shared CPU under contention.
 *
 *                Lowered from 3 → 2 (2026-06-08): observed homepage's
 *                6 parallel getTopPackages queries stacking up at the
 *                pg connection slot during ingest. Leaving 1 extra
 *                slot for web SSR is more important than the marginal
 *                ingest throughput gain from a 3rd ingest connection.
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
    max: 2,
    statement_timeout: 300_000,
    connectionTimeoutMillis: 30_000,
    application_name: "vulnscope-ingest",
    // Send a TCP keepalive every ~10s. Fly Postgres closes truly idle
    // connections silently; a keepalive packet keeps the kernel-level
    // socket alive between INSERTs (one parse chunk can be 5-30s
    // depending on ecosystem). Combined with the pool 'error' handler
    // below this means a server-side drop just removes one client from
    // the pool — the next query gets a fresh one — instead of taking
    // down the whole Node process.
    keepAlive: true,
    keepAliveInitialDelayMillis: 10_000,
  });

// See src/db/client.ts for why this listener is mandatory. Same story
// here: an idle ingest connection dropped by Fly Postgres maintenance
// would otherwise crash the process via uncaughtException and take
// every in-flight source down with it.
if (!globalThis.__pgIngestPool) {
  ingestPool.on("error", (err) => {
    console.error("[ingest pool] idle client error:", err.message);
  });
}

if (process.env.NODE_ENV !== "production") {
  globalThis.__pgIngestPool = ingestPool;
}

export const ingestDb = drizzle(ingestPool, { schema });
