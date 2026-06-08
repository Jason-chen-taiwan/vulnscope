import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";

const connectionString =
  process.env.DATABASE_URL ??
  "postgres://vulnscope:vulnscope@127.0.0.1:55432/vulnscope";

declare global {
  // eslint-disable-next-line no-var
  var __pgPool: Pool | undefined;
}

export const pool =
  globalThis.__pgPool ??
  new Pool({ connectionString, max: 10 });

// CRITICAL: pg Pool emits 'error' when an idle client's connection is
// terminated by the server (Fly Postgres maintenance, idle timeouts,
// failover). With no listener, Node escalates it to uncaughtException
// and kills the whole process — observed 2026-06-08 02:16:13, which
// took down 15 in-flight ingests at once and crashed the refresh.
// The 'error' event is informational; pg drops the dead client from
// the pool on its own. We just need to acknowledge.
if (!globalThis.__pgPool) {
  pool.on("error", (err) => {
    console.error("[web pool] idle client error:", err.message);
  });
}

if (process.env.NODE_ENV !== "production") {
  globalThis.__pgPool = pool;
}

export const db = drizzle(pool, { schema });
export { schema };
