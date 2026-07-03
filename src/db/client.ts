import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";
import { query as d1Query } from "./d1";

/**
 * Web-tier database client.
 *
 * After the Cloudflare migration the site's read path runs on Workers and
 * reads from D1 (SQLite), not Postgres. The many existing call sites use
 * `pool.query(sql, params)` and destructure `{ rows }`, so we keep that
 * exact surface but back it with the D1 shim (`src/db/d1.ts`). Only the SQL
 * dialect changed: `$1..$n` placeholders became D1's positional `?`.
 *
 * The generic `<T>` on `pool.query` mirrors the `pg` Pool signature that a
 * few call sites still spell out, e.g. `pool.query<{ n: number }>(...)`.
 */
export const pool = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  query: <T = any>(
    sql: string,
    params: unknown[] = [],
  ): Promise<{ rows: T[] }> => d1Query<T>(sql, params),
};

/**
 * Drizzle instance is retained only so the ingest/build tooling that still
 * imports `db`/`schema` continues to type-check. It is NOT used on the
 * Workers read path (queries.ts only references `db` in a `void` no-op to
 * suppress an unused-import lint). The Pool is created lazily and never
 * connects unless a drizzle query is actually issued, so importing this
 * module inside a Worker is side-effect-free.
 */
const connectionString =
  process.env.DATABASE_URL ??
  "postgres://vulnscope:vulnscope@127.0.0.1:55432/vulnscope";

let _db: ReturnType<typeof drizzle<typeof schema>> | undefined;
/**
 * Lazily-constructed Drizzle client. Building it (and the underlying `pg`
 * Pool) is deferred until first use so that merely importing this module on
 * Workers — where `queries.ts` only touches `db` in a `void` no-op — never
 * instantiates a Postgres connection.
 */
export const db = new Proxy({} as ReturnType<typeof drizzle<typeof schema>>, {
  get(_target, prop) {
    if (!_db) {
      const pgPool = new Pool({ connectionString, max: 10 });
      _db = drizzle(pgPool, { schema });
    }
    return Reflect.get(_db as object, prop);
  },
});
export { schema };
