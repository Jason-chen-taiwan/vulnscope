import "server-only";
import { getCloudflareContext } from "@opennextjs/cloudflare";
import type { D1Database } from "@cloudflare/workers-types";

/**
 * D1 query shim.
 *
 * The web tier used to talk to Postgres via a `pg` Pool whose call sites
 * all look like `pool.query(sql, params)` and read back `{ rows }`. On
 * Cloudflare Workers there is no pg — reads go to a D1 database bound as
 * `env.DB`. This helper preserves the exact `{ rows }` return shape so the
 * ~30 existing call sites in queries.ts / insights.ts keep working with a
 * one-line import swap; the only SQL-level change is Postgres `$1..$n`
 * placeholders become D1's positional `?`.
 *
 * `getCloudflareContext()` is provided by OpenNext's Cloudflare adapter and
 * exposes the Worker's bindings (`env`) from inside any request-scoped
 * Next.js server code.
 */
// The generic defaults to `any` (not `Record<string, unknown>`) to mirror
// the `pg` Pool's `QueryResult<any>`, so the many untyped `pool.query(...)`
// call sites keep compiling with row access like `rows[0].cve_id`.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function query<T = any>(
  sql: string,
  params: unknown[] = [],
): Promise<{ rows: T[] }> {
  const { env } = getCloudflareContext();
  const db = (env as unknown as { DB: D1Database }).DB;
  const stmt = db.prepare(sql).bind(...(params as unknown[]));
  const result = await stmt.all<T>();
  return { rows: result.results ?? [] };
}
