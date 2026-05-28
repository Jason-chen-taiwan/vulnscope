import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";

const connectionString =
  process.env.DATABASE_URL ??
  "postgres://cvehub:cvehub@127.0.0.1:55432/cvehub";

declare global {
  // eslint-disable-next-line no-var
  var __pgPool: Pool | undefined;
}

export const pool =
  globalThis.__pgPool ??
  new Pool({ connectionString, max: 10 });

if (process.env.NODE_ENV !== "production") {
  globalThis.__pgPool = pool;
}

export const db = drizzle(pool, { schema });
export { schema };
