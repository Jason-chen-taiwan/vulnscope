import { readFileSync } from "node:fs";
import type { Config } from "drizzle-kit";

// Minimal .env.local loader (avoids the dotenv package dependency).
function loadDotenv(path: string) {
  try {
    const txt = readFileSync(path, "utf8");
    for (const line of txt.split("\n")) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
    }
  } catch {
    /* ignore */
  }
}
loadDotenv(".env.local");

export default {
  schema: "./src/db/schema.ts",
  out: "./drizzle",
  dialect: "postgresql",
  dbCredentials: {
    url:
      process.env.DATABASE_URL ??
      "postgres://cvehub:cvehub@127.0.0.1:55432/cvehub",
  },
} satisfies Config;
