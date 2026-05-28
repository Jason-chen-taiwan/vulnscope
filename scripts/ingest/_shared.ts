import { readFileSync } from "node:fs";

// Load .env.local before db client imports so DATABASE_URL is set.
export function loadEnv() {
  try {
    const txt = readFileSync(".env.local", "utf8");
    for (const line of txt.split("\n")) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
    }
  } catch {
    /* ignore */
  }
}
loadEnv();

export function logProgress(label: string, n: number, total?: number) {
  if (total) process.stdout.write(`\r[${label}] ${n}/${total}        `);
  else process.stdout.write(`\r[${label}] ${n}            `);
}

export function done(label: string) {
  process.stdout.write(`\r[${label}] done\n`);
}

export function parseDate(s: string | undefined | null): Date | null {
  if (!s) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}
