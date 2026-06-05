/**
 * OSV bulk ingest (CLI).
 *
 * Source: https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
 *
 * This is the ops one-shot. Both this and the scheduler-driven
 * `src/lib/ingest/osv.ts` are thin wrappers around
 * `src/lib/ingest/osv-batch.ts::streamOsvDir`, so there's a single
 * source of truth for the parse → flush loop. The CLI deliberately
 * uses the **web pool** (no `statement_timeout`) because operators
 * running a backfill manually want to see full DB errors uncapped —
 * they're driving and can Ctrl-C if something hangs.
 *
 * Usage:
 *   pnpm ingest:osv -- --ecosystem=npm
 *   pnpm ingest:osv -- --ecosystem=PyPI,Maven
 */
import "./_shared";
import { fetch } from "undici";
import { createWriteStream, promises as fs } from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { db, pool } from "../../src/db/client";
import { streamOsvZip, type UpsertCtx } from "../../src/lib/ingest/osv-batch";

const BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com";

function canonicalizeEco(input: string): string {
  return input.split(":")[0];
}

function parseArgs() {
  const args = process.argv.slice(2);
  const ecos: string[] = [];
  for (const a of args) {
    const m = a.match(/^--ecosystem=(.+)$/);
    if (m) ecos.push(...m[1].split(",").map((s) => s.trim()).filter(Boolean));
  }
  if (ecos.length === 0) {
    console.error("usage: osv.ts --ecosystem=npm[,PyPI,Maven,Debian,Alpine,...]");
    process.exit(2);
  }
  return { ecos };
}

function classifyAlias(alias: string): string {
  const a = alias.toUpperCase();
  if (a.startsWith("GHSA-")) return "ghsa";
  if (a.startsWith("DSA-")) return "dsa";
  if (a.startsWith("DLA-")) return "dla";
  if (a.startsWith("DEBIAN-")) return "debian";
  if (a.startsWith("ALPINE-")) return "alpine";
  if (a.startsWith("RHSA-")) return "rhsa";
  if (a.startsWith("USN-")) return "usn";
  if (a.startsWith("GLSA-")) return "glsa";
  if (a.startsWith("SUSE-")) return "suse";
  if (a.startsWith("PYSEC-")) return "pysec";
  if (a.startsWith("RUSTSEC-")) return "rustsec";
  if (a.startsWith("GO-")) return "goadvisory";
  if (a.startsWith("OSV-")) return "osv-id";
  return "other";
}

async function downloadZipToFile(url: string, dest: string): Promise<void> {
  console.log(`[osv] downloading ${url}`);
  const res = await fetch(url);
  if (!res.ok || !res.body) throw new Error(`OSV fetch failed: ${res.status}`);
  await pipeline(Readable.fromWeb(res.body as never), createWriteStream(dest));
}

async function ingestEcosystem(ecoArg: string) {
  const eco = canonicalizeEco(ecoArg);
  const url = `${BASE_URL}/${encodeURIComponent(ecoArg)}/all.zip`;
  const work = await fs.mkdtemp(join(tmpdir(), "osv-"));
  const zipPath = join(work, "all.zip");
  try {
    await downloadZipToFile(url, zipPath);

    const ctx: UpsertCtx = {
      eco,
      ecoMatch: (recordEco) => canonicalizeEco(recordEco) === eco,
      pkgCache: new Map(),
    };
    const startTime = Date.now();
    const { processed, imported } = await streamOsvZip({
      ctx,
      zipPath,
      db,
      pool,
      classifyAlias,
      log: (msg) => console.log(msg),
      onChunk({ processed: p, imported: i, chunkIndex }) {
        // Periodic CLI progress — every 10 chunks (~500 records) so the
        // operator sees forward motion. streamOsvDir also logs rss every
        // 20 chunks, which is more telling for debugging.
        if (chunkIndex % 10 === 0) {
          process.stdout.write(`\r[osv:${eco}] chunk=${chunkIndex} processed=${p} imported=${i}    `);
        }
      },
    });
    const dt = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`\n[osv:${eco}] processed=${processed} imported=${imported} (${dt}s)`);
    return { eco, processed, imported };
  } finally {
    await fs.rm(work, { recursive: true, force: true }).catch(() => {});
  }
}

async function main() {
  const { ecos } = parseArgs();
  const results: { eco: string; processed: number; imported: number }[] = [];
  for (const e of ecos) {
    try {
      results.push(await ingestEcosystem(e));
    } catch (err) {
      console.error(`[osv:${e}] FAILED:`, err);
    }
  }
  console.log("---");
  for (const r of results) {
    console.log(`  ${r.eco.padEnd(15)} processed=${r.processed} imported=${r.imported}`);
  }
  const stats = await pool.query(
    `SELECT
       (SELECT COUNT(*)::int FROM vulnerabilities) AS vulns,
       (SELECT COUNT(*)::int FROM packages) AS pkgs,
       (SELECT COUNT(*)::int FROM affected) AS aff,
       (SELECT COUNT(*)::int FROM cvss_scores) AS cvss,
       (SELECT COUNT(*)::int FROM refs) AS refs`,
  );
  console.log(`DB now: ${JSON.stringify(stats.rows[0])}`);
  await pool.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
