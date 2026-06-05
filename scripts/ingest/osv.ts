/**
 * OSV bulk ingest (CLI).
 *
 * Source: https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
 *
 * This is the ops one-shot. The scheduler uses `src/lib/ingest/osv.ts`
 * which shares the same buffer/flush core via `src/lib/ingest/osv-batch.ts`.
 *
 * The CLI deliberately uses the **web pool** (no `statement_timeout`)
 * because operators running a backfill manually want to see full DB
 * errors uncapped — they're driving and can Ctrl-C if something hangs.
 *
 * Usage:
 *   pnpm ingest:osv -- --ecosystem=npm
 *   pnpm ingest:osv -- --ecosystem=PyPI,Maven
 */
import "./_shared";
import { fetch } from "undici";
import pLimit from "p-limit";
import { createWriteStream, promises as fs } from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { db, pool } from "../../src/db/client";
import { osvRecordSchema } from "../../src/lib/osv";
import {
  bufferRecord,
  emptyBuffers,
  flush,
  maybeTrimPkgCache,
  CHUNK_RECORDS,
  type Buffers,
  type UpsertCtx,
} from "../../src/lib/ingest/osv-batch";
import { logProgress } from "./_shared";

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

async function downloadZipToFile(url: string, dest: string): Promise<void> {
  console.log(`[osv] downloading ${url}`);
  const res = await fetch(url);
  if (!res.ok || !res.body) throw new Error(`OSV fetch failed: ${res.status}`);
  await pipeline(Readable.fromWeb(res.body as never), createWriteStream(dest));
}

async function extractZip(zipPath: string, destDir: string): Promise<void> {
  await fs.mkdir(destDir, { recursive: true });
  await new Promise<void>((resolve, reject) => {
    const child = spawn("unzip", ["-q", "-o", zipPath, "-d", destDir], { stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`unzip exited ${code}`))));
  });
}

async function ingestEcosystem(ecoArg: string) {
  const eco = canonicalizeEco(ecoArg);
  const url = `${BASE_URL}/${encodeURIComponent(ecoArg)}/all.zip`;
  const work = await fs.mkdtemp(join(tmpdir(), "osv-"));
  const zipPath = join(work, "all.zip");
  const extractDir = join(work, "json");
  try {
    await downloadZipToFile(url, zipPath);
    console.log(`[osv:${eco}] extracting…`);
    await extractZip(zipPath, extractDir);
    await fs.unlink(zipPath).catch(() => {});

    const files = (await fs.readdir(extractDir)).filter((f) => f.endsWith(".json"));
    console.log(`[osv:${eco}] ${files.length} JSON records on disk`);

    const ctx: UpsertCtx = {
      eco,
      ecoMatch: (recordEco) => canonicalizeEco(recordEco) === eco,
      pkgCache: new Map(),
    };
    const limit = pLimit(6);
    let processed = 0;
    let imported = 0;
    let skipped = 0;
    let errored = 0;
    const startTime = Date.now();

    const PARSE_CHUNK = 200;
    let buf: Buffers = emptyBuffers();

    async function maybeFlush(force: boolean) {
      if (force || buf.recordsBuffered >= CHUNK_RECORDS) {
        if (buf.vulns.length || buf.aliases.length) {
          await flush(buf, db);
        }
        buf = emptyBuffers();
      }
    }

    for (let off = 0; off < files.length; off += PARSE_CHUNK) {
      const slice = files.slice(off, off + PARSE_CHUNK);
      await Promise.all(
        slice.map((name) =>
          limit(async () => {
            try {
              const raw = JSON.parse(await fs.readFile(join(extractDir, name), "utf8"));
              const parsed = osvRecordSchema.safeParse(raw);
              if (!parsed.success) {
                skipped++;
                return;
              }
              const cveId = await bufferRecord(ctx, buf, parsed.data, db, pool);
              if (cveId) imported++;
              else skipped++;
            } catch (e) {
              errored++;
              if (errored < 5) console.error(`\n[osv:${eco}] ${name}:`, e);
            } finally {
              processed++;
              if (processed % 1000 === 0) logProgress(`osv:${eco}`, processed, files.length);
            }
          }),
        ),
      );
      maybeTrimPkgCache(ctx);
      await maybeFlush(false);
    }
    await maybeFlush(true);
    const dt = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`\n[osv:${eco}] imported=${imported} skipped=${skipped} errored=${errored} (${dt}s)`);
    return { eco, imported, skipped, errored };
  } finally {
    await fs.rm(work, { recursive: true, force: true }).catch(() => {});
  }
}

async function main() {
  const { ecos } = parseArgs();
  const results: { eco: string; imported: number; skipped: number; errored: number }[] = [];
  for (const e of ecos) {
    try {
      results.push(await ingestEcosystem(e));
    } catch (err) {
      console.error(`[osv:${e}] FAILED:`, err);
    }
  }
  console.log("---");
  for (const r of results) {
    console.log(`  ${r.eco.padEnd(15)} imported=${r.imported} skipped=${r.skipped} errored=${r.errored}`);
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
