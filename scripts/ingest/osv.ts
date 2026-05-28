/**
 * OSV bulk ingest.
 *
 * Source: https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
 *
 * For Phase 0 we only care about CVE-keyed records. For each JSON in the zip:
 *   - find the CVE alias; skip if none
 *   - upsert vulnerabilities row (don't overwrite kev / kev_added_at)
 *   - insert cvss_scores from severity[]
 *   - upsert each affected package and insert an `affected` row keyed on
 *     (cve_id, package_id, source_id) so OSV records that mention the same
 *     package multiple times don't duplicate.
 *   - upsert refs
 *
 * Usage:
 *   pnpm ingest:osv -- --ecosystem=npm
 *   pnpm ingest:osv -- --ecosystem=PyPI
 */
import "./_shared";
import { fetch } from "undici";
import { sql } from "drizzle-orm";
import pLimit from "p-limit";
import { createWriteStream, promises as fs } from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { db, pool } from "../../src/db/client";
import { vulnerabilities, cvssScores, packages, affected, refs } from "../../src/db/schema";
import {
  osvRecordSchema,
  pickCveAlias,
  normalizePypiName,
  refTypeFromOsv,
  severityFromScore,
  type OsvRecord,
} from "../../src/lib/osv";
import { baseScoreFromVector } from "../../src/lib/cvss";
import { done, logProgress, parseDate } from "./_shared";

// OSV bulk-download base. Any ecosystem name listed at
// https://osv-vulnerabilities.storage.googleapis.com/ can be passed in.
// We canonicalize Debian:NN / Ubuntu:NN / Alpine:vX.Y to their base name
// for `packages.ecosystem` so the same package across distros consolidates.
const BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com";

function canonicalizeEco(input: string): string {
  // Strip per-version suffix: "Debian:12" -> "Debian", "Alpine:v3.18" -> "Alpine"
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
  // Use system unzip — adm-zip / inflate-in-process blows up on the 200MB npm zip.
  await new Promise<void>((resolve, reject) => {
    const child = spawn("unzip", ["-q", "-o", zipPath, "-d", destDir], { stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`unzip exited ${code}`))));
  });
}

function extractBaseScore(vec: string): number | null {
  return baseScoreFromVector(vec);
}

function cvssVersionLabel(type: string): string {
  // OSV severity types: CVSS_V2 / CVSS_V3 / CVSS_V4
  if (type === "CVSS_V2") return "2.0";
  if (type === "CVSS_V3") return "3.1"; // OSV doesn't distinguish v3.0 vs v3.1; assume 3.1
  if (type === "CVSS_V4") return "4.0";
  return type;
}

interface UpsertCtx {
  eco: string; // canonical (e.g. "Debian", "npm")
  ecoMatch: (recordEco: string) => boolean; // accepts "Debian:12" when ctx.eco = "Debian"
  pkgCache: Map<string, number>;
}

async function getOrCreatePackageId(ctx: UpsertCtx, name: string): Promise<number> {
  const normName = ctx.eco === "PyPI" ? normalizePypiName(name) : name;
  const cacheKey = `${ctx.eco}:${normName}`;
  const cached = ctx.pkgCache.get(cacheKey);
  if (cached) return cached;
  const inserted = await db
    .insert(packages)
    .values({ ecosystem: ctx.eco, name: normName })
    .onConflictDoNothing({ target: [packages.ecosystem, packages.name] })
    .returning({ id: packages.id });
  let id: number;
  if (inserted.length > 0) {
    id = inserted[0].id;
  } else {
    const { rows } = await pool.query(
      "SELECT id FROM packages WHERE ecosystem=$1 AND name=$2",
      [ctx.eco, normName],
    );
    id = rows[0].id as number;
  }
  ctx.pkgCache.set(cacheKey, id);
  return id;
}

async function processRecord(ctx: UpsertCtx, rec: OsvRecord) {
  const cveId = pickCveAlias(rec);
  if (!cveId) return false; // Phase 0: CVE-keyed only

  const publishedAt = parseDate(rec.published);
  const modifiedAt = parseDate(rec.modified);
  // Upsert vulnerability. Don't ever overwrite KEV fields.
  await db
    .insert(vulnerabilities)
    .values({
      cveId,
      sourceId: rec.id,
      summary: rec.summary ?? null,
      description: rec.details ?? null,
      publishedAt,
      modifiedAt,
    })
    .onConflictDoUpdate({
      target: vulnerabilities.cveId,
      set: {
        sourceId: rec.id,
        summary: sql`COALESCE(EXCLUDED.summary, ${vulnerabilities.summary})`,
        description: sql`COALESCE(EXCLUDED.description, ${vulnerabilities.description})`,
        publishedAt: sql`COALESCE(${vulnerabilities.publishedAt}, EXCLUDED.published_at)`,
        modifiedAt: sql`COALESCE(EXCLUDED.modified_at, ${vulnerabilities.modifiedAt})`,
      },
    });

  // CVSS scores (record-level + per-affected-entry)
  const allSeverities = [
    ...(rec.severity ?? []),
    ...((rec.affected ?? []).flatMap((a) => a.severity ?? [])),
  ];
  const seenSeverity = new Set<string>();
  for (const s of allSeverities) {
    const ver = cvssVersionLabel(s.type);
    const key = `${ver}|${s.score}`;
    if (seenSeverity.has(key)) continue;
    seenSeverity.add(key);
    const base = extractBaseScore(s.score);
    await db
      .insert(cvssScores)
      .values({
        cveId,
        version: ver,
        vector: s.score,
        baseScore: base !== null ? String(base) : null,
        severity: severityFromScore(base),
        source: "osv",
      })
      .onConflictDoNothing({
        target: [cvssScores.cveId, cvssScores.version, cvssScores.source],
      });
  }

  // Affected packages
  for (const a of rec.affected ?? []) {
    if (!ctx.ecoMatch(a.package.ecosystem)) continue;
    const pkgId = await getOrCreatePackageId(ctx, a.package.name);
    await db
      .insert(affected)
      .values({
        cveId,
        packageId: pkgId,
        ecosystem: ctx.eco,
        rangesJson: a.ranges ?? [],
        versionsJson: a.versions ?? null,
        sourceId: rec.id,
      })
      .onConflictDoNothing({
        target: [affected.cveId, affected.packageId, affected.sourceId],
      });
  }

  // References
  for (const r of rec.references ?? []) {
    await db
      .insert(refs)
      .values({ cveId, url: r.url, type: refTypeFromOsv(r.type) })
      .onConflictDoNothing({ target: [refs.cveId, refs.url] });
  }
  return true;
}

async function ingestEcosystem(ecoArg: string) {
  // ecoArg may be either the bucket prefix ("Debian", "Alpine") or include a
  // version suffix that we'll strip for the `packages.ecosystem` value but
  // pass through to the URL.
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

    const CHUNK = 200;
    for (let off = 0; off < files.length; off += CHUNK) {
      const slice = files.slice(off, off + CHUNK);
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
              const ok = await processRecord(ctx, parsed.data);
              if (ok) imported++;
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
      if (ctx.pkgCache.size > 50000) ctx.pkgCache.clear();
    }
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
