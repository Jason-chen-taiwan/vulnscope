/**
 * OSV bulk ingest.
 *
 * Source: https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
 *
 * Phase 0: CVE-keyed records only. For each JSON in the zip:
 *   - find the CVE alias; skip if none
 *   - upsert vulnerabilities row (don't overwrite kev / kev_added_at)
 *   - insert cvss_scores from severity[]
 *   - upsert each affected package and insert an `affected` row keyed on
 *     (cve_id, package_id, source_id) so OSV records that mention the same
 *     package multiple times don't duplicate
 *   - upsert refs
 *
 * Performance: rather than one INSERT per record per child-table (which gave
 * us ~2.2M sequential round-trips for npm and a 40-minute run that fly's
 * boot-reaper killed), we buffer per chunk and emit multi-row INSERTs
 * (vulns / cvss / affected / refs). Same upsert semantics, ~100× fewer
 * round-trips. packages still uses single-row upsert because we need the
 * generated id immediately to put into the `affected` buffer.
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
import { logProgress, parseDate } from "./_shared";

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
  // System unzip; in-process inflate OOMs on the 200MB npm zip.
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
  if (type === "CVSS_V2") return "2.0";
  if (type === "CVSS_V3") return "3.1";
  if (type === "CVSS_V4") return "4.0";
  return type;
}

// ─── Buffer types ────────────────────────────────────────────────────────────

type VulnRow = {
  cveId: string;
  sourceId: string;
  summary: string | null;
  description: string | null;
  publishedAt: Date | null;
  modifiedAt: Date | null;
};
type CvssRow = {
  cveId: string;
  version: string;
  vector: string;
  baseScore: string | null;
  severity: string | null;
};
type AffectedRow = {
  cveId: string;
  packageId: number;
  ecosystem: string;
  rangesJson: unknown;
  versionsJson: unknown;
  sourceId: string;
};
type RefRow = { cveId: string; url: string; type: string | null };

interface Buffers {
  vulns: VulnRow[];
  cvss: CvssRow[];
  affected: AffectedRow[];
  refs: RefRow[];
  // In-buffer dedup keys so a multi-row INSERT doesn't trip ON CONFLICT
  // against its own rows (Postgres can't deduplicate within a single
  // statement; the upsert target needs unique keys).
  vulnSeen: Map<string, number>; // cveId → index into vulns[]
  cvssSeen: Set<string>; // `${cveId}|${version}|osv`
  affectedSeen: Set<string>; // `${cveId}|${packageId}|${sourceId}`
  refsSeen: Set<string>; // `${cveId}|${url}`
}

function emptyBuffers(): Buffers {
  return {
    vulns: [],
    cvss: [],
    affected: [],
    refs: [],
    vulnSeen: new Map(),
    cvssSeen: new Set(),
    affectedSeen: new Set(),
    refsSeen: new Set(),
  };
}

interface UpsertCtx {
  eco: string;
  ecoMatch: (recordEco: string) => boolean;
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

// ─── Record → buffer (no DB writes for child rows) ───────────────────────────

async function bufferRecord(ctx: UpsertCtx, buf: Buffers, rec: OsvRecord): Promise<boolean> {
  const cveId = pickCveAlias(rec);
  if (!cveId) return false;

  const publishedAt = parseDate(rec.published);
  const modifiedAt = parseDate(rec.modified);

  // If the same CVE shows up twice within one buffer flush, keep the latest
  // values (matches the COALESCE-on-conflict semantics of the row-by-row
  // path: later writes win for non-null fields).
  const existingIdx = buf.vulnSeen.get(cveId);
  const newVuln: VulnRow = {
    cveId,
    sourceId: rec.id,
    summary: rec.summary ?? null,
    description: rec.details ?? null,
    publishedAt,
    modifiedAt,
  };
  if (existingIdx !== undefined) {
    buf.vulns[existingIdx] = newVuln;
  } else {
    buf.vulnSeen.set(cveId, buf.vulns.length);
    buf.vulns.push(newVuln);
  }

  // CVSS — flatten record-level + per-affected severity; dedupe by (cveId, version, source)
  const allSeverities = [
    ...(rec.severity ?? []),
    ...((rec.affected ?? []).flatMap((a) => a.severity ?? [])),
  ];
  const seenInRec = new Set<string>(); // (cveId, version) within this record — earlier vector wins
  for (const s of allSeverities) {
    const ver = cvssVersionLabel(s.type);
    const inRecKey = `${cveId}|${ver}`;
    if (seenInRec.has(inRecKey)) continue;
    seenInRec.add(inRecKey);
    const dedupeKey = `${cveId}|${ver}|osv`;
    if (buf.cvssSeen.has(dedupeKey)) continue;
    buf.cvssSeen.add(dedupeKey);
    const base = extractBaseScore(s.score);
    buf.cvss.push({
      cveId,
      version: ver,
      vector: s.score,
      baseScore: base !== null ? String(base) : null,
      severity: severityFromScore(base),
    });
  }

  // Affected packages (still needs package_id resolution → one RT per
  // distinct package, but cached aggressively).
  for (const a of rec.affected ?? []) {
    if (!ctx.ecoMatch(a.package.ecosystem)) continue;
    const pkgId = await getOrCreatePackageId(ctx, a.package.name);
    const dedupeKey = `${cveId}|${pkgId}|${rec.id}`;
    if (buf.affectedSeen.has(dedupeKey)) continue;
    buf.affectedSeen.add(dedupeKey);
    buf.affected.push({
      cveId,
      packageId: pkgId,
      ecosystem: ctx.eco,
      rangesJson: a.ranges ?? [],
      versionsJson: a.versions ?? null,
      sourceId: rec.id,
    });
  }

  // References (PK = cveId, url)
  for (const r of rec.references ?? []) {
    const dedupeKey = `${cveId}|${r.url}`;
    if (buf.refsSeen.has(dedupeKey)) continue;
    buf.refsSeen.add(dedupeKey);
    buf.refs.push({ cveId, url: r.url, type: refTypeFromOsv(r.type) });
  }
  return true;
}

// ─── Flush buffers (one multi-row INSERT per table per flush) ────────────────

const FLUSH_INSERT_BATCH = 1000; // rows per single INSERT statement

async function flushVulns(rows: VulnRow[]) {
  for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
    const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
    await db
      .insert(vulnerabilities)
      .values(slice)
      .onConflictDoUpdate({
        target: vulnerabilities.cveId,
        set: {
          sourceId: sql`EXCLUDED.source_id`,
          summary: sql`COALESCE(EXCLUDED.summary, ${vulnerabilities.summary})`,
          description: sql`COALESCE(EXCLUDED.description, ${vulnerabilities.description})`,
          publishedAt: sql`COALESCE(${vulnerabilities.publishedAt}, EXCLUDED.published_at)`,
          modifiedAt: sql`COALESCE(EXCLUDED.modified_at, ${vulnerabilities.modifiedAt})`,
        },
      });
  }
}

async function flushCvss(rows: CvssRow[]) {
  for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
    const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
    await db
      .insert(cvssScores)
      .values(slice.map((r) => ({ ...r, source: "osv" })))
      .onConflictDoNothing({
        target: [cvssScores.cveId, cvssScores.version, cvssScores.source],
      });
  }
}

async function flushAffected(rows: AffectedRow[]) {
  for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
    const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
    await db
      .insert(affected)
      .values(slice)
      .onConflictDoNothing({
        target: [affected.cveId, affected.packageId, affected.sourceId],
      });
  }
}

async function flushRefs(rows: RefRow[]) {
  for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
    const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
    await db
      .insert(refs)
      .values(slice)
      .onConflictDoNothing({ target: [refs.cveId, refs.url] });
  }
}

async function flush(buf: Buffers) {
  // Order matters: vulns first (other tables FK to cveId).
  if (buf.vulns.length) await flushVulns(buf.vulns);
  // The next three are independent of each other; parallelize.
  await Promise.all([
    buf.cvss.length ? flushCvss(buf.cvss) : Promise.resolve(),
    buf.affected.length ? flushAffected(buf.affected) : Promise.resolve(),
    buf.refs.length ? flushRefs(buf.refs) : Promise.resolve(),
  ]);
}

// ─── Driver ──────────────────────────────────────────────────────────────────

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
    // Concurrency only for the read+parse+pkg-resolve phase — buffer writes
    // and flushes are sequential to keep ordering predictable.
    const limit = pLimit(6);
    let processed = 0;
    let imported = 0;
    let skipped = 0;
    let errored = 0;
    const startTime = Date.now();

    const CHUNK = 1000; // records per buffer flush
    for (let off = 0; off < files.length; off += CHUNK) {
      const slice = files.slice(off, off + CHUNK);
      const buf = emptyBuffers();
      // Buffer is shared across parallel readers — bufferRecord is async
      // because pkg lookup may hit DB, but all buffer mutations are
      // synchronous JS so there's no interleave concern between awaits.
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
              const ok = await bufferRecord(ctx, buf, parsed.data);
              if (ok) imported++;
              else skipped++;
            } catch (e) {
              errored++;
              if (errored < 5) console.error(`\n[osv:${eco}] ${name}:`, e);
            } finally {
              processed++;
              if (processed % 5000 === 0) logProgress(`osv:${eco}`, processed, files.length);
            }
          }),
        ),
      );
      // Flush this chunk's buffer. Failures here surface as an exception
      // and abort the whole ecosystem (matching old behaviour — partial
      // ingest is fine, we re-sync from scratch on the next run anyway).
      await flush(buf);
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
