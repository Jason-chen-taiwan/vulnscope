import "server-only";
import { fetch } from "undici";
import { sql } from "drizzle-orm";
import pLimit from "p-limit";
import { createWriteStream, promises as fs } from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { db, pool } from "@/db/client";
import { vulnerabilities, cvssScores, packages, affected, refs } from "@/db/schema";
import {
  osvRecordSchema,
  pickCveAlias,
  normalizePypiName,
  refTypeFromOsv,
  severityFromScore,
  type OsvRecord,
} from "@/lib/osv";
import { baseScoreFromVector } from "@/lib/cvss";
import { startJob } from "@/lib/sync-jobs";

const BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com";

function canonicalizeEco(input: string): string {
  return input.split(":")[0];
}

function parseDate(s: string | undefined | null): Date | null {
  if (!s) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

function cvssVersionLabel(type: string): string {
  if (type === "CVSS_V2") return "2.0";
  if (type === "CVSS_V3") return "3.1";
  if (type === "CVSS_V4") return "4.0";
  return type;
}

async function downloadZipToFile(url: string, dest: string): Promise<void> {
  const res = await fetch(url);
  if (!res.ok || !res.body) throw new Error(`OSV fetch failed: ${res.status} ${url}`);
  await pipeline(Readable.fromWeb(res.body as never), createWriteStream(dest));
}

async function extractZip(zipPath: string, destDir: string): Promise<void> {
  await fs.mkdir(destDir, { recursive: true });
  await new Promise<void>((resolve, reject) => {
    const child = spawn("unzip", ["-q", "-o", zipPath, "-d", destDir], { stdio: "ignore" });
    child.on("error", reject);
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`unzip exited ${code}`))));
  });
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

async function processRecord(ctx: UpsertCtx, rec: OsvRecord): Promise<boolean> {
  const cveId = pickCveAlias(rec);
  if (!cveId) return false;
  const publishedAt = parseDate(rec.published);
  const modifiedAt = parseDate(rec.modified);

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
    const base = baseScoreFromVector(s.score);
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

  for (const r of rec.references ?? []) {
    await db
      .insert(refs)
      .values({ cveId, url: r.url, type: refTypeFromOsv(r.type) })
      .onConflictDoNothing({ target: [refs.cveId, refs.url] });
  }
  return true;
}

export async function runOsvIngest(ecosystem: string): Promise<{ seen: number; changed: number }> {
  const eco = canonicalizeEco(ecosystem);
  const job = await startJob(`osv:${eco}`);
  let seen = 0;
  let imported = 0;
  try {
    const url = `${BASE_URL}/${encodeURIComponent(ecosystem)}/all.zip`;
    const work = await fs.mkdtemp(join(tmpdir(), "osv-"));
    const zipPath = join(work, "all.zip");
    const extractDir = join(work, "json");
    try {
      await downloadZipToFile(url, zipPath);
      await extractZip(zipPath, extractDir);
      await fs.unlink(zipPath).catch(() => {});
      const files = (await fs.readdir(extractDir)).filter((f) => f.endsWith(".json"));
      seen = files.length;
      const ctx: UpsertCtx = {
        eco,
        ecoMatch: (recordEco) => canonicalizeEco(recordEco) === eco,
        pkgCache: new Map(),
      };
      const limit = pLimit(6);
      const CHUNK = 200;
      let processed = 0;
      for (let off = 0; off < files.length; off += CHUNK) {
        const slice = files.slice(off, off + CHUNK);
        await Promise.all(
          slice.map((name) =>
            limit(async () => {
              try {
                const raw = JSON.parse(await fs.readFile(join(extractDir, name), "utf8"));
                const parsed = osvRecordSchema.safeParse(raw);
                if (!parsed.success) return;
                if (await processRecord(ctx, parsed.data)) imported++;
              } catch {
                /* per-record errors swallowed; aggregate metrics go to job row */
              } finally {
                processed++;
              }
            }),
          ),
        );
        // Surface live progress to the sync_jobs row. The handle coalesces
        // these updates internally so we don't flood the DB.
        job.progress({ seen: processed, changed: imported });
        if (ctx.pkgCache.size > 50000) ctx.pkgCache.clear();
      }
    } finally {
      await fs.rm(work, { recursive: true, force: true }).catch(() => {});
    }
    await job.finish({ seen, changed: imported, error: null });
    return { seen, changed: imported };
  } catch (err) {
    await job.finish({ seen, changed: imported, error: err as Error });
    throw err;
  }
}
