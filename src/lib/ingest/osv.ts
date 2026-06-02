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
import { getMeta, setMeta } from "./meta";
import { ensureIngestSchema } from "./ensure-schema";

/**
 * Classify a non-CVE identifier into a source tag so the UI can group
 * by ecosystem advisory provider. The set is small and well-known —
 * everything we don't recognise falls into "other" rather than being
 * dropped (we want to surface unknowns, not silently lose data).
 */
function classifyAlias(alias: string): string {
  const a = alias.toUpperCase();
  if (a.startsWith("GHSA-")) return "ghsa";
  if (a.startsWith("DSA-")) return "dsa";
  if (a.startsWith("DLA-")) return "dla";
  if (a.startsWith("DEBIAN-")) return "debian";
  if (a.startsWith("ALPINE-")) return "alpine";
  if (a.startsWith("RHSA-")) return "rhsa";
  if (a.startsWith("USN-")) return "usn"; // Ubuntu
  if (a.startsWith("GLSA-")) return "glsa"; // Gentoo
  if (a.startsWith("SUSE-")) return "suse";
  if (a.startsWith("PYSEC-")) return "pysec";
  if (a.startsWith("RUSTSEC-")) return "rustsec";
  if (a.startsWith("GO-")) return "goadvisory";
  if (a.startsWith("OSV-")) return "osv-id";
  return "other";
}

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

  // Per-record incremental skip done at the SQL layer using a cheap
  // indexed lookup: if the existing row's modified_at >= this record's,
  // skip the entire write. We avoid loading an in-memory Map for the
  // whole DB (which previously OOM'd the app when the table grew past
  // ~50k rows).
  if (modifiedAt) {
    const existing = await pool.query<{ modified_at: Date | null }>(
      `SELECT modified_at FROM vulnerabilities WHERE cve_id = $1`,
      [cveId],
    );
    if (existing.rows.length > 0) {
      const known = existing.rows[0].modified_at;
      if (known && new Date(known).getTime() >= modifiedAt.getTime()) return false;
    }
  }

  // Collect every non-CVE identifier that points at this vuln. The OSV
  // record id itself is included when it isn't the CVE we resolved to
  // (so GHSA-... and ALPINE-... main IDs become searchable aliases).
  const aliasSet = new Set<string>();
  if (rec.id && !/^CVE-\d{4}-\d+$/i.test(rec.id) && rec.id !== cveId) {
    aliasSet.add(rec.id);
  }
  for (const a of rec.aliases ?? []) {
    if (a && !/^CVE-\d{4}-\d+$/i.test(a) && a !== cveId) aliasSet.add(a);
  }
  for (const u of rec.upstream ?? []) {
    if (u && !/^CVE-\d{4}-\d+$/i.test(u) && u !== cveId) aliasSet.add(u);
  }
  for (const r of rec.related ?? []) {
    if (r && !/^CVE-\d{4}-\d+$/i.test(r) && r !== cveId) aliasSet.add(r);
  }

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

  // Persist every non-CVE alias as a queryable identifier. ON CONFLICT
  // covers the case where the same alias appears in multiple records
  // (e.g. GHSA-... can show up in both the GHSA-prefixed OSV record
  // and a related ALPINE-... record); whichever we see first wins.
  // Cross-CVE conflicts (uq_vuln_aliases_alias) are skipped silently —
  // OSV's own data is occasionally inconsistent and we don't want a
  // single malformed alias to abort an entire record write.
  for (const alias of aliasSet) {
    await pool.query(
      `INSERT INTO vuln_aliases (cve_id, alias, source)
            VALUES ($1, $2, $3)
       ON CONFLICT DO NOTHING`,
      [cveId, alias, classifyAlias(alias)],
    );
  }
  return true;
}

export async function runOsvIngest(ecosystem: string): Promise<{ seen: number; changed: number }> {
  const eco = canonicalizeEco(ecosystem);
  await ensureIngestSchema();
  const job = await startJob(`osv:${eco}`);
  let seen = 0;
  let imported = 0;
  const metaKey = `osv:${eco}:last_modified`;
  try {
    const url = `${BASE_URL}/${encodeURIComponent(ecosystem)}/all.zip`;
    // Zip-level incremental skip: HEAD the GCS object, compare its
    // Last-Modified header with what we stored last time. A no-change
    // tick is <1s instead of multi-minute download + decompress.
    const headRes = await fetch(url, { method: "HEAD" });
    const upstreamMtime = headRes.headers.get("last-modified");
    const knownMtime = await getMeta(metaKey);
    if (upstreamMtime && knownMtime === upstreamMtime) {
      await job.finish({ seen: 0, changed: 0, error: null });
      return { seen: 0, changed: 0 };
    }
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
      // Concurrency 3 (down from 6) and chunk 100 (down from 200) bound
      // peak Node heap: each in-flight record holds the file string +
      // the parsed object + zod's intermediate value, which adds up fast
      // on the 220k-record npm zip. The chunk boundary is also a
      // microtask yield where V8 gets to reap.
      const limit = pLimit(3);
      const CHUNK = 100;
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
        // Yield to the event loop so V8 can reap the chunk's parsed
        // OSV records before we load the next batch. Critical on small
        // app machines — without this we OOM on the 220k-record zip.
        await new Promise((r) => setImmediate(r));
      }
    } finally {
      await fs.rm(work, { recursive: true, force: true }).catch(() => {});
    }
    if (upstreamMtime) await setMeta(metaKey, upstreamMtime);
    await job.finish({ seen, changed: imported, error: null });
    return { seen, changed: imported };
  } catch (err) {
    await job.finish({ seen, changed: imported, error: err as Error });
    throw err;
  }
}
