import "server-only";
import { fetch } from "undici";
import pLimit from "p-limit";
import { createWriteStream, promises as fs } from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ingestDb, ingestPool } from "@/db/ingest-pool";
import { osvRecordSchema } from "@/lib/osv";
import { startJob } from "@/lib/sync-jobs";
import { getMeta, setMeta } from "./meta";
import { ensureIngestSchema } from "./ensure-schema";
import {
  bufferRecord,
  emptyBuffers,
  flush,
  maybeTrimPkgCache,
  pushAlias,
  CHUNK_RECORDS,
  type Buffers,
  type UpsertCtx,
} from "./osv-batch";

/**
 * Classify a non-CVE identifier into a source tag so the UI can group
 * by ecosystem advisory provider. Unknown prefixes fall to "other"
 * rather than being dropped — we want to surface unknowns, not lose data.
 */
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

const BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com";

function canonicalizeEco(input: string): string {
  return input.split(":")[0];
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

function collectAliases(
  rec: { id?: string; aliases?: string[]; upstream?: string[]; related?: string[] },
  cveId: string,
): string[] {
  const out = new Set<string>();
  if (rec.id && !/^CVE-\d{4}-\d+$/i.test(rec.id) && rec.id !== cveId) out.add(rec.id);
  for (const a of rec.aliases ?? []) {
    if (a && !/^CVE-\d{4}-\d+$/i.test(a) && a !== cveId) out.add(a);
  }
  for (const u of rec.upstream ?? []) {
    if (u && !/^CVE-\d{4}-\d+$/i.test(u) && u !== cveId) out.add(u);
  }
  for (const r of rec.related ?? []) {
    if (r && !/^CVE-\d{4}-\d+$/i.test(r) && r !== cveId) out.add(r);
  }
  return [...out];
}

export interface RunOsvOptions {
  /**
   * Cooperative cancellation signal. Checked at each parse-chunk
   * boundary; throws if aborted. Does NOT cancel in-flight pg queries —
   * those are bounded by the ingest pool's `statement_timeout`.
   */
  signal?: AbortSignal;
}

export async function runOsvIngest(
  ecosystem: string,
  opts?: RunOsvOptions,
): Promise<{ seen: number; changed: number }> {
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
    if (opts?.signal?.aborted) throw new Error(`aborted: osv:${eco}`);

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
      // Parse concurrency 3 and parse chunk 100 bound peak Node heap:
      // each in-flight record holds the file string + parsed object +
      // zod's intermediate, which adds up fast on the 220k-record npm
      // zip. The chunk boundary is also a microtask yield where V8 reaps.
      const limit = pLimit(3);
      const PARSE_CHUNK = 100;
      let processed = 0;
      let buf: Buffers = emptyBuffers();

      // Coordinator: buffer accumulates across multiple parse chunks
      // until >= CHUNK_RECORDS records are in flight, then we flush.
      // The flush boundary is independent of the parse boundary so the
      // batched INSERT amortizes its network cost properly.
      async function maybeFlush(force: boolean) {
        if (force || buf.recordsBuffered >= CHUNK_RECORDS) {
          if (buf.vulns.length || buf.aliases.length) {
            await flush(buf, ingestDb);
          }
          buf = emptyBuffers();
        }
      }

      for (let off = 0; off < files.length; off += PARSE_CHUNK) {
        if (opts?.signal?.aborted) throw new Error(`aborted: osv:${eco}`);
        const slice = files.slice(off, off + PARSE_CHUNK);
        await Promise.all(
          slice.map((name) =>
            limit(async () => {
              try {
                const raw = JSON.parse(await fs.readFile(join(extractDir, name), "utf8"));
                const parsed = osvRecordSchema.safeParse(raw);
                if (!parsed.success) return;
                const rec = parsed.data;
                const cveId = await bufferRecord(ctx, buf, rec, ingestDb, ingestPool);
                if (!cveId) return;
                imported++;
                for (const alias of collectAliases(rec, cveId)) {
                  pushAlias(buf, cveId, alias, classifyAlias(alias));
                }
              } catch {
                /* per-record errors swallowed; aggregate metrics go to job row */
              } finally {
                processed++;
              }
            }),
          ),
        );
        maybeTrimPkgCache(ctx);
        await maybeFlush(false);
        // Surface live progress to the sync_jobs row. The handle
        // coalesces these (max one UPDATE per second) so even calling
        // every parse chunk doesn't flood the DB.
        job.progress({ seen: processed, changed: imported });
        // Yield to the event loop so V8 can reap the chunk's parsed
        // records before the next batch. Critical on 1GB Fly machines.
        await new Promise((r) => setImmediate(r));
      }
      // Tail flush — the last partial buffer.
      await maybeFlush(true);
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
