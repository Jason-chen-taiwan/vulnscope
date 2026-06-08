import "server-only";
import { fetch } from "undici";
import { createWriteStream, promises as fs } from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ingestDb, ingestPool } from "@/db/ingest-pool";
import { startJob } from "@/lib/sync-jobs";
import { getMeta, setMeta } from "./meta";
import { ensureIngestSchema } from "./ensure-schema";
import { streamOsvZip, type UpsertCtx } from "./osv-batch";

/**
 * Classify a non-CVE identifier into a source tag so the UI can group
 * by ecosystem advisory provider. Unknown prefixes fall to "other"
 * rather than being dropped — we want to surface unknowns, not lose
 * data.
 *
 * Lives here (not in osv-batch.ts) so osv-batch stays domain-agnostic;
 * the function is injected into streamOsvDir via options.
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

async function downloadZipToFile(
  url: string,
  dest: string,
  signal?: AbortSignal,
): Promise<void> {
  const res = await fetch(url, { signal });
  if (!res.ok || !res.body) throw new Error(`OSV fetch failed: ${res.status} ${url}`);
  // pipeline AbortSignal aborts both ends — if the orchestrator's per-source
  // timeout fires mid-download, the partial file is closed and removed
  // (via the runOsvIngest finally that rms the work tmpdir).
  await pipeline(Readable.fromWeb(res.body as never), createWriteStream(dest), { signal });
}

/**
 * HEAD probes should never hang. GCS objects respond in <500ms in practice;
 * anything past 30s is a network problem we want surfaced immediately so
 * the orchestrator can record the failure and move on. Pre-fix, a hanging
 * HEAD blocked the whole ingest indefinitely — sync_jobs row stayed at
 * status='running' with records_seen=NULL forever (root cause of the
 * 2026-06-05 osv:npm 3-day stall).
 */
const HEAD_TIMEOUT_MS = 30_000;

async function headWithTimeout(url: string, outerSignal?: AbortSignal) {
  const localCtrl = new AbortController();
  const timer = setTimeout(() => localCtrl.abort(new Error("HEAD timeout")), HEAD_TIMEOUT_MS);
  const onOuterAbort = () => localCtrl.abort();
  outerSignal?.addEventListener("abort", onOuterAbort, { once: true });
  try {
    return await fetch(url, { method: "HEAD", signal: localCtrl.signal });
  } finally {
    clearTimeout(timer);
    outerSignal?.removeEventListener("abort", onOuterAbort);
  }
}

export interface RunOsvOptions {
  /**
   * Cooperative cancellation signal. Checked at each chunk boundary
   * inside streamOsvDir; throws if aborted. Does NOT cancel in-flight
   * pg queries — those are bounded by the ingest pool's `statement_timeout`.
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
  let processed = 0;
  let imported = 0;
  const metaKey = `osv:${eco}:last_modified`;
  try {
    const url = `${BASE_URL}/${encodeURIComponent(ecosystem)}/all.zip`;
    // Zip-level incremental skip: HEAD the GCS object, compare its
    // Last-Modified header with what we stored last time. A no-change
    // tick is <1s instead of multi-minute download + decompress.
    const headRes = await headWithTimeout(url, opts?.signal);
    const upstreamMtime = headRes.headers.get("last-modified");
    const knownMtime = await getMeta(metaKey);
    if (upstreamMtime && knownMtime === upstreamMtime) {
      await job.finish({ seen: 0, changed: 0, error: null });
      return { seen: 0, changed: 0 };
    }
    if (opts?.signal?.aborted) throw new Error(`aborted: osv:${eco}`);

    const work = await fs.mkdtemp(join(tmpdir(), "osv-"));
    const zipPath = join(work, "all.zip");
    try {
      await downloadZipToFile(url, zipPath, opts?.signal);

      const ctx: UpsertCtx = {
        eco,
        ecoMatch: (recordEco) => canonicalizeEco(recordEco) === eco,
        pkgCache: new Map(),
      };

      const result = await streamOsvZip({
        ctx,
        zipPath,
        db: ingestDb,
        pool: ingestPool,
        signal: opts?.signal,
        classifyAlias,
        log: (msg) => console.log(msg),
        onChunk({ processed: p, imported: i }) {
          processed = p;
          imported = i;
          // JobHandle coalesces these (max 1 UPDATE/s) so calling every
          // chunk doesn't flood the DB.
          job.progress({ seen: p, changed: i });
        },
      });
      processed = result.processed;
      imported = result.imported;
    } finally {
      // `work` now holds only the zip — single unlink, no inode storm.
      await fs.rm(work, { recursive: true, force: true }).catch(() => {});
    }
    if (upstreamMtime) await setMeta(metaKey, upstreamMtime);
    await job.finish({ seen: processed, changed: imported, error: null });
    return { seen: processed, changed: imported };
  } catch (err) {
    await job.finish({ seen: processed, changed: imported, error: err as Error });
    throw err;
  }
}
