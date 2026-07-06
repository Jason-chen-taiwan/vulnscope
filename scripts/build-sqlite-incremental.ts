/**
 * Incremental OSV build entry point.
 *
 * For each ecosystem: read the D1-backed watermark (from the local SQLite's
 * sync_state, seeded by the previous push), read OSV's modified_id.csv to find
 * primary ids changed since the watermark, download all.zip, and stream ONLY
 * the changed records into the incremental SQLite via streamOsvZip(idFilter).
 * Then record the new watermark. KEV/EPSS run too (same as the daily build).
 *
 * The resulting SQLite is pushed to D1 by push-to-d1.sh in delta mode; the
 * sync_state rows ride along in that push (emitted after all data).
 *
 * Env: SQLITE_OUT (output path), INGEST_ECOSYSTEMS (comma list; default all).
 */
import DatabaseCtor from "better-sqlite3";
import type Database from "better-sqlite3";
import { fetch } from "undici";
import { createWriteStream, promises as fs } from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { streamOsvZip, type UpsertCtx } from "../src/lib/ingest/osv-batch";
import { SqliteIngestSink } from "../src/lib/ingest/sink-sqlite";
import { parseModifiedCsv, MODIFIED_CSV_URL } from "../src/lib/ingest/osv-modified";
import {
  SYNC_STATE_DDL,
  readWatermark,
  writeWatermark,
} from "../src/lib/ingest/sync-state";
import {
  buildSchema,
  canonicalizeEco,
  classifyAlias,
  ingestKev,
  ingestEpss,
  DEFAULT_ECOSYSTEMS,
  OSV_BASE_URL,
} from "./build-sqlite";

export const SPIKE_THRESHOLD = 5000;
const COLD_START_DAYS = 7;

export function sevenDaysAgoIso(nowMs: number): string {
  return new Date(nowMs - COLD_START_DAYS * 24 * 60 * 60 * 1000).toISOString();
}

export interface IncrementalResult {
  eco: string;
  changedCount: number;
  imported: number;
  skippedBySpike: boolean;
  watermark: string | null;
}

export interface IngestOsvIncrementalOpts {
  eco: string;
  db: Database.Database;
  nowMs: number;
  /** Injected for tests; defaults to real HTTP GET of the modified_id.csv. */
  fetchCsv?: (eco: string) => Promise<string>;
  /** Injected for tests; defaults to real zip download to a tmp file. */
  fetchZipToFile?: (eco: string, dest: string) => Promise<void>;
  /** Test-only: force the starting watermark (bypasses sync_state read). */
  watermarkOverride?: string | null;
  log?: (msg: string) => void;
}

async function defaultFetchCsv(eco: string): Promise<string> {
  const res = await fetch(MODIFIED_CSV_URL(eco));
  if (!res.ok) throw new Error(`modified_id.csv fetch failed: ${res.status}`);
  return res.text();
}

async function defaultFetchZip(eco: string, dest: string): Promise<void> {
  const url = `${OSV_BASE_URL}/${encodeURIComponent(eco)}/all.zip`;
  const res = await fetch(url);
  if (!res.ok || !res.body) throw new Error(`OSV zip fetch failed: ${res.status}`);
  await pipeline(Readable.fromWeb(res.body as never), createWriteStream(dest));
}

export async function ingestOsvIncremental(
  opts: IngestOsvIncrementalOpts,
): Promise<IncrementalResult> {
  const {
    eco,
    db,
    nowMs,
    fetchCsv = defaultFetchCsv,
    fetchZipToFile = defaultFetchZip,
    watermarkOverride,
    log = () => {},
  } = opts;

  const source = `osv:${eco}`;
  const stored =
    watermarkOverride !== undefined ? watermarkOverride : readWatermark(db, source);
  const watermark = stored ?? sevenDaysAgoIso(nowMs);

  const csv = await fetchCsv(eco);
  const { changedIds, newWatermark } = parseModifiedCsv(csv, watermark);

  if (changedIds.size === 0) {
    return { eco, changedCount: 0, imported: 0, skippedBySpike: false, watermark: stored ?? null };
  }

  if (changedIds.size > SPIKE_THRESHOLD) {
    log(`[osv-inc:${eco}] SPIKE ${changedIds.size} > ${SPIKE_THRESHOLD} — skipping, watermark untouched`);
    return {
      eco,
      changedCount: changedIds.size,
      imported: 0,
      skippedBySpike: true,
      watermark: stored ?? null,
    };
  }

  const work = await fs.mkdtemp(join(tmpdir(), "osv-inc-"));
  const zipPath = join(work, "all.zip");
  let imported = 0;
  try {
    await fetchZipToFile(eco, zipPath);
    const ctx: UpsertCtx = {
      eco: canonicalizeEco(eco),
      ecoMatch: (recordEco) => canonicalizeEco(recordEco) === canonicalizeEco(eco),
      pkgCache: new Map(),
    };
    const r = await streamOsvZip({
      ctx,
      zipPath,
      sink: new SqliteIngestSink(db),
      classifyAlias,
      idFilter: changedIds,
      log,
    });
    imported = r.imported;
  } finally {
    await fs.rm(work, { recursive: true, force: true }).catch(() => {});
  }

  // Advance the watermark ONLY after the data is in the local SQLite. The push
  // to D1 (delta) carries both the data and this watermark row atomically.
  if (newWatermark) {
    writeWatermark(db, source, newWatermark, new Date(nowMs).toISOString());
  }

  return { eco, changedCount: changedIds.size, imported, skippedBySpike: false, watermark: newWatermark };
}

async function main() {
  const outPath = resolve(
    process.env.SQLITE_OUT ??
      join(dirname(fileURLToPath(import.meta.url)), "..", "scratch-phase0", "vulnscope-incremental.sqlite"),
  );
  await fs.mkdir(dirname(outPath), { recursive: true });
  await fs.rm(outPath, { force: true });

  const db = new DatabaseCtor(outPath);
  buildSchema(db);
  db.exec(SYNC_STATE_DDL);

  const raw = process.env.INGEST_ECOSYSTEMS;
  const ecosystems = raw
    ? raw.split(",").map((s) => s.trim()).filter(Boolean)
    : DEFAULT_ECOSYSTEMS;

  const nowMs = Date.now();
  for (const eco of ecosystems) {
    try {
      const r = await ingestOsvIncremental({ eco, db, nowMs, log: (m) => console.log(m) });
      console.log(`[osv-inc:${eco}] changed=${r.changedCount} imported=${r.imported} spike=${r.skippedBySpike}`);
    } catch (err) {
      // One ecosystem's failure must not abort the others; watermark stays put.
      console.error(`[osv-inc:${eco}] ERROR — skipped, watermark untouched:`, err);
    }
  }

  // KEV/EPSS refresh (same as the daily build).
  await ingestKev(db);
  await ingestEpss(db);

  db.close();
  console.log(`[osv-inc] done → ${outPath}`);
}

// Run main() only as a CLI, not when imported by tests.
const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
