# Incremental OSV Ingest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep OSV vulnerability data auto-refreshed daily within the Cloudflare D1 free tier by ingesting only records changed since a per-ecosystem watermark, derived from OSV's `modified_id.csv` changelog.

**Architecture:** For each ecosystem, read a watermark from D1's `sync_state` table, stream `{eco}/modified_id.csv` (reverse-chronological) to collect changed primary ids since the watermark, download the existing `{eco}/all.zip`, and stream it through the existing `streamOsvZip` with a new optional `idFilter` that skips non-changed zip entries before inflate. Only changed CVE records land in an incremental SQLite, which the existing `push-to-d1.sh` delta mode pushes to D1; watermarks ride along in the same push (`sync_state` rows, emitted after all data).

**Tech Stack:** TypeScript, tsx, better-sqlite3, vitest, undici (fetch), yauzl (via existing osv-batch), Cloudflare D1 / wrangler, bash (push-to-d1.sh).

## Global Constraints

- **CVE-only scope:** only records that resolve to a `CVE-xxxx` id are written. Enforced downstream by `bufferRecord` (returns `null` for no-CVE-alias records). The `modified_id.csv` parser MUST NOT pre-filter to `CVE-` — npm/PyPI records are keyed by `GHSA-*` with the CVE in aliases.
- **idFilter matches the PRIMARY id** (the `modified_id.csv` id column = the zip entry filename stem), NOT the resolved CVE id.
- **Watermark advances only after data lands in D1.** Any failure leaves the watermark unchanged; re-processing is idempotent.
- **`sync_state` UPSERT statements must be emitted AFTER all data statements** in the delta SQL, so a mid-push failure cannot advance a watermark ahead of un-landed data.
- **Spike guard:** if an ecosystem's changed-id count > `5000`, skip that ecosystem, record it in `sync_jobs.error_message`, do NOT advance its watermark.
- **Cold start:** missing `sync_state` row → initial watermark = 7 days before now (ISO string).
- **Timestamp comparison is ISO-8601 lexical string comparison** (all OSV timestamps are UTC `Z`, identical format). Watermark boundary is exclusive-of-equal: stop at first line where `modified <= watermark`.
- **Zero behaviour change without `idFilter`:** `streamOsvZip` called without `idFilter` must behave identically to today. `build-sqlite.ts` full mode and `sink-sqlite.test.ts` stay green.
- **Source key convention:** `sync_state.source` = `osv:<eco>` (e.g. `osv:npm`).
- OSV base URL: `https://osv-vulnerabilities.storage.googleapis.com`.
- Test runner: `pnpm vitest run <file>`. Type check: `pnpm exec tsc --noEmit`.

---

### Task 1: `modified_id.csv` parser (`osv-modified.ts`)

**Files:**
- Create: `src/lib/ingest/osv-modified.ts`
- Test: `src/lib/ingest/osv-modified.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `parseModifiedCsv(text: string, watermark: string | null): { changedIds: Set<string>; newWatermark: string | null }` — pure, parses an already-fetched CSV string.
  - `MODIFIED_CSV_URL(eco: string): string` — returns `https://osv-vulnerabilities.storage.googleapis.com/<eco>/modified_id.csv` (eco URL-encoded).

- [ ] **Step 1: Write the failing test**

```ts
// src/lib/ingest/osv-modified.test.ts
import { describe, it, expect } from "vitest";
import { parseModifiedCsv, MODIFIED_CSV_URL } from "./osv-modified";

// Reverse-chronological CSV (newest first), matching OSV's format.
const CSV = [
  "2026-07-05T23:00:00.000Z,GHSA-aaaa-bbbb-cccc",
  "2026-07-05T22:00:00.000Z,CVE-2026-1234",
  "2026-07-05T21:00:00.000Z,MAL-2026-0001",
  "2026-07-04T10:00:00.000Z,CVE-2026-0099",
  "2026-07-01T09:00:00.000Z,CVE-2025-8888",
].join("\n");

describe("parseModifiedCsv", () => {
  it("collects primary ids newer than the watermark and stops at <= watermark", () => {
    // watermark = the 2026-07-04 line's timestamp → that line and older excluded.
    const { changedIds, newWatermark } = parseModifiedCsv(
      CSV,
      "2026-07-04T10:00:00.000Z",
    );
    expect([...changedIds].sort()).toEqual(
      ["CVE-2026-1234", "GHSA-aaaa-bbbb-cccc", "MAL-2026-0001"].sort(),
    );
    // primary ids kept verbatim — NOT pre-filtered to CVE-.
    expect(newWatermark).toBe("2026-07-05T23:00:00.000Z");
  });

  it("returns all rows when watermark is null (cold-ish, but bounded by caller)", () => {
    const { changedIds, newWatermark } = parseModifiedCsv(CSV, null);
    expect(changedIds.size).toBe(5);
    expect(newWatermark).toBe("2026-07-05T23:00:00.000Z");
  });

  it("returns empty set + null watermark for empty input", () => {
    const { changedIds, newWatermark } = parseModifiedCsv("", "2026-01-01T00:00:00.000Z");
    expect(changedIds.size).toBe(0);
    expect(newWatermark).toBeNull();
  });

  it("returns empty set when every row is <= watermark", () => {
    const { changedIds } = parseModifiedCsv(CSV, "2026-07-05T23:00:00.000Z");
    expect(changedIds.size).toBe(0);
  });

  it("builds the per-ecosystem URL", () => {
    expect(MODIFIED_CSV_URL("npm")).toBe(
      "https://osv-vulnerabilities.storage.googleapis.com/npm/modified_id.csv",
    );
    expect(MODIFIED_CSV_URL("crates.io")).toContain("/crates.io/modified_id.csv");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run src/lib/ingest/osv-modified.test.ts`
Expected: FAIL — `Cannot find module './osv-modified'`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/lib/ingest/osv-modified.ts
/**
 * OSV modified_id.csv changelog parser (DB-agnostic, pure).
 *
 * OSV publishes a per-ecosystem changelog at
 *   <base>/<eco>/modified_id.csv
 * sorted reverse-chronologically as `<iso-modified>,<primary-id>`. Consumers
 * stream from the top and stop at the first timestamp they have already seen.
 *
 * We collect the PRIMARY ids (the csv id column) verbatim — we do NOT filter
 * to CVE- here, because npm/PyPI records are keyed by GHSA-* with the CVE in
 * their aliases; filtering the csv id would drop them. CVE-only scope is
 * enforced later by bufferRecord (returns null for no-CVE-alias records).
 */

const OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com";

export function MODIFIED_CSV_URL(eco: string): string {
  return `${OSV_BASE}/${encodeURIComponent(eco)}/modified_id.csv`;
}

export function parseModifiedCsv(
  text: string,
  watermark: string | null,
): { changedIds: Set<string>; newWatermark: string | null } {
  const changedIds = new Set<string>();
  let newWatermark: string | null = null;

  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const comma = line.indexOf(",");
    if (comma === -1) continue;
    const modified = line.slice(0, comma);
    const id = line.slice(comma + 1).trim();
    if (!id) continue;

    // First (newest) line sets the new watermark.
    if (newWatermark === null) newWatermark = modified;

    // Reverse-chronological: once we reach a row at/older than the
    // watermark, everything below is already seen — stop.
    if (watermark !== null && modified <= watermark) break;

    changedIds.add(id);
  }

  return { changedIds, newWatermark };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run src/lib/ingest/osv-modified.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/lib/ingest/osv-modified.ts src/lib/ingest/osv-modified.test.ts
git commit -m "feat(ingest): OSV modified_id.csv changelog parser"
```

---

### Task 2: `sync_state` watermark SQL (`sync-state.ts`)

**Files:**
- Create: `src/lib/ingest/sync-state.ts`
- Test: `src/lib/ingest/sync-state.test.ts`

**Interfaces:**
- Consumes: `better-sqlite3` `Database` type (already a dependency).
- Produces:
  - `SYNC_STATE_DDL: string` — `CREATE TABLE IF NOT EXISTS sync_state (...)`.
  - `readWatermark(db: Database.Database, source: string): string | null`.
  - `writeWatermark(db: Database.Database, source: string, lastModified: string, updatedAt: string): void` — UPSERT by `source`.
- These operate on a **local** better-sqlite3 db (the incremental build's SQLite). The rows are later pushed to D1 by push-to-d1.sh (Task 5).

- [ ] **Step 1: Write the failing test**

```ts
// src/lib/ingest/sync-state.test.ts
import { describe, it, expect } from "vitest";
import DatabaseCtor from "better-sqlite3";
import { SYNC_STATE_DDL, readWatermark, writeWatermark } from "./sync-state";

function freshDb() {
  const db = new DatabaseCtor(":memory:");
  db.exec(SYNC_STATE_DDL);
  return db;
}

describe("sync-state", () => {
  it("returns null for a missing source (cold start)", () => {
    const db = freshDb();
    expect(readWatermark(db, "osv:npm")).toBeNull();
  });

  it("writes then reads a watermark", () => {
    const db = freshDb();
    writeWatermark(db, "osv:npm", "2026-07-05T23:00:00.000Z", "2026-07-06T05:00:00.000Z");
    expect(readWatermark(db, "osv:npm")).toBe("2026-07-05T23:00:00.000Z");
  });

  it("upserts (second write for same source overwrites)", () => {
    const db = freshDb();
    writeWatermark(db, "osv:npm", "2026-07-05T23:00:00.000Z", "2026-07-06T05:00:00.000Z");
    writeWatermark(db, "osv:npm", "2026-07-06T23:00:00.000Z", "2026-07-07T05:00:00.000Z");
    expect(readWatermark(db, "osv:npm")).toBe("2026-07-06T23:00:00.000Z");
    const rows = db.prepare("SELECT count(*) AS c FROM sync_state WHERE source='osv:npm'").get() as { c: number };
    expect(rows.c).toBe(1);
  });

  it("keeps sources independent", () => {
    const db = freshDb();
    writeWatermark(db, "osv:npm", "2026-07-05T00:00:00.000Z", "x");
    writeWatermark(db, "osv:PyPI", "2026-07-01T00:00:00.000Z", "x");
    expect(readWatermark(db, "osv:npm")).toBe("2026-07-05T00:00:00.000Z");
    expect(readWatermark(db, "osv:PyPI")).toBe("2026-07-01T00:00:00.000Z");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run src/lib/ingest/sync-state.test.ts`
Expected: FAIL — `Cannot find module './sync-state'`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/lib/ingest/sync-state.ts
/**
 * Per-source ingest watermark stored in a `sync_state` table.
 *
 * Used by the incremental OSV build to remember, per ecosystem, the newest
 * `modified` timestamp it has already ingested. The row is written into the
 * incremental SQLite and pushed to D1 by push-to-d1.sh (delta mode), so the
 * watermark advance is atomic with the data push.
 *
 * source key convention: `osv:<eco>` (e.g. `osv:npm`).
 */
import type Database from "better-sqlite3";

export const SYNC_STATE_DDL = `CREATE TABLE IF NOT EXISTS sync_state (
  source TEXT PRIMARY KEY,
  last_modified TEXT,
  updated_at TEXT
)`;

export function readWatermark(
  db: Database.Database,
  source: string,
): string | null {
  const row = db
    .prepare("SELECT last_modified FROM sync_state WHERE source = ?")
    .get(source) as { last_modified: string | null } | undefined;
  return row?.last_modified ?? null;
}

export function writeWatermark(
  db: Database.Database,
  source: string,
  lastModified: string,
  updatedAt: string,
): void {
  db.prepare(
    `INSERT INTO sync_state (source, last_modified, updated_at)
     VALUES (@source, @lastModified, @updatedAt)
     ON CONFLICT (source) DO UPDATE SET
       last_modified = excluded.last_modified,
       updated_at    = excluded.updated_at`,
  ).run({ source, lastModified, updatedAt });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run src/lib/ingest/sync-state.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/lib/ingest/sync-state.ts src/lib/ingest/sync-state.test.ts
git commit -m "feat(ingest): sync_state watermark read/write helpers"
```

---

### Task 3: `idFilter` param on `streamOsvZip`

**Files:**
- Modify: `src/lib/ingest/osv-batch.ts` (add to `StreamOsvOptions` at ~line 299; add filter check in the entry loop at ~line 540, next to `skipByName`)
- Test: `src/lib/ingest/osv-batch-idfilter.test.ts`

**Interfaces:**
- Consumes: existing `streamOsvZip(opts: StreamOsvOptions)` and `SqliteIngestSink`.
- Produces: `StreamOsvOptions` gains **optional** `idFilter?: Set<string>`. When present, a zip entry whose primary id (filename stem, i.e. basename minus `.json`) is NOT in the set is skipped **before inflate** (counts as `skipped`, not `processed`). When absent, behaviour is unchanged.

**Context:** The zip entry filename is `<PRIMARY-ID>.json` (e.g. `GHSA-52v5-jr5w-gjxr.json`, `EEF-CVE-2025-4754.json`). `modified_id.csv` lists the same primary id. So the filter compares `basename(entry.fileName).replace(/\.json$/, "")` against the set. Placing the check beside the existing `skipByName` (line ~540) means non-changed entries are never inflated — that is the efficiency of Approach B.

- [ ] **Step 1: Write the failing test**

This test builds a tiny zip in-memory-ish (written to a tmp file) with 3 OSV
records and asserts `idFilter` keeps only the in-set one. It reuses
`SqliteIngestSink` + the real schema builder to observe what was written.

```ts
// src/lib/ingest/osv-batch-idfilter.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import DatabaseCtor from "better-sqlite3";
import type Database from "better-sqlite3";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { streamOsvZip, type UpsertCtx } from "./osv-batch";
import { SqliteIngestSink } from "./sink-sqlite";
// NOTE: match the existing convention in sink-sqlite.test.ts — this repo's
// test imports of scripts/build-sqlite use the ".js" extension.
import { buildSchema } from "../../../scripts/build-sqlite.js";

// Minimal valid OSV records. Two resolve to CVEs (one in-set, one out-of-set),
// primary-id-keyed like real npm data.
function osvJson(id: string, cve: string) {
  return JSON.stringify({
    id,
    modified: "2026-07-05T00:00:00Z",
    aliases: [cve],
    affected: [
      { package: { ecosystem: "Hex", name: "demo" }, ranges: [] },
    ],
    references: [],
  });
}

let work: string;
let zipPath: string;

beforeAll(async () => {
  work = await fs.mkdtemp(join(tmpdir(), "idfilter-"));
  const dir = join(work, "z");
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(join(dir, "GHSA-in-set-0001.json"), osvJson("GHSA-in-set-0001", "CVE-2026-1111"));
  await fs.writeFile(join(dir, "GHSA-out-set-0002.json"), osvJson("GHSA-out-set-0002", "CVE-2026-2222"));
  await fs.writeFile(join(dir, "GHSA-out-set-0003.json"), osvJson("GHSA-out-set-0003", "CVE-2026-3333"));
  zipPath = join(work, "all.zip");
  // Use the system `zip` to create the archive with flat entry names.
  execFileSync("zip", ["-j", "-q", zipPath, ...[
    "GHSA-in-set-0001.json",
    "GHSA-out-set-0002.json",
    "GHSA-out-set-0003.json",
  ].map((f) => join(dir, f))]);
});

afterAll(async () => {
  await fs.rm(work, { recursive: true, force: true }).catch(() => {});
});

function sinkDb(): Database.Database {
  const db = new DatabaseCtor(":memory:");
  buildSchema(db);
  return db;
}

function ctx(): UpsertCtx {
  return {
    eco: "Hex",
    ecoMatch: () => true,
    pkgCache: new Map(),
  };
}

describe("streamOsvZip idFilter", () => {
  it("with idFilter, only in-set primary ids are written", async () => {
    const db = sinkDb();
    const sink = new SqliteIngestSink(db);
    const { imported } = await streamOsvZip({
      ctx: ctx(),
      zipPath,
      sink,
      classifyAlias: () => "ghsa",
      idFilter: new Set(["GHSA-in-set-0001"]),
    });
    expect(imported).toBe(1);
    const cves = db.prepare("SELECT cve_id FROM vulnerabilities ORDER BY cve_id").all() as { cve_id: string }[];
    expect(cves.map((r) => r.cve_id)).toEqual(["CVE-2026-1111"]);
  });

  it("without idFilter, all records are written (regression)", async () => {
    const db = sinkDb();
    const sink = new SqliteIngestSink(db);
    const { imported } = await streamOsvZip({
      ctx: ctx(),
      zipPath,
      sink,
      classifyAlias: () => "ghsa",
    });
    expect(imported).toBe(3);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run src/lib/ingest/osv-batch-idfilter.test.ts`
Expected: FAIL — the first test writes 3 records (idFilter ignored) so `imported` is `3`, not `1`.

> Note: if `buildSchema` is not currently exported from `scripts/build-sqlite.ts`, add `export` to its declaration as part of this step (it is needed by the test). Verify with: `grep -n "function buildSchema" scripts/build-sqlite.ts`.

- [ ] **Step 3: Add the optional param to the type**

In `src/lib/ingest/osv-batch.ts`, inside `interface StreamOsvOptions` (~line 299), after the `log?` field, add:

```ts
  /**
   * Optional set of PRIMARY ids (OSV record ids = zip entry filename stems,
   * e.g. "GHSA-52v5-jr5w-gjxr") to ingest. When present, any zip entry whose
   * primary id is NOT in the set is skipped BEFORE inflate — this is how the
   * incremental build ingests only changed records. When absent, every entry
   * is processed (full-build behaviour, unchanged).
   */
  idFilter?: Set<string>;
```

- [ ] **Step 4: Apply the filter before inflate**

In `streamOsvZip`, destructure `idFilter` from `opts` (line ~447):

```ts
  const { ctx, zipPath, sink, signal, onChunk, classifyAlias, log, idFilter } = opts;
```

Then in the entry loop, immediately AFTER the existing `skipByName` block
(the one that ends `skipped++; continue;` around line 548) and BEFORE the
`loggedFirstEntryPath` block, insert:

```ts
      if (idFilter) {
        // entry.fileName is "<PRIMARY-ID>.json" (possibly path-prefixed).
        const base = entry.fileName.replace(/^.*\//, "").replace(/\.json$/i, "");
        if (!idFilter.has(base)) {
          skipped++;
          continue;
        }
      }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pnpm vitest run src/lib/ingest/osv-batch-idfilter.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 6: Run the existing ingest tests (regression)**

Run: `pnpm vitest run src/lib/ingest/sink-sqlite.test.ts`
Expected: PASS (unchanged — `idFilter` absent means no behaviour change).

- [ ] **Step 7: Commit**

```bash
git add src/lib/ingest/osv-batch.ts src/lib/ingest/osv-batch-idfilter.test.ts scripts/build-sqlite.ts
git commit -m "feat(ingest): optional idFilter on streamOsvZip (skip non-changed entries pre-inflate)"
```

---

### Task 4: Incremental build entry point (`build-sqlite-incremental.ts`)

**Files:**
- Create: `scripts/build-sqlite-incremental.ts`
- Modify: `scripts/build-sqlite.ts` — export `buildSchema` and the reused helpers `canonicalizeEco`, `ingestKev`, `ingestEpss`, `DEFAULT_ECOSYSTEMS`, `downloadZipToFile`, `OSV_BASE_URL`, `classifyAlias` if not already exported (verify each with grep; add `export` where missing).
- Test: `scripts/build-sqlite-incremental.test.ts`

**Interfaces:**
- Consumes: `parseModifiedCsv`, `MODIFIED_CSV_URL` (Task 1); `SYNC_STATE_DDL`, `readWatermark`, `writeWatermark` (Task 2); `streamOsvZip` with `idFilter` (Task 3); `SqliteIngestSink`, `buildSchema`, ecosystem helpers (build-sqlite.ts).
- Produces:
  - `sevenDaysAgoIso(nowMs: number): string` — cold-start watermark helper (pure, testable).
  - `ingestOsvIncremental(opts): Promise<IncrementalResult>` — orchestrates ONE ecosystem: fetch csv → parse → spike-guard → fetch zip → streamOsvZip(idFilter) → write watermark. Returns `{ eco, changedCount, imported, skippedBySpike, watermark }`.
  - A CLI `main()` that loops the default ecosystems, runs KEV/EPSS, and writes the incremental SQLite (path from `SQLITE_OUT` env, default `scratch-phase0/vulnscope-incremental.sqlite`).

**Constants (from spec Global Constraints):**
- `SPIKE_THRESHOLD = 5000`
- `COLD_START_DAYS = 7`

- [ ] **Step 1: Write the failing test (pure helpers + spike guard)**

The orchestration does network I/O, so the unit test targets the pure pieces
and the spike guard via injected fetchers.

```ts
// scripts/build-sqlite-incremental.test.ts
import { describe, it, expect } from "vitest";
import DatabaseCtor from "better-sqlite3";
// ".js" extension matches the proven convention in sink-sqlite.test.ts.
import { buildSchema } from "./build-sqlite.js";
import { SYNC_STATE_DDL, readWatermark } from "../src/lib/ingest/sync-state";
import { sevenDaysAgoIso, ingestOsvIncremental } from "./build-sqlite-incremental";

describe("sevenDaysAgoIso", () => {
  it("returns an ISO string 7 days before the given ms", () => {
    const now = Date.parse("2026-07-08T00:00:00.000Z");
    expect(sevenDaysAgoIso(now)).toBe("2026-07-01T00:00:00.000Z");
  });
});

function db() {
  const d = new DatabaseCtor(":memory:");
  buildSchema(d);
  d.exec(SYNC_STATE_DDL);
  return d;
}

describe("ingestOsvIncremental spike guard", () => {
  it("skips the ecosystem and does NOT advance the watermark when changed > threshold", async () => {
    const d = db();
    // 5001 changed ids in the csv → over SPIKE_THRESHOLD (5000).
    const lines = Array.from({ length: 5001 }, (_, i) =>
      `2026-07-05T00:00:${String(i % 60).padStart(2, "0")}.000Z,CVE-2026-${1000 + i}`,
    ).join("\n");
    const res = await ingestOsvIncremental({
      eco: "Hex",
      db: d,
      nowMs: Date.parse("2026-07-06T00:00:00.000Z"),
      fetchCsv: async () => lines,
      // fetchZip must NOT be called when the spike guard trips.
      fetchZipToFile: async () => {
        throw new Error("fetchZip should not run on spike");
      },
    });
    expect(res.skippedBySpike).toBe(true);
    expect(readWatermark(d, "osv:Hex")).toBeNull(); // watermark untouched
  });

  it("skips (no write) when csv has no changes since watermark", async () => {
    const d = db();
    const res = await ingestOsvIncremental({
      eco: "Hex",
      db: d,
      nowMs: Date.parse("2026-07-06T00:00:00.000Z"),
      // Only one row, exactly at the watermark we seed → empty changed set.
      fetchCsv: async () => "2026-07-01T00:00:00.000Z,CVE-2026-0001",
      fetchZipToFile: async () => {
        throw new Error("fetchZip should not run when nothing changed");
      },
      // seed watermark = the only row's ts → nothing newer.
      watermarkOverride: "2026-07-01T00:00:00.000Z",
    });
    expect(res.changedCount).toBe(0);
    expect(res.imported).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run scripts/build-sqlite-incremental.test.ts`
Expected: FAIL — `Cannot find module './build-sqlite-incremental'`.

- [ ] **Step 3: Implement the orchestrator**

```ts
// scripts/build-sqlite-incremental.ts
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
```

- [ ] **Step 4: Ensure the reused exports exist**

Run: `grep -nE "export (async )?function (buildSchema|canonicalizeEco|classifyAlias|ingestKev|ingestEpss|downloadZipToFile)|export const (DEFAULT_ECOSYSTEMS|OSV_BASE_URL)" scripts/build-sqlite.ts`
Expected: each symbol appears. For any that print nothing, add `export` to its declaration in `scripts/build-sqlite.ts`. (`ingestKev`/`ingestEpss` currently take a `Database.Database` — matches usage here.)

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm vitest run scripts/build-sqlite-incremental.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 6: Type-check the whole project**

Run: `pnpm exec tsc --noEmit`
Expected: no errors.

- [ ] **Step 7: Add the package script**

In `package.json` `scripts`, add next to `build:sqlite`:

```json
    "build:sqlite:incremental": "tsx scripts/build-sqlite-incremental.ts",
```

Verify: `grep -n "build:sqlite" package.json`

- [ ] **Step 8: Commit**

```bash
git add scripts/build-sqlite-incremental.ts scripts/build-sqlite-incremental.test.ts scripts/build-sqlite.ts package.json
git commit -m "feat(ingest): incremental OSV build orchestrator (watermark + spike guard + KEV/EPSS)"
```

---

### Task 5: Push `sync_state` in delta mode (`push-to-d1.sh`)

**Files:**
- Modify: `scripts/push-to-d1.sh` — delta path (`push_delta`, ~line 156–345) and full path table lists.
- Test: `scripts/push-to-d1-syncstate.test.sh` (a bash assertion script) OR manual verification (see steps).

**Interfaces:**
- Consumes: an incremental SQLite that now contains a `sync_state` table (Task 4).
- Produces: the delta SQL emits, AFTER all data statements, `CREATE TABLE IF NOT EXISTS sync_state (...)` and one `INSERT ... ON CONFLICT(source) DO UPDATE` per `sync_state` row. Full mode includes `sync_state` in its dumped base tables.

**Context:** In `push_delta` (see `scripts/push-to-d1.sh`), data statements are appended to `$DELTA_SQL` through section (e) FTS. The `sync_state` block MUST come AFTER section (d) sync_jobs and the FTS section — it is the last thing appended — so a mid-push batch failure cannot advance a watermark ahead of un-landed data (spec Global Constraint).

- [ ] **Step 1: Add `sync_state` to full mode's base tables**

In `push_full`, the `BASE_TABLES` line (~line 105) and the `DROP TABLE` preamble (~line 108-114): add `sync_state`. Change:

```bash
  local BASE_TABLES="vulnerabilities packages affected cvss_scores vuln_aliases refs sync_jobs"
```
to:
```bash
  local BASE_TABLES="vulnerabilities packages affected cvss_scores vuln_aliases refs sync_jobs sync_state"
```

And in the heredoc preamble add as the first DROP:
```sql
DROP TABLE IF EXISTS sync_state;
```

- [ ] **Step 2: Emit sync_state UPSERTs at the END of the delta SQL**

In `push_delta`, AFTER the FTS section (e) block that ends near line ~324
(the `packages_fts` insert), and BEFORE the `grep -vE "$STRIP"` clean step
(~line 327), append:

```bash
  # ── (f) sync_state: watermark rows. MUST be emitted LAST (after all data +
  #        FTS), so a mid-push failure cannot advance a watermark ahead of data
  #        that never landed. create-if-not-exists then UPSERT by source. ──
  cat >> "$DELTA_SQL" <<'DDL'
CREATE TABLE IF NOT EXISTS sync_state (source TEXT PRIMARY KEY, last_modified TEXT, updated_at TEXT);
DDL
  # Only emit if the incremental SQLite actually has a sync_state table.
  if sqlite3 "$SQLITE_FILE" "SELECT name FROM sqlite_master WHERE type='table' AND name='sync_state';" | grep -q sync_state; then
    sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO sync_state (source, last_modified, updated_at) VALUES ('
  || quote(source) || ',' || quote(last_modified) || ',' || quote(updated_at)
  || ') ON CONFLICT(source) DO UPDATE SET last_modified=excluded.last_modified, updated_at=excluded.updated_at;'
FROM sync_state;
SQL
  fi
```

- [ ] **Step 3: Add sync_state to the verification loop**

In the verification `for TBL in ...` list at the end of the script (~line 350),
add `sync_state`:

```bash
for TBL in vulnerabilities packages affected cvss_scores vuln_aliases refs sync_jobs sync_state vulns_fts packages_fts; do
```

- [ ] **Step 4: Verify the generated delta SQL locally (no D1 needed)**

Build a tiny incremental SQLite with a sync_state row, then dry-run the delta
SQL generation by pointing the script at it but stopping before the push.
Simplest: assert the emitted order with a scratch run.

Run:
```bash
cd /Users/jnr350/Desktop/Yansiang/cve_list
# Build a 1-ecosystem incremental file (Hex is tiny).
INGEST_ECOSYSTEMS=Hex SQLITE_OUT=/tmp/inc.sqlite pnpm build:sqlite:incremental
# Confirm it has a sync_state row.
sqlite3 /tmp/inc.sqlite "SELECT source, last_modified FROM sync_state;"
```
Expected: at least one `osv:Hex|<timestamp>` row (or empty if Hex had no
changes in the last 7 days — in that case pick a busier ecosystem like `npm`).

- [ ] **Step 5: End-to-end against a throwaway D1**

```bash
cd /Users/jnr350/Desktop/Yansiang/cve_list
DBID=$(wrangler d1 create vulnscope-inctest 2>&1 | grep -oE '"database_id": "[^"]*"' | cut -d'"' -f4)
# Seed schema (reuse full-mode DDL via a tiny full push of the incremental file
# is overkill; instead create the base tables the delta expects). Simplest:
# run a FULL push of the incremental file first so tables exist, then a delta.
SQLITE_FILE=/tmp/inc.sqlite D1_DATABASE=vulnscope-inctest bash scripts/push-to-d1.sh /tmp/inc.sqlite vulnscope-inctest full
# Now confirm sync_state landed:
wrangler d1 execute vulnscope-inctest --remote --command="SELECT source, last_modified FROM sync_state" 2>&1 | grep osv
# Cleanup
wrangler d1 delete vulnscope-inctest --yes
```
Expected: the `osv:*` watermark row is present in D1.

- [ ] **Step 6: Commit**

```bash
git add scripts/push-to-d1.sh
git commit -m "feat(ingest): push sync_state watermarks to D1 (delta emits them last)"
```

---

### Task 6: Wire incremental OSV into the daily GitHub Actions job

**Files:**
- Modify: `.github/workflows/ingest.yml` — the daily `refresh-kev-epss` job.

**Interfaces:**
- Consumes: `pnpm build:sqlite:incremental` (Task 4), `push-to-d1.sh` delta (Task 5).
- Produces: the daily job builds the incremental SQLite (OSV changed records + KEV/EPSS) and delta-pushes it, advancing watermarks.

**Context:** The current daily job (`refresh-kev-epss`, ~line 87–121) runs `build:sqlite` with `INGEST_ECOSYSTEMS=" "` (KEV/EPSS only) then delta-pushes. Incremental OSV replaces the build step: `build:sqlite:incremental` already does KEV/EPSS too, so it is a drop-in that ALSO refreshes OSV.

- [ ] **Step 1: Rename the job and update its build step**

In `.github/workflows/ingest.yml`, replace the `refresh-kev-epss` job's name and
the "Build SQLite" step. Change the job name:

```yaml
  refresh-daily:
    name: "Daily: OSV incremental + KEV + EPSS"
```
(keep the same `if:` schedule guard `github.event.schedule == '0 5 * * *'`).

Replace the build step (the one with `INGEST_ECOSYSTEMS: " "`) with:

```yaml
      - name: Build SQLite — incremental OSV + KEV + EPSS
        # Reads per-ecosystem watermarks from D1 (carried in the SQLite's
        # sync_state after the previous push), ingests only OSV records changed
        # since, plus a full KEV/EPSS refresh. Default ecosystems = all 13.
        env:
          SQLITE_OUT: scratch-phase0/vulnscope-incremental.sqlite
        run: pnpm build:sqlite:incremental
```

- [ ] **Step 2: Point the push step at the incremental file**

The push step currently runs `bash scripts/push-to-d1.sh vulnscope` (delta).
Update it to pass the incremental file explicitly:

```yaml
      - name: Push to D1 (delta — merge changed OSV + KEV/EPSS, advance watermarks)
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          PUSH_MODE: delta
        run: bash scripts/push-to-d1.sh scratch-phase0/vulnscope-incremental.sqlite vulnscope delta
```

- [ ] **Step 3: Seed the initial watermark into D1 (one-time note)**

Add a comment above the daily job documenting cold start (no code):

```yaml
  # On the FIRST incremental run, D1's sync_state is empty, so each ecosystem
  # cold-starts at "7 days ago" (one-time larger delta, still under the free
  # cap). Subsequent runs pull ~1 day each.
```

- [ ] **Step 4: Validate YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ingest.yml')); print('YAML OK')"`
Expected: `YAML OK`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ingest.yml
git commit -m "ci: daily job ingests incremental OSV alongside KEV/EPSS"
```

---

### Task 7: Documentation + end-to-end verification

**Files:**
- Modify: `docs/phase6-cutover.md` OR create `docs/incremental-ingest.md` — operator notes.

- [ ] **Step 1: Write operator doc**

Create `docs/incremental-ingest.md`:

```markdown
# Incremental OSV Ingest (operator notes)

The daily "Ingest → D1" job now refreshes OSV vuln data incrementally, not just
KEV/EPSS. It reads OSV's `modified_id.csv` per ecosystem, ingests only records
changed since a watermark stored in D1's `sync_state` table, and delta-pushes.

## Watermarks
- Table: `sync_state (source, last_modified, updated_at)`, one row per source
  `osv:<eco>` (e.g. `osv:npm`).
- A watermark advances ONLY after that ecosystem's data lands in D1.
- Inspect: `wrangler d1 execute vulnscope --remote --command="SELECT * FROM sync_state ORDER BY source"`

## Cold start
- Empty `sync_state` → each ecosystem starts at 7 days ago on first run.

## Spike guard
- If an ecosystem has > 5000 changed records in one run, it is skipped and
  logged (watermark untouched). Re-run, or do a manual full refresh
  (workflow_dispatch, ecosystems="full") to catch up.

## Manual full refresh (unchanged)
- Still available via Actions → "Ingest → D1" → Run workflow → ecosystems="full"
  (Workers Paid recommended for the ~677k-row write).

## Reset a watermark (force re-pull)
- `wrangler d1 execute vulnscope --remote --command="DELETE FROM sync_state WHERE source='osv:npm'"`
  → next run cold-starts npm at 7 days ago.
```

- [ ] **Step 2: Full end-to-end dry run (busy ecosystem)**

```bash
cd /Users/jnr350/Desktop/Yansiang/cve_list
INGEST_ECOSYSTEMS=npm SQLITE_OUT=/tmp/inc-npm.sqlite pnpm build:sqlite:incremental
sqlite3 /tmp/inc-npm.sqlite "SELECT (SELECT count(*) FROM vulnerabilities) AS vulns, (SELECT count(*) FROM sync_state) AS watermarks;"
```
Expected: `vulns` > 0 (npm changes in last 7 days), `watermarks` = 1.

- [ ] **Step 3: Run the whole test suite**

Run: `pnpm vitest run`
Expected: all tests pass (new + existing).

- [ ] **Step 4: Type-check**

Run: `pnpm exec tsc --noEmit`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add docs/incremental-ingest.md
git commit -m "docs: incremental OSV ingest operator notes"
```

---

## Notes for the executor

- **Watermark idempotency:** re-running the daily job before the next OSV change
  produces an empty changed set per ecosystem → near-zero writes. Safe.
- **The `sync_state` write is the last delta statement** — never reorder it
  before data. This is the correctness linchpin.
- **`idFilter` matches primary ids** (zip filename stems), never resolved CVE
  ids. Do not "helpfully" filter the csv to `CVE-` — that drops GHSA-keyed CVEs.
- **Regression guard:** `build-sqlite.ts` full mode and `sink-sqlite.test.ts`
  must stay green; `idFilter` absent = no behaviour change.
