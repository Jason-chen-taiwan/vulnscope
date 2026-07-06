# Incremental OSV Ingest — Design

**Date:** 2026-07-06
**Status:** Approved (brainstorming) → ready for implementation plan

## Goal

Keep the OSV vulnerability data (the `affected` / `refs` / `cvss_scores` rows
and vulnerability body text — ~95% of the dataset) automatically fresh every
day, staying within the Cloudflare D1 free tier (100k row-writes/day), running
in GitHub Actions with no local state between runs.

## Background & why this shape

The site migrated to Cloudflare Workers + D1. Two ingest paths exist today:

- **Daily** — KEV + EPSS only. Small (~1631 CVEs), touches only the
  `kev` / `epss_*` columns. Well under the free write cap.
- **On-demand full** — a full 13-ecosystem OSV DROP+rebuild (~677k row writes).
  Over the free cap, so it is NOT scheduled; run manually on Workers Paid.

The gap: between manual full refreshes, **OSV vulnerability data goes stale** —
new CVEs and updated affected-package ranges don't land. KEV/EPSS keep the
*urgent* signals current but do not add or update the vuln bodies.

### Why not NVD / GHSA

We evaluated pulling NVD (`lastModStartDate`) or GHSA (`updatedSince`) as
incremental sources. Rejected because:

- **GHSA is already an upstream of OSV** — OSV already ingests GHSA. Pulling
  GHSA separately duplicates data OSV will carry anyway.
- **NVD cannot supply `affected`** — NVD has no per-ecosystem "package X
  version Y is vulnerable" data. The dataset's bulk (`affected`, 119k rows)
  has exactly one incremental source: OSV itself.

So the correct fix is to make **OSV's own feed** incremental, not to add a
second source. This also avoids all multi-source precedence/merge complexity.

### The enabling discovery

OSV publishes a purpose-built changelog for incremental consumers:

- Per-ecosystem: `https://osv-vulnerabilities.storage.googleapis.com/<ECO>/modified_id.csv`
- Format: `<iso-modified-timestamp>,<id>` — e.g. `2026-07-05T23:56:26.681Z,CVE-2026-1234`
- **Sorted reverse-chronologically** (newest first).
- OSV docs: "stream the file and stop when you encounter a timestamp you have
  already seen."

Verified live (2026-07-06): the CSV exists per-ecosystem, is reverse-sorted,
and individual records are fetchable at `<ECO>/<ID>.json`. npm shows ~48
changed records/day; most recent changes are `MAL-*` (malicious-package
reports) and `GHSA-*`, with `CVE-*` a minority.

## Decisions (locked)

1. **Source:** OSV incremental only (no NVD/GHSA).
2. **Fetch strategy — Approach B:** read `modified_id.csv` to compute the set
   of changed CVE-IDs since the watermark, then download the existing
   `<ECO>/all.zip` and stream it, upserting **only** records whose id is in the
   changed set. Reuses the existing `streamOsvZip` verbatim (plus one optional
   filter param). The zip download is free bandwidth in GitHub Actions; D1
   writes — the real constraint — are limited to changed records only.
3. **Record scope:** CVE-`xxxx` only. `MAL-*` and CVE-less `GHSA-*` records are
   filtered out, matching the current dataset (all 74,280 rows are `CVE-*`).
4. **Watermark storage:** a `sync_state` table in D1 (single source of truth,
   co-located with the data). Read at the start of each run, advanced only
   after that ecosystem's data successfully lands in D1.
5. **Schedule:** folded into the existing daily 05:00 UTC job, after KEV/EPSS.
   One job → one delta push → one watermark update.

## Architecture

Per ecosystem, independently:

```
① Read watermark for this ecosystem from D1 sync_state
   (cold start / missing row → default to "7 days ago")
② Stream {eco}/modified_id.csv (reverse-chronological); stop at first
   timestamp ≤ watermark. Collect the PRIMARY ids (the csv's id column) of
   every changed record — NOT pre-filtered to "CVE-".
   → changedIds: Set<string>, newWatermark = timestamp of first (newest) line
③ If changedIds is empty → skip this ecosystem (nothing changed)
④ Download {eco}/all.zip; run streamOsvZip with idFilter = changedIds,
   matching on the record's PRIMARY id (rec.id). Only changed records are
   written. CVE-only scope is enforced downstream: bufferRecord returns null
   for records with no CVE alias, so MAL-* and CVE-less GHSA-* are dropped.
⑤ push-to-d1.sh delta mode pushes the SQLite to D1 (existing batching+retry)
⑥ On success, UPSERT sync_state.last_modified = newWatermark for this ecosystem
```

### Core invariant

**A watermark advances only after that ecosystem's data has successfully
landed in D1.** Any failure (CSV fetch, zip download, delta push, or a spike
guard trip) leaves the watermark unchanged, so the next run re-processes from
the old watermark. Re-processing is idempotent — `Set.has` + the delta push's
`COALESCE`/existing-wins upsert make re-applying a record harmless. **Data is
never silently dropped.**

## Components

### New: `src/lib/ingest/osv-modified.ts`

Pure, DB-agnostic. Parses a `modified_id.csv` stream.

- **Consumes:** ecosystem name, watermark timestamp (ISO string | null).
- **Produces:** `{ changedIds: Set<string>, newWatermark: string | null }`.
- **Logic:** stream lines; for each `[modified, id]`, stop when
  `modified <= watermark`; collect the primary `id` verbatim (NO `CVE-`
  prefix filter — npm/PyPI records are keyed by `GHSA-*` with the CVE in
  aliases; filtering the csv id would drop them);
  `newWatermark` = the timestamp of the first (newest) line, or `null` if the
  CSV was empty.
- Timestamp comparison is ISO-8601 lexical string comparison (valid because
  all timestamps are UTC `Z` with identical format).

### New: `src/lib/ingest/sync-state.ts`

Owns the `sync_state` read/write SQL.

- Schema: `CREATE TABLE IF NOT EXISTS sync_state (source TEXT PRIMARY KEY,
  last_modified TEXT, updated_at TEXT)`.
- `readWatermark(source)` → the stored `last_modified`, or `null` on a missing
  row (cold start).
- `writeWatermark(source, ts)` → UPSERT by `source`.
- `source` key convention: `osv:<eco>` (e.g. `osv:npm`).

### New: `scripts/build-sqlite-incremental.ts`

Incremental build entry point, parallel to `build-sqlite.ts`. Reuses
`SqliteIngestSink` + `streamOsvZip`. Orchestrates the per-ecosystem flow (steps
①–④ + ⑥), writing changed records and the new watermarks into the incremental
SQLite. Does **not** modify `build-sqlite.ts` (full mode stays as-is).

### Changed: `streamOsvZip` (`src/lib/ingest/osv-batch.ts`)

Add one **optional** param `idFilter?: Set<string>`.

- With filter: `if (idFilter && !idFilter.has(record.id)) continue;`
- Without filter: behaviour is **identical** to today — existing full build and
  `sink-sqlite.test.ts` are unaffected (regression-guarded).

### Watermark round-trip (no `push-to-d1.sh` logic change)

The incremental build writes the new watermarks into the SQLite's `sync_state`
table as ordinary rows. The delta push carries them to D1 the same way it
already carries `sync_jobs` rows (append/upsert). This keeps the
watermark-advance atomic with the data push. The only `push-to-d1.sh` change is
additive: register `sync_state` in the delta push's table list (create-if-not-
exists + UPSERT by `source`) alongside the existing `sync_jobs` handling — the
batching/retry logic is unchanged.

**Ordering note:** `sync_state` UPSERT statements must be emitted in the delta
SQL *after* all data statements for the run, so a mid-push failure (which aborts
the remaining batches) cannot advance a watermark ahead of data that never
landed. This preserves the core invariant at the SQL level.

## Scheduling & write budget

Folded into the existing daily 05:00 UTC job, after KEV/EPSS:

```
Daily 05:00 UTC — one job:
  1. KEV/EPSS delta        (existing, unchanged)
  2. OSV incremental       (new: all 13 ecosystems, Approach B)
  → merged into one SQLite → one delta push to D1
```

### Write budget (vs D1 free 100k rows/day)

| Source            | Daily change       | Est. D1 row-writes |
| ----------------- | ------------------ | ------------------ |
| KEV/EPSS (exist)  | ~1631 CVEs         | ~16k               |
| OSV incremental   | ~500–1500 CVEs     | ~8k–23k            |
| **Total**         |                    | **~24k–39k**       |

≈ 24–39% of the free cap. Comfortable margin.

### Spike guard

If an ecosystem's changed-CVE count exceeds a threshold (**5000**), skip that
ecosystem for this run, record it in `sync_jobs.error_message`, and **do not
advance its watermark**. Prevents an abnormal OSV mass-re-modification (e.g. a
Debian batch) from blowing the free cap. Normal days never trip this; the
skipped ecosystem is caught up by the next run or a manual full refresh.

### Cold start

Empty `sync_state` for an ecosystem → initial watermark = "7 days ago". The
first run ingests the last 7 days of changes (one-time, still within the free
cap); subsequent runs pull ~1 day each.

## Error handling

| Situation                         | Handling                                              |
| --------------------------------- | ---------------------------------------------------- |
| `modified_id.csv` fetch fails     | Skip ecosystem, record error, watermark unchanged    |
| zip download fails                | Skip ecosystem, record error, watermark unchanged    |
| delta push to D1 fails            | No watermarks advance; next run re-runs from old      |
| changed count > 5000 (spike)      | Skip ecosystem, alert, watermark unchanged            |
| `sync_state` row missing          | Treat as cold start → "7 days ago"                    |

Each ecosystem is independent: one ecosystem's failure does not block others.

## Testing (TDD)

| Component                     | Tests                                                                                     |
| ----------------------------- | ----------------------------------------------------------------------------------------- |
| `osv-modified.ts`             | Fake CSV strings: (a) reverse-order stop-at-watermark; (b) CVE-only filter; (c) newWatermark = newest line; (d) empty / all-old CSV → empty set, null watermark |
| `sync-state.ts`               | Generated SELECT/UPSERT SQL correct; missing row → null (cold start)                       |
| `streamOsvZip` idFilter       | Small zip fixture: with filter only in-set ids written; without filter identical to today (regression) |
| `build-sqlite-incremental.ts` | Integration: mock CSV + small zip → only changed CVEs in SQLite + watermarks written       |
| End-to-end                    | Real run against a throwaway D1 (as done for the batching fix)                             |

### Regression protection

`build-sqlite.ts` full mode and `sink-sqlite.test.ts` are untouched and must
stay green. `idFilter` is optional; omitting it changes nothing.

## Out of scope

- NVD / GHSA ingest (rejected above).
- MAL-* / CVE-less GHSA-* records (scope decision: CVE-only).
- Changes to full/manual refresh or KEV/EPSS paths.
- `push-to-d1.sh` batching/retry logic (already in place).
