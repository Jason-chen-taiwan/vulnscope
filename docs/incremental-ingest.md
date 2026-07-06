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
