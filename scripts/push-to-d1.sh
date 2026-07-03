#!/usr/bin/env bash
# push-to-d1.sh — Dump a local SQLite dataset and push it to a Cloudflare D1 database.
#
# Usage:
#   bash scripts/push-to-d1.sh [sqlite-file] [d1-database-name]
#
# Or via environment variables:
#   SQLITE_FILE=/path/to/file.sqlite D1_DATABASE=vulnscope bash scripts/push-to-d1.sh
#
# Defaults:
#   SQLITE_FILE  → <repo-root>/scratch-phase0/vulnscope.sqlite   (build:sqlite output)
#   D1_DATABASE  → vulnscope
#
# Steps reproduced faithfully from the Phase-0 spike (proven against D1):
#   1. Dump the 7 base tables (NOT FTS shadow tables — those must be rebuilt).
#   2. Strip lines D1 rejects: BEGIN TRANSACTION, COMMIT, PRAGMA.
#   3. Import via `wrangler d1 execute --file --remote`.
#   4. Rebuild FTS5 virtual tables on D1 (DROP + CREATE + INSERT for idempotency).
set -euo pipefail

# ── Resolve paths ────────────────────────────────────────────────────────────
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SQLITE_FILE="${1:-${SQLITE_FILE:-$ROOT/scratch-phase0/vulnscope.sqlite}}"
D1_DATABASE="${2:-${D1_DATABASE:-vulnscope}}"

# ── Temp-file workspace ──────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

D1_IMPORT_SQL="$WORK_DIR/d1-import.sql"
BUILD_FTS_SQL="$WORK_DIR/build-fts.sql"

# ── Validate inputs ──────────────────────────────────────────────────────────
if [[ ! -f "$SQLITE_FILE" ]]; then
  echo "[push-to-d1] ERROR: SQLite file not found: $SQLITE_FILE"
  echo "  Build it first with:  INGEST_ECOSYSTEMS=Hex pnpm build:sqlite"
  exit 1
fi

echo "[push-to-d1] ══════════════════════════════════════════════"
echo "[push-to-d1] sqlite file : $SQLITE_FILE"
echo "[push-to-d1] D1 database : $D1_DATABASE"
echo "[push-to-d1] ══════════════════════════════════════════════"

# ── Step 1 & 2: Dump base tables, strip D1-incompatible lines ────────────────
echo
echo "[push-to-d1] [1/4] Dumping 7 base tables and stripping D1-rejected lines …"
# Tables to dump (base tables only — NOT FTS5 shadow tables):
BASE_TABLES="vulnerabilities packages affected cvss_scores vuln_aliases refs sync_jobs"

# Prepend DROP TABLE IF EXISTS for each base table so re-runs are idempotent.
# Order matters for FK-less SQLite but D1 doesn't enforce FKs by default, so
# any order is fine. Drop indexes first via the DROP TABLE (SQLite drops
# dependent indexes automatically).
cat > "$D1_IMPORT_SQL" <<'PREAMBLE'
DROP TABLE IF EXISTS sync_jobs;
DROP TABLE IF EXISTS refs;
DROP TABLE IF EXISTS vuln_aliases;
DROP TABLE IF EXISTS cvss_scores;
DROP TABLE IF EXISTS affected;
DROP TABLE IF EXISTS packages;
DROP TABLE IF EXISTS vulnerabilities;
PREAMBLE

sqlite3 "$SQLITE_FILE" ".dump $BASE_TABLES" \
  | grep -vE '^(BEGIN TRANSACTION|COMMIT|PRAGMA )' \
  >> "$D1_IMPORT_SQL"

LINE_COUNT=$(wc -l < "$D1_IMPORT_SQL")
echo "[push-to-d1]   → d1-import.sql: ${LINE_COUNT} lines"

# ── Step 3: Push base data to D1 ─────────────────────────────────────────────
echo
echo "[push-to-d1] [2/4] Importing base data into D1 ($D1_DATABASE) …"
echo "[push-to-d1]   (This may take several minutes for large datasets)"
wrangler d1 execute "$D1_DATABASE" \
  --file="$D1_IMPORT_SQL" \
  --remote \
  --yes

echo "[push-to-d1]   → base import complete"

# ── Step 4: Rebuild FTS5 virtual tables on D1 ────────────────────────────────
# FTS5 virtual tables cannot be dumped and restored as plain SQL — the .dump
# command emits shadow tables that D1 cannot accept. Instead, we DROP + CREATE
# + INSERT on D1 directly. This is idempotent: re-runs safely replace old FTS.
echo
echo "[push-to-d1] [3/4] Rebuilding FTS5 indexes on D1 …"
cat > "$BUILD_FTS_SQL" <<'SQL'
-- Drop existing FTS tables (idempotent re-run safety)
DROP TABLE IF EXISTS vulns_fts;
DROP TABLE IF EXISTS packages_fts;

-- Rebuild vulns_fts: full-text search over CVE id/summary/description
CREATE VIRTUAL TABLE vulns_fts USING fts5(
  cve_id, summary, description, tokenize='porter unicode61'
);
INSERT INTO vulns_fts(cve_id, summary, description)
  SELECT cve_id, summary, description FROM vulnerabilities;

-- Rebuild packages_fts: trigram fuzzy search over package names
CREATE VIRTUAL TABLE packages_fts USING fts5(
  name, tokenize='trigram'
);
INSERT INTO packages_fts(rowid, name)
  SELECT id, name FROM packages;
SQL

wrangler d1 execute "$D1_DATABASE" \
  --file="$BUILD_FTS_SQL" \
  --remote \
  --yes

echo "[push-to-d1]   → FTS rebuild complete"

# ── Step 5: Verify ───────────────────────────────────────────────────────────
# D1 limits the number of compound SELECT terms, so query each table separately.
echo
echo "[push-to-d1] [4/4] Verification counts …"
for TBL in vulnerabilities packages affected sync_jobs vulns_fts packages_fts; do
  printf "  %-20s " "$TBL:"
  wrangler d1 execute "$D1_DATABASE" \
    --remote \
    --command="SELECT count(*) AS cnt FROM $TBL" \
    2>&1 | grep -E '"cnt"' | head -1 || echo "(query failed)"
done

echo
echo "[push-to-d1] ✓ Push complete — D1 database: $D1_DATABASE"
