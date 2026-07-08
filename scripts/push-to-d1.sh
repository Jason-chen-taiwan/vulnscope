#!/usr/bin/env bash
# push-to-d1.sh — Push a local SQLite dataset to a Cloudflare D1 database.
#
# Two modes, selected via PUSH_MODE (env) or the 3rd positional arg:
#
#   full   — Cold seed / weekly full refresh. DROP + recreate all base tables,
#            import everything, then rebuild the FTS5 indexes from scratch.
#            Correct because a full build contains ALL data, so a full replace
#            loses nothing. Used by Phase-6 cold seed and the weekly OSV job.
#
#   delta  — Daily incremental refresh (DEFAULT). NEVER drops anything. Merges
#            the delta SQLite onto D1's existing data:
#              • vulnerabilities: INSERT ... ON CONFLICT(cve_id) DO UPDATE (upsert)
#              • packages:        INSERT ... ON CONFLICT(id) DO UPDATE (upsert)
#              • affected / cvss_scores / vuln_aliases / refs: for each cve_id in
#                the delta, DELETE that cve_id's rows then INSERT the delta's rows
#                (these child tables have NO unique key, so replace-per-cve is the
#                only correct dedupe — a CVE fully owns its child rows).
#              • sync_jobs: append the delta's bookkeeping rows.
#              • FTS: re-index only the changed CVEs / new packages — the whole
#                corpus is NOT re-read (that would blow the D1 write quota).
#
#   WHY delta exists: the daily ingest builds a KEV/EPSS-only SQLite (no OSV).
#   The old script DROPPED every base table before importing, so each daily run
#   WIPED all OSV data (the bulk of CVEs) from D1 until the weekly full refresh —
#   the site was broken 6 days out of 7. Delta mode merges instead of replacing,
#   leaving existing OSV data intact while applying the day's KEV/EPSS changes.
#
# Usage:
#   bash scripts/push-to-d1.sh [sqlite-file] [d1-database-name] [full|delta]
#   PUSH_MODE=full  bash scripts/push-to-d1.sh vulnscope           # weekly / cold seed
#   PUSH_MODE=delta bash scripts/push-to-d1.sh vulnscope           # daily (default)
#
# Env overrides: SQLITE_FILE, D1_DATABASE, PUSH_MODE.
# Defaults: SQLITE_FILE → <repo>/scratch-phase0/vulnscope.sqlite ; D1_DATABASE → vulnscope
#           PUSH_MODE   → delta (safe: never wipes existing data).
set -euo pipefail

# ── Resolve paths & mode ─────────────────────────────────────────────────────
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Resolve the wrangler CLI. In CI (GitHub Actions) wrangler is NOT on PATH as a
# global — it's a project devDependency — so prefer the local install and fall
# back to a global `wrangler` for dev machines that have it installed globally.
if [[ -x "$ROOT/node_modules/.bin/wrangler" ]]; then
  WRANGLER="$ROOT/node_modules/.bin/wrangler"
elif command -v wrangler >/dev/null 2>&1; then
  WRANGLER="wrangler"
else
  WRANGLER="pnpm exec wrangler"
fi

# Positional args: $1 may be the sqlite file OR (for convenience) the db name.
# We keep the historical order [sqlite] [db] [mode] but also accept the common
# call `push-to-d1.sh <dbname>` where the first arg is actually the db name.
ARG1="${1:-}"
ARG2="${2:-}"
ARG3="${3:-}"

if [[ -n "$ARG1" && ! -f "$ARG1" && "$ARG1" != *.sqlite && -z "$ARG2" ]]; then
  # Single non-file arg → treat as the D1 database name.
  SQLITE_FILE="${SQLITE_FILE:-$ROOT/scratch-phase0/vulnscope.sqlite}"
  D1_DATABASE="$ARG1"
else
  SQLITE_FILE="${ARG1:-${SQLITE_FILE:-$ROOT/scratch-phase0/vulnscope.sqlite}}"
  D1_DATABASE="${ARG2:-${D1_DATABASE:-vulnscope-v2}}"
fi

PUSH_MODE="${ARG3:-${PUSH_MODE:-delta}}"

# emit-stats-sql runs from $ROOT; make the sqlite path absolute so it resolves.
if [[ -f "$SQLITE_FILE" ]]; then
  SQLITE_FILE="$(cd "$(dirname "$SQLITE_FILE")" && pwd)/$(basename "$SQLITE_FILE")"
fi

if [[ "$PUSH_MODE" != "full" && "$PUSH_MODE" != "delta" && "$PUSH_MODE" != "stats-rebuild" ]]; then
  echo "[push-to-d1] ERROR: PUSH_MODE must be 'full', 'delta' or 'stats-rebuild' (got '$PUSH_MODE')"
  exit 1
fi

# ── Temp-file workspace ──────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# D1 rejects BEGIN TRANSACTION / COMMIT / PRAGMA — strip them from any dump.
STRIP='^(BEGIN TRANSACTION|COMMIT|PRAGMA )'

# ── Validate inputs ──────────────────────────────────────────────────────────
if [[ "$PUSH_MODE" != "stats-rebuild" ]]; then
  if [[ ! -f "$SQLITE_FILE" ]]; then
    echo "[push-to-d1] ERROR: SQLite file not found: $SQLITE_FILE"
    echo "  Build it first with:  INGEST_ECOSYSTEMS=Hex pnpm build:sqlite"
    exit 1
  fi
fi

echo "[push-to-d1] ══════════════════════════════════════════════"
echo "[push-to-d1] sqlite file : $SQLITE_FILE"
echo "[push-to-d1] D1 database : $D1_DATABASE"
echo "[push-to-d1] mode        : $PUSH_MODE"
echo "[push-to-d1] ══════════════════════════════════════════════"

# ─────────────────────────────────────────────────────────────────────────────
#  FULL MODE — DROP + recreate + import + rebuild FTS (cold seed / weekly)
# ─────────────────────────────────────────────────────────────────────────────
push_full() {
  local D1_IMPORT_SQL="$WORK_DIR/d1-import.sql"
  local BUILD_FTS_SQL="$WORK_DIR/build-fts.sql"

  echo
  echo "[push-to-d1] [full 1/4] Dumping base tables (DROP + recreate) …"
  local BASE_TABLES="vulnerabilities packages affected cvss_scores vuln_aliases refs sync_jobs sync_state page_stats package_stats"

  cat > "$D1_IMPORT_SQL" <<'PREAMBLE'
DROP TABLE IF EXISTS package_stats;
DROP TABLE IF EXISTS page_stats;
DROP TABLE IF EXISTS sync_state;
DROP TABLE IF EXISTS sync_jobs;
DROP TABLE IF EXISTS refs;
DROP TABLE IF EXISTS vuln_aliases;
DROP TABLE IF EXISTS cvss_scores;
DROP TABLE IF EXISTS affected;
DROP TABLE IF EXISTS packages;
DROP TABLE IF EXISTS vulnerabilities;
PREAMBLE

  sqlite3 "$SQLITE_FILE" ".dump $BASE_TABLES" \
    | grep -vE "$STRIP" \
    >> "$D1_IMPORT_SQL"

  echo "[push-to-d1]   → d1-import.sql: $(wc -l < "$D1_IMPORT_SQL") lines"

  echo
  echo "[push-to-d1] [full 2/4] Importing base data into D1 ($D1_DATABASE) …"
  $WRANGLER d1 execute "$D1_DATABASE" --file="$D1_IMPORT_SQL" --remote --yes
  echo "[push-to-d1]   → base import complete"

  echo
  echo "[push-to-d1] [full 3/4] Rebuilding FTS5 indexes on D1 …"
  cat > "$BUILD_FTS_SQL" <<'SQL'
DROP TABLE IF EXISTS vulns_fts;
DROP TABLE IF EXISTS packages_fts;

CREATE VIRTUAL TABLE vulns_fts USING fts5(
  cve_id, summary, description, tokenize='porter unicode61'
);
INSERT INTO vulns_fts(cve_id, summary, description)
  SELECT cve_id, summary, description FROM vulnerabilities;

CREATE VIRTUAL TABLE packages_fts USING fts5(
  name, tokenize='trigram'
);
INSERT INTO packages_fts(rowid, name)
  SELECT id, name FROM packages;
SQL

  $WRANGLER d1 execute "$D1_DATABASE" --file="$BUILD_FTS_SQL" --remote --yes
  echo "[push-to-d1]   → FTS rebuild complete"

  echo
  echo "[push-to-d1] [full 4/4] Ensuring plain indexes exist …"
  # INCIDENT GUARD (2026-07-08): the vulnscope-v2 full import silently landed
  # WITHOUT any of the dump's CREATE INDEX statements — every query full-scanned
  # (a single refs lookup read 256k rows; crawler facet queries hit 125M rows /
  # 36s and monopolized the instance). The dump DOES contain the indexes, so the
  # loss happens somewhere in the wrangler/D1 import path. Never trust it again:
  # recreate every index explicitly (IF NOT EXISTS = no-op when import behaved),
  # then FAIL LOUDLY if the count still disagrees.
  local ENSURE_IDX_SQL="$WORK_DIR/ensure-indexes.sql"
  sqlite3 "$SQLITE_FILE" \
    "SELECT sql || ';' FROM sqlite_master WHERE type='index' AND sql IS NOT NULL" \
    | sed 's/^CREATE INDEX /CREATE INDEX IF NOT EXISTS /' > "$ENSURE_IDX_SQL"
  local WANT_IDX
  WANT_IDX=$(grep -c 'CREATE INDEX' "$ENSURE_IDX_SQL" | tr -d ' ')
  $WRANGLER d1 execute "$D1_DATABASE" --file="$ENSURE_IDX_SQL" --remote --yes
  local HAVE_IDX
  HAVE_IDX=$($WRANGLER d1 execute "$D1_DATABASE" --remote --json \
    --command="SELECT COUNT(*) AS n FROM sqlite_master WHERE type='index' AND sql IS NOT NULL" \
    2>/dev/null | grep -oE '"n": [0-9]+' | grep -oE '[0-9]+' | head -1)
  echo "[push-to-d1]   → indexes: want=$WANT_IDX have=${HAVE_IDX:-?}"
  if [[ -z "$HAVE_IDX" || "$HAVE_IDX" -lt "$WANT_IDX" ]]; then
    echo "[push-to-d1] ERROR: index verification failed (want=$WANT_IDX have=${HAVE_IDX:-unknown}) — DB would full-scan everything"
    return 1
  fi
}

# Apply a sentinel-delimited SQL file to D1 in batches of 150 statements,
# retrying each batch up to 3×. Shared by delta and stats-rebuild modes.
apply_sentinel_sql() {
  local SQL_FILE="$1"
  local BATCH_DIR="$WORK_DIR/sql-batches-$RANDOM"
  mkdir -p "$BATCH_DIR"
  awk -v dir="$BATCH_DIR" -v per=150 '
    /^--@@STMT@@$/ { sc++; if (sc % per == 0) bi++; next }
    { print >> (dir "/batch-" sprintf("%05d", bi)) }
  ' "$SQL_FILE"
  local TOTAL_BATCHES N=0
  TOTAL_BATCHES=$(find "$BATCH_DIR" -name 'batch-*' | wc -l | tr -d ' ')
  if [[ "$TOTAL_BATCHES" -eq 0 ]]; then
    echo "[push-to-d1]   → nothing to apply (0 statements)"
    return 0
  fi
  for BATCH in "$BATCH_DIR"/batch-*; do
    N=$((N + 1))
    echo "[push-to-d1]   → batch $N/$TOTAL_BATCHES ($(wc -l < "$BATCH" | tr -d ' ') lines)"
    local ATTEMPT=1 OK=0
    while [[ "$ATTEMPT" -le 3 ]]; do
      if $WRANGLER d1 execute "$D1_DATABASE" --file="$BATCH" --remote --yes; then
        OK=1; break
      fi
      echo "[push-to-d1]     ⚠ batch $N attempt $ATTEMPT failed; retrying …"
      ATTEMPT=$((ATTEMPT + 1))
      sleep 5
    done
    if [[ "$OK" -ne 1 ]]; then
      echo "[push-to-d1] ERROR: batch $N failed after 3 attempts"
      return 1
    fi
  done
  echo "[push-to-d1]   → applied in $TOTAL_BATCHES batch(es)"
}

# ─────────────────────────────────────────────────────────────────────────────
#  DELTA MODE — merge onto D1's existing data (daily). NEVER drops anything.
# ─────────────────────────────────────────────────────────────────────────────
#  Generated SQL is emitted by sqlite3 querying the delta file. SQLite's
#  quote() gives correctly-escaped SQL literals (NULL-safe) for every value.
push_delta() {
  local DELTA_SQL="$WORK_DIR/d1-delta.sql"

  echo
  echo "[push-to-d1] [delta 1/3] Generating delta SQL from $SQLITE_FILE …"

  # cve_ids touched by this delta = union of vulnerabilities + every child table.
  # (A KEV/EPSS-only delta UPDATEs vulnerabilities that already exist and has no
  #  child rows; a partial-ecosystem delta touches child tables too.)
  local CVE_IDS_SQL="$WORK_DIR/cve-ids.txt"
  sqlite3 "$SQLITE_FILE" <<'SQL' > "$CVE_IDS_SQL"
SELECT cve_id FROM vulnerabilities
UNION
SELECT cve_id FROM affected     WHERE cve_id IS NOT NULL
UNION
SELECT cve_id FROM cvss_scores  WHERE cve_id IS NOT NULL
UNION
SELECT cve_id FROM vuln_aliases WHERE cve_id IS NOT NULL
UNION
SELECT cve_id FROM refs         WHERE cve_id IS NOT NULL;
SQL
  local CVE_COUNT
  CVE_COUNT=$(grep -c . "$CVE_IDS_SQL" || true)
  echo "[push-to-d1]   → $CVE_COUNT cve_id(s) in delta"

  : > "$DELTA_SQL"

  # ── (a) vulnerabilities: UPSERT by cve_id (preserve OSV, update KEV/EPSS) ──
  #  DATA-INTEGRITY FIX (Task 5.2): a daily KEV/EPSS-only delta build has NO OSV
  #  data. For a CVE that is KEV-listed, the KEV ingest sets summary to the short
  #  KEV title (vulnerabilityName) and description to the short KEV blurb, and
  #  leaves published_at/modified_at NULL. So the delta row for a CVE that is BOTH
  #  OSV-loaded AND KEV-listed (e.g. Log4Shell CVE-2021-44228) carries a NON-EMPTY
  #  short KEV title/blurb and NULL dates. The old blind `excluded.*` upsert
  #  OVERWROTE D1's rich OSV summary/description with the KEV title and NULLed
  #  published_at/modified_at — clobbering good OSV data (and degrading vulns_fts)
  #  6 days out of 7, healed only by Sunday's full rebuild.
  #
  #  Fix: mirror the exact COALESCE precedence the KEV ingest and SqliteIngestSink
  #  already use (src/lib/ingest/kev.ts, sink-sqlite.ts): the EXISTING (OSV) value
  #  wins for the OSV-owned text/date columns, and the delta only fills a gap when
  #  D1 has none — `COALESCE(vulnerabilities.<col>, excluded.<col>)`. NULLIF on the
  #  text columns treats an empty delta string as "no value". The KEV/EPSS-owned
  #  columns take the fresh delta value (that is the daily delta's whole purpose);
  #  kev_added_at/epss_* are COALESCE-guarded so a KEV-only row lacking EPSS never
  #  nulls a prior EPSS score. This is also safe for future partial-ecosystem
  #  deltas — full mode (weekly) still fully refreshes OSV text.
  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO vulnerabilities (cve_id, source_id, summary, description, published_at, modified_at, kev, kev_added_at, epss_score, epss_percentile, epss_updated_at) VALUES ('
  || quote(cve_id) || ',' || quote(source_id) || ',' || quote(summary) || ','
  || quote(description) || ',' || quote(published_at) || ',' || quote(modified_at) || ','
  || quote(kev) || ',' || quote(kev_added_at) || ',' || quote(epss_score) || ','
  || quote(epss_percentile) || ',' || quote(epss_updated_at)
  || ') ON CONFLICT(cve_id) DO UPDATE SET '
  -- OSV-owned columns: existing D1 (OSV) value wins; delta only fills a gap.
  || 'source_id=COALESCE(vulnerabilities.source_id, NULLIF(excluded.source_id,'''')), '
  || 'summary=COALESCE(vulnerabilities.summary, NULLIF(excluded.summary,'''')), '
  || 'description=COALESCE(vulnerabilities.description, NULLIF(excluded.description,'''')), '
  || 'published_at=COALESCE(vulnerabilities.published_at, excluded.published_at), '
  || 'modified_at=COALESCE(vulnerabilities.modified_at, excluded.modified_at), '
  -- KEV/EPSS-owned columns: the daily delta exists to change these.
  || 'kev=excluded.kev, '
  || 'kev_added_at=COALESCE(excluded.kev_added_at, vulnerabilities.kev_added_at), '
  || 'epss_score=COALESCE(excluded.epss_score, vulnerabilities.epss_score), '
  || 'epss_percentile=COALESCE(excluded.epss_percentile, vulnerabilities.epss_percentile), '
  || 'epss_updated_at=COALESCE(excluded.epss_updated_at, vulnerabilities.epss_updated_at);'
  || char(10) || '--@@STMT@@'
FROM vulnerabilities;
SQL

  # ── (b) packages: get-or-create by natural key (ecosystem, name). ──
  #        Local rowids are meaningless in D1 (assigned from an independent full
  #        seed); keying on id would silently rename whichever D1 package already
  #        occupies that id. Instead, INSERT only when the (ecosystem, name) pair
  #        is absent, letting D1 assign/keep its own id. ──
  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO packages (ecosystem, name) SELECT ' || quote(ecosystem) || ',' || quote(name)
  || ' WHERE NOT EXISTS (SELECT 1 FROM packages WHERE ecosystem=' || quote(ecosystem) || ' AND name=' || quote(name) || ');'
  || char(10) || '--@@STMT@@'
FROM packages;
SQL

  # ── (c) child tables: DELETE-then-INSERT scoped PER-TABLE to the cve_ids the
  #        delta actually carries rows for IN THAT TABLE. ──
  #  CRITICAL: a KEV/EPSS-only delta carries NO child rows, so it must NOT delete
  #  any existing children. If we scoped the DELETE to the global cve_id union
  #  (incl. vulnerabilities), a KEV/EPSS update to an existing OSV CVE would
  #  DELETE that CVE's affected/cvss/refs/aliases and have nothing to re-insert —
  #  wiping OSV data. So each table only replaces cve_ids present in that same
  #  table in the delta: replace-what-you-carry, leave everything else untouched.
  for TBL in affected cvss_scores vuln_aliases refs; do
    sqlite3 "$SQLITE_FILE" <<SQL >> "$DELTA_SQL"
SELECT DISTINCT 'DELETE FROM $TBL WHERE cve_id=' || quote(cve_id) || ';'
  || char(10) || '--@@STMT@@'
FROM $TBL WHERE cve_id IS NOT NULL;
SQL
  done

  # affected inserts: resolve package_id against D1 by (ecosystem, name) — do
  # NOT carry the local rowid or local package_id, both of which are unrelated
  # to D1's id-space. The packages block above (Fix A) runs first, so the
  # subquery will always find the package. D1 assigns affected.id freely; the
  # per-cve_id DELETE above already cleared the slate for these cve_ids.
  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO affected (cve_id, package_id, ecosystem, ranges_json, versions_json, source_id) SELECT '
  || quote(a.cve_id) || ', (SELECT id FROM packages WHERE ecosystem=' || quote(p.ecosystem) || ' AND name=' || quote(p.name) || '), '
  || quote(a.ecosystem) || ',' || quote(a.ranges_json) || ',' || quote(a.versions_json) || ',' || quote(a.source_id) || ';'
  || char(10) || '--@@STMT@@'
FROM affected a JOIN packages p ON p.id = a.package_id;
SQL

  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO cvss_scores (cve_id, version, vector, base_score, severity, source) VALUES ('
  || quote(cve_id) || ',' || quote(version) || ',' || quote(vector) || ','
  || quote(base_score) || ',' || quote(severity) || ',' || quote(source) || ');'
  || char(10) || '--@@STMT@@'
FROM cvss_scores;
SQL

  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO vuln_aliases (cve_id, alias, source) VALUES ('
  || quote(cve_id) || ',' || quote(alias) || ',' || quote(source) || ');'
  || char(10) || '--@@STMT@@'
FROM vuln_aliases;
SQL

  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO refs (cve_id, url, type) VALUES ('
  || quote(cve_id) || ',' || quote(url) || ',' || quote(type) || ');'
  || char(10) || '--@@STMT@@'
FROM refs;
SQL

  # ── (d) sync_jobs: append this delta's bookkeeping rows (no id → autoinc). ──
  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO sync_jobs (source, started_at, finished_at, status, records_seen, records_changed, error_message, last_heartbeat_at) VALUES ('
  || quote(source) || ',' || quote(started_at) || ',' || quote(finished_at) || ','
  || quote(status) || ',' || quote(records_seen) || ',' || quote(records_changed) || ','
  || quote(error_message) || ',' || quote(last_heartbeat_at) || ');'
  || char(10) || '--@@STMT@@'
FROM sync_jobs;
SQL

  # ── (e) FTS delta: re-index ONLY the changed CVEs + new packages. ──
  #  vulns_fts: delete+reinsert per delta vulnerability cve_id (idempotent,
  #  bounded). Scoped to the delta's `vulnerabilities` rows — exactly the set we
  #  re-insert below — so every deleted FTS row is re-created.
  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT 'DELETE FROM vulns_fts WHERE cve_id=' || quote(cve_id) || ';'
  || char(10) || '--@@STMT@@'
FROM vulnerabilities;
SQL
  # Reinsert FTS rows from the (already-upserted) vulnerabilities on the D1 side.
  #  DATA-INTEGRITY FIX (Task 5.2): source summary/description from D1's
  #  `vulnerabilities` row (the SELECT sub-query runs against D1 after the upsert
  #  above has landed), NOT from the delta file. A KEV/EPSS-only delta's
  #  summary/description are the short KEV title/blurb; the upsert preserved the
  #  rich OSV text in `vulnerabilities`, so the FTS index must mirror that
  #  preserved text or search would degrade to the KEV title.
  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO vulns_fts (cve_id, summary, description) '
  || 'SELECT cve_id, summary, description FROM vulnerabilities WHERE cve_id=' || quote(cve_id) || ';'
  || char(10) || '--@@STMT@@'
FROM vulnerabilities;
SQL

  # packages_fts: index new packages by their D1-resolved rowid. The rowid MUST
  # equal D1's packages.id (queries do `p.id IN (SELECT rowid FROM packages_fts
  # MATCH ?)`). The incremental build's local packages.id does NOT match D1's id
  # (Fix A lets D1 assign its own id by natural key), so resolve the rowid via a
  # subquery on (ecosystem, name) — same natural-key pattern as the affected fix.
  # The NOT EXISTS guard (keyed on that resolved rowid) avoids duplicate FTS rows.
  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO packages_fts (rowid, name) SELECT (SELECT id FROM packages WHERE ecosystem='
  || quote(ecosystem) || ' AND name=' || quote(name) || '), ' || quote(name)
  || ' WHERE NOT EXISTS (SELECT 1 FROM packages_fts WHERE rowid=(SELECT id FROM packages WHERE ecosystem='
  || quote(ecosystem) || ' AND name=' || quote(name) || '));'
  || char(10) || '--@@STMT@@'
FROM packages;
SQL

  # ── (e2) Stats refresh: scoped package_stats recompute + chunked page_stats
  #        recount (src/lib/ingest/stats-sql.ts). Emitted AFTER all data/FTS
  #        statements so it aggregates post-upsert state, and BEFORE sync_state
  #        so the watermark-last invariant holds. Every statement is bounded
  #        (year/id-range chunks; scratch-table-driven recompute) — no full
  #        scans of vulnerabilities/affected/cvss_scores on D1. ──
  (cd "$ROOT" && pnpm exec tsx scripts/emit-stats-sql.ts delta "$SQLITE_FILE") >> "$DELTA_SQL"

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
  || char(10) || '--@@STMT@@'
FROM sync_state;
SQL
  fi

  # Strip anything D1 rejects (defensive — quote() output has none, but keep it).
  grep -vE "$STRIP" "$DELTA_SQL" > "$DELTA_SQL.clean" && mv "$DELTA_SQL.clean" "$DELTA_SQL"

  # Debug: DEBUG_KEEP_SQL=/path/file.sql preserves the generated delta SQL
  # (WORK_DIR is trap-deleted on exit).
  [[ -n "${DEBUG_KEEP_SQL:-}" ]] && cp "$DELTA_SQL" "$DEBUG_KEEP_SQL"

  local STMT_COUNT
  STMT_COUNT=$(grep -c '^--@@STMT@@$' "$DELTA_SQL" || true)
  echo "[push-to-d1]   → d1-delta.sql: $STMT_COUNT statement(s), $(wc -l < "$DELTA_SQL") lines"

  if [[ "$STMT_COUNT" -eq 0 ]]; then
    echo "[push-to-d1]   → delta is empty; nothing to push."
    return 0
  fi

  echo
  echo "[push-to-d1] [delta 2/3] Applying delta to D1 ($D1_DATABASE) in batches …"
  apply_sentinel_sql "$DELTA_SQL" || return 1
  echo "[push-to-d1]   → delta applied (no tables dropped; existing data preserved)"
}

# ─────────────────────────────────────────────────────────────────────────────
#  STATS-REBUILD MODE — one-time additive migration / disaster recovery.
#  Creates page_stats/package_stats (IF NOT EXISTS) and backfills them with
#  bounded, sharded statements. Touches NO other tables. No SQLite file needed.
# ─────────────────────────────────────────────────────────────────────────────
push_stats_rebuild() {
  local REBUILD_SQL="$WORK_DIR/stats-rebuild.sql"
  echo
  echo "[push-to-d1] [stats-rebuild 1/2] Generating sharded rebuild SQL …"
  (cd "$ROOT" && pnpm exec tsx scripts/emit-stats-sql.ts rebuild) > "$REBUILD_SQL"
  echo "[push-to-d1]   → $(grep -c '^--@@STMT@@$' "$REBUILD_SQL") statement(s)"
  echo
  echo "[push-to-d1] [stats-rebuild 2/2] Applying to D1 ($D1_DATABASE) …"
  apply_sentinel_sql "$REBUILD_SQL"
}

# ── Dispatch ─────────────────────────────────────────────────────────────────
if [[ "$PUSH_MODE" == "full" ]]; then
  push_full
elif [[ "$PUSH_MODE" == "stats-rebuild" ]]; then
  push_stats_rebuild
else
  push_delta
fi

# ── Verify ───────────────────────────────────────────────────────────────────
echo
echo "[push-to-d1] Verification probes (existence only — no full-table counts) …"
for TBL in vulnerabilities packages affected cvss_scores vuln_aliases refs sync_jobs sync_state page_stats package_stats vulns_fts packages_fts; do
  printf "  %-20s " "$TBL:"
  $WRANGLER d1 execute "$D1_DATABASE" \
    --remote \
    --command="SELECT CASE WHEN EXISTS (SELECT 1 FROM $TBL LIMIT 1) THEN 'has rows' ELSE 'EMPTY' END AS probe" \
    2>&1 | grep -E '"probe"' | head -1 || echo "(probe failed)"
done
echo
echo "[push-to-d1] page_stats snapshot:"
$WRANGLER d1 execute "$D1_DATABASE" --remote \
  --command="SELECT vuln_total, package_total, critical_total, kev_total, computed_at FROM page_stats WHERE id = 1" \
  2>&1 | grep -E '"(vuln_total|package_total|critical_total|kev_total|computed_at)"' || echo "  (page_stats missing — run stats-rebuild)"

echo
echo "[push-to-d1] ✓ Push complete ($PUSH_MODE) — D1 database: $D1_DATABASE"
