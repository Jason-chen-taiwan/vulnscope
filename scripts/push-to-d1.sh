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
  D1_DATABASE="${ARG2:-${D1_DATABASE:-vulnscope}}"
fi

PUSH_MODE="${ARG3:-${PUSH_MODE:-delta}}"

if [[ "$PUSH_MODE" != "full" && "$PUSH_MODE" != "delta" ]]; then
  echo "[push-to-d1] ERROR: PUSH_MODE must be 'full' or 'delta' (got '$PUSH_MODE')"
  exit 1
fi

# ── Temp-file workspace ──────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# D1 rejects BEGIN TRANSACTION / COMMIT / PRAGMA — strip them from any dump.
STRIP='^(BEGIN TRANSACTION|COMMIT|PRAGMA )'

# ── Validate inputs ──────────────────────────────────────────────────────────
if [[ ! -f "$SQLITE_FILE" ]]; then
  echo "[push-to-d1] ERROR: SQLite file not found: $SQLITE_FILE"
  echo "  Build it first with:  INGEST_ECOSYSTEMS=Hex pnpm build:sqlite"
  exit 1
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
  local BASE_TABLES="vulnerabilities packages affected cvss_scores vuln_aliases refs sync_jobs"

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
FROM vulnerabilities;
SQL

  # ── (b) packages: UPSERT by id. Package ids are stable within a full-corpus
  #        build; a KEV/EPSS-only delta carries ZERO package rows. DO UPDATE is
  #        safe (name/eco identical for a given id). ──
  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO packages (id, ecosystem, name) VALUES ('
  || quote(id) || ',' || quote(ecosystem) || ',' || quote(name)
  || ') ON CONFLICT(id) DO UPDATE SET ecosystem=excluded.ecosystem, name=excluded.name;'
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
FROM $TBL WHERE cve_id IS NOT NULL;
SQL
  done

  # affected inserts (id preserved so package_id references stay consistent).
  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO affected (id, cve_id, package_id, ecosystem, ranges_json, versions_json, source_id) VALUES ('
  || quote(id) || ',' || quote(cve_id) || ',' || quote(package_id) || ','
  || quote(ecosystem) || ',' || quote(ranges_json) || ',' || quote(versions_json) || ','
  || quote(source_id) || ');'
FROM affected;
SQL

  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO cvss_scores (cve_id, version, vector, base_score, severity, source) VALUES ('
  || quote(cve_id) || ',' || quote(version) || ',' || quote(vector) || ','
  || quote(base_score) || ',' || quote(severity) || ',' || quote(source) || ');'
FROM cvss_scores;
SQL

  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO vuln_aliases (cve_id, alias, source) VALUES ('
  || quote(cve_id) || ',' || quote(alias) || ',' || quote(source) || ');'
FROM vuln_aliases;
SQL

  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO refs (cve_id, url, type) VALUES ('
  || quote(cve_id) || ',' || quote(url) || ',' || quote(type) || ');'
FROM refs;
SQL

  # ── (d) sync_jobs: append this delta's bookkeeping rows (no id → autoinc). ──
  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO sync_jobs (source, started_at, finished_at, status, records_seen, records_changed, error_message, last_heartbeat_at) VALUES ('
  || quote(source) || ',' || quote(started_at) || ',' || quote(finished_at) || ','
  || quote(status) || ',' || quote(records_seen) || ',' || quote(records_changed) || ','
  || quote(error_message) || ',' || quote(last_heartbeat_at) || ');'
FROM sync_jobs;
SQL

  # ── (e) FTS delta: re-index ONLY the changed CVEs + new packages. ──
  #  vulns_fts: delete+reinsert per delta vulnerability cve_id (idempotent,
  #  bounded). Scoped to the delta's `vulnerabilities` rows — exactly the set we
  #  re-insert below — so every deleted FTS row is re-created.
  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT 'DELETE FROM vulns_fts WHERE cve_id=' || quote(cve_id) || ';'
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
FROM vulnerabilities;
SQL

  # packages_fts: index only packages not already indexed (new rows). Delta
  # package ids are stable, so a NOT IN guard avoids duplicate FTS entries and
  # avoids re-reading the whole corpus.
  sqlite3 "$SQLITE_FILE" <<'SQL' >> "$DELTA_SQL"
SELECT
  'INSERT INTO packages_fts (rowid, name) SELECT ' || quote(id) || ',' || quote(name)
  || ' WHERE NOT EXISTS (SELECT 1 FROM packages_fts WHERE rowid=' || quote(id) || ');'
FROM packages;
SQL

  # Strip anything D1 rejects (defensive — quote() output has none, but keep it).
  grep -vE "$STRIP" "$DELTA_SQL" > "$DELTA_SQL.clean" && mv "$DELTA_SQL.clean" "$DELTA_SQL"

  local STMT_COUNT
  STMT_COUNT=$(grep -c ';' "$DELTA_SQL" || true)
  echo "[push-to-d1]   → d1-delta.sql: $STMT_COUNT statement(s), $(wc -l < "$DELTA_SQL") lines"

  if [[ "$STMT_COUNT" -eq 0 ]]; then
    echo "[push-to-d1]   → delta is empty; nothing to push."
    return 0
  fi

  echo
  echo "[push-to-d1] [delta 2/3] Applying delta to D1 ($D1_DATABASE) …"
  $WRANGLER d1 execute "$D1_DATABASE" --file="$DELTA_SQL" --remote --yes
  echo "[push-to-d1]   → delta applied (no tables dropped; existing data preserved)"
}

# ── Dispatch ─────────────────────────────────────────────────────────────────
if [[ "$PUSH_MODE" == "full" ]]; then
  push_full
else
  push_delta
fi

# ── Verify ───────────────────────────────────────────────────────────────────
echo
echo "[push-to-d1] Verification counts …"
for TBL in vulnerabilities packages affected cvss_scores vuln_aliases refs sync_jobs vulns_fts packages_fts; do
  printf "  %-20s " "$TBL:"
  $WRANGLER d1 execute "$D1_DATABASE" \
    --remote \
    --command="SELECT count(*) AS cnt FROM $TBL" \
    2>&1 | grep -E '"cnt"' | head -1 || echo "(query failed)"
done

echo
echo "[push-to-d1] ✓ Push complete ($PUSH_MODE) — D1 database: $D1_DATABASE"
