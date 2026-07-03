#!/usr/bin/env bash
# Phase-0 spike: convert the local Postgres CVE dataset to a SQLite file
# with FTS5 search indexes, then report its size. Answers the one question
# that gates the whole Cloudflare/D1 migration: does the full 13-ecosystem
# dataset (+ FTS5) fit under D1's free per-database limit?
#
# Read-only against Postgres. Produces ./scratch-phase0/vulnscope.sqlite.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PGBIN="/opt/homebrew/opt/postgresql@16/bin"
URL="postgres://vulnscope:vulnscope@127.0.0.1:55432/vulnscope"
OUT="$ROOT/scratch-phase0"
DB="$OUT/vulnscope.sqlite"
mkdir -p "$OUT"
rm -f "$DB"

echo "==> [1/4] Exporting Postgres tables to CSV"
for t in vulnerabilities packages affected cvss_scores vuln_aliases refs; do
  # jsonb columns export as text automatically; tsvector is excluded (rebuilt as FTS5).
  case "$t" in
    vulnerabilities)
      "$PGBIN/psql" "$URL" -c "\copy (SELECT cve_id, source_id, summary, description, published_at, modified_at, kev::int, kev_added_at, epss_score, epss_percentile, epss_updated_at FROM vulnerabilities) TO '$OUT/$t.csv' WITH CSV" ;;
    *)
      "$PGBIN/psql" "$URL" -c "\copy $t TO '$OUT/$t.csv' WITH CSV" ;;
  esac
  echo "    $t.csv -> $(wc -l < "$OUT/$t.csv") rows"
done

echo "==> [2/4] Building SQLite schema"
sqlite3 "$DB" <<'SQL'
PRAGMA journal_mode=OFF;
PRAGMA synchronous=OFF;

CREATE TABLE vulnerabilities (
  cve_id TEXT PRIMARY KEY, source_id TEXT, summary TEXT, description TEXT,
  published_at TEXT, modified_at TEXT, kev INTEGER, kev_added_at TEXT,
  epss_score REAL, epss_percentile REAL, epss_updated_at TEXT
);
CREATE TABLE packages (id INTEGER PRIMARY KEY, ecosystem TEXT, name TEXT);
CREATE TABLE affected (
  id INTEGER PRIMARY KEY, cve_id TEXT, package_id INTEGER, ecosystem TEXT,
  ranges_json TEXT, versions_json TEXT, source_id TEXT
);
CREATE TABLE cvss_scores (
  cve_id TEXT, version TEXT, vector TEXT, base_score REAL, severity TEXT, source TEXT
);
CREATE TABLE vuln_aliases (cve_id TEXT, alias TEXT, source TEXT);
CREATE TABLE refs (cve_id TEXT, url TEXT, type TEXT);
SQL

echo "==> [3/4] Importing CSVs"
for t in vulnerabilities packages affected cvss_scores vuln_aliases refs; do
  sqlite3 "$DB" <<SQL
.mode csv
.import '$OUT/$t.csv' $t
SQL
done

echo "==> [3b/4] Creating indexes (mirrors the Postgres index set)"
sqlite3 "$DB" <<'SQL'
CREATE INDEX idx_affected_cve ON affected(cve_id);
CREATE INDEX idx_affected_pkg ON affected(package_id);
CREATE INDEX idx_cvss_cve ON cvss_scores(cve_id);
CREATE INDEX idx_aliases_cve ON vuln_aliases(cve_id);
CREATE INDEX idx_aliases_alias ON vuln_aliases(alias);
CREATE INDEX idx_refs_cve ON refs(cve_id);
CREATE INDEX idx_pkg_eco_name ON packages(ecosystem, name);
CREATE INDEX idx_vuln_kev ON vulnerabilities(kev);
CREATE INDEX idx_vuln_published ON vulnerabilities(published_at);
CREATE INDEX idx_vuln_epss ON vulnerabilities(epss_score);
SQL

echo "==> [3c/4] Building FTS5 search indexes (tsvector + pg_trgm replacement)"
sqlite3 "$DB" <<'SQL'
-- Full-text search over CVE id/summary/description (replaces tsvector @@).
CREATE VIRTUAL TABLE vulns_fts USING fts5(
  cve_id, summary, description, tokenize='porter unicode61'
);
INSERT INTO vulns_fts(cve_id, summary, description)
  SELECT cve_id, summary, description FROM vulnerabilities;

-- Trigram fuzzy search over package names (replaces pg_trgm ILIKE '%q%').
CREATE VIRTUAL TABLE packages_fts USING fts5(name, tokenize='trigram');
INSERT INTO packages_fts(rowid, name) SELECT id, name FROM packages;
SQL

echo "==> [4/4] Sizes"
sqlite3 "$DB" "VACUUM;"
echo "    ---- table/index breakdown (KB) ----"
sqlite3 "$DB" "SELECT name, printf('%,d', SUM(pgsize)/1024) AS kb FROM dbstat GROUP BY name ORDER BY SUM(pgsize) DESC LIMIT 20;" 2>/dev/null || echo "    (dbstat unavailable)"
echo "    ---- TOTAL ----"
ls -lh "$DB" | awk '{print "    SQLite file: "$5}'
echo
echo "D1 free per-database limit is 500 MB (conservative) / 5 GB (account). Compare above."
