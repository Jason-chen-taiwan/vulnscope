-- Performance indexes to cut SSR queries from 30s timeout to <2s.
-- Production observed 2026-06-08: pages /, /packages, /search all
-- timing out at 30s with pg_stat_activity stuck at IO:DataFileRead.
-- Root cause was the COUNT(DISTINCT a.cve_id) aggregate in
-- getTopPackages / browsePackages doing full scans of the 120k-row
-- affected table per call, multiplied by homepage's 6 parallel
-- ecosystem calls. The vulnerabilities table is 243 MB and doesn't
-- fit in the 512 MB DB machine's shared_buffers, so every full scan
-- hits disk.
--
-- All CREATE INDEX statements use CONCURRENTLY so the building doesn't
-- lock the affected table during a long online migration. Postgres
-- requires CONCURRENTLY to run OUTSIDE a transaction, so this file
-- has no BEGIN/COMMIT and each statement runs auto-commit individually.
-- Run with `psql -f` (NOT inside a wrapper transaction).

-- (1) affected(ecosystem, package_id) INCLUDE (cve_id):
--     getTopPackages / browsePackages filter by ecosystem then GROUP
--     BY package and COUNT(DISTINCT cve_id). This index gives them a
--     direct ecosystem entry point plus the cve_id column inline so
--     PG can run COUNT(DISTINCT) as an index-only scan, never touching
--     the heap.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affected_eco_pkg
  ON affected (ecosystem, package_id) INCLUDE (cve_id);

-- (2) cvss_scores(cve_id, base_score DESC NULLS LAST):
--     searchVulns has a LEFT JOIN LATERAL that picks the highest
--     base_score per cve_id. Without this, PG uses idx_cvss_cve
--     (cve_id only) then sorts in memory. With this composite index,
--     the sort is satisfied by the index order — pure index scan, no
--     sort step.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cvss_cve_score
  ON cvss_scores (cve_id, base_score DESC NULLS LAST);

-- (3) vulnerabilities partial index on (kev, kev_added_at DESC):
--     getRecentKev filters kev=true and orders by kev_added_at DESC.
--     A partial index WHERE kev=true is dramatically smaller than
--     a full-table boolean index (only ~1600 KEV rows of 75k vulns),
--     and the kev_added_at sort is satisfied by the index order.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vuln_kev_added
  ON vulnerabilities (kev_added_at DESC NULLS LAST)
  WHERE kev = true;
