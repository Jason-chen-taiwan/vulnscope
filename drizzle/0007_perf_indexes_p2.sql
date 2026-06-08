-- Phase 2 perf indexes. Follow-up to 0006_perf_indexes.sql after a full
-- query audit found 8 RED queries (full scan / N+1) on top of the 3 we
-- already fixed. Most of the remaining RED cases are solved by query
-- rewrites alone; this migration adds the one new index that is needed.
--
-- Like 0006, CREATE INDEX CONCURRENTLY cannot run inside a transaction.
-- Apply each statement individually with autocommit.

-- idx_vuln_epss_score_partial:
--   getEpssRising orders all vulns by epss_score DESC where epss_score
--   IS NOT NULL. The existing idx_vuln_epss (epss_score DESC NULLS LAST)
--   indexes all 75k rows including the 40k+ with NULL epss; a partial
--   index restricted to non-null epss_score is ~half the size and lets
--   the optimizer skip the IS NOT NULL filter entirely.
--   Also helps sitemap.ts's `WHERE kev=true OR epss_score >= 0.05`
--   via bitmap-or with idx_vuln_kev_added.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vuln_epss_score_partial
  ON vulnerabilities (epss_score DESC NULLS LAST)
  WHERE epss_score IS NOT NULL;
