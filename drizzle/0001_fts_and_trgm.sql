-- Generated tsvector column for full-text search (drizzle-kit can't emit this)
ALTER TABLE "vulnerabilities"
  ADD COLUMN IF NOT EXISTS "search_tsv" tsvector
  GENERATED ALWAYS AS (
    setweight(to_tsvector('english', coalesce("cve_id",'')), 'A') ||
    setweight(to_tsvector('english', coalesce("summary",'')),  'B') ||
    setweight(to_tsvector('english', coalesce("description",'')), 'C')
  ) STORED;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_vuln_fts" ON "vulnerabilities" USING GIN ("search_tsv");
--> statement-breakpoint
-- Trigram index for typo-tolerant package name search
CREATE INDEX IF NOT EXISTS "idx_pkg_name_trgm" ON "packages" USING GIN ("name" gin_trgm_ops);
--> statement-breakpoint
-- Trigram for CVE ID prefix search ("CVE-2021-2" should hit "CVE-2021-23337")
CREATE INDEX IF NOT EXISTS "idx_vuln_cve_id_trgm" ON "vulnerabilities" USING GIN ("cve_id" gin_trgm_ops);
