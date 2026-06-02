-- Track non-CVE identifiers (GHSA, DSA, ALPINE-..., etc.) that point at
-- the same underlying vulnerability. OSV records list these in their
-- `aliases`, `upstream`, and `related` arrays; before this migration
-- we silently dropped them, which meant /cve/GHSA-xxxx returned 404
-- and the source-diff view had no GHSA-side data.
--
-- One CVE can have many aliases (CVE-2021-44228 has GHSA-jfh8-c2jp-5v3q
-- plus DSA-5020-1 plus ALPINE-CVE-... plus more) and one alias maps to
-- exactly one CVE — hence the UNIQUE on alias.

CREATE TABLE IF NOT EXISTS "vuln_aliases" (
  "cve_id"  text NOT NULL REFERENCES "vulnerabilities"("cve_id") ON DELETE CASCADE,
  "alias"   text NOT NULL,
  "source"  text NOT NULL,                 -- 'ghsa' | 'dsa' | 'alpine' | 'related' | 'osv-id' | 'upstream'
  PRIMARY KEY ("cve_id", "alias")
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "uq_vuln_aliases_alias"
  ON "vuln_aliases" ("alias");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_vuln_aliases_cve"
  ON "vuln_aliases" ("cve_id");
