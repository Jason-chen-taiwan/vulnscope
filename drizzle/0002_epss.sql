ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "epss_score" numeric(6,5);
--> statement-breakpoint
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "epss_percentile" numeric(6,5);
--> statement-breakpoint
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "epss_updated_at" timestamptz;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_vuln_epss" ON "vulnerabilities" (epss_score DESC NULLS LAST);
