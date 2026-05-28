CREATE TABLE IF NOT EXISTS "affected" (
	"id" serial PRIMARY KEY NOT NULL,
	"cve_id" text NOT NULL,
	"package_id" integer NOT NULL,
	"ecosystem" text NOT NULL,
	"ranges_json" jsonb NOT NULL,
	"versions_json" jsonb,
	"source_id" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "cvss_scores" (
	"cve_id" text NOT NULL,
	"version" text NOT NULL,
	"vector" text,
	"base_score" numeric(3, 1),
	"severity" text,
	"source" text NOT NULL,
	CONSTRAINT "cvss_scores_cve_id_version_source_pk" PRIMARY KEY("cve_id","version","source")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "meta_kv" (
	"key" text PRIMARY KEY NOT NULL,
	"value" text,
	"updated_at" timestamp with time zone DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "packages" (
	"id" serial PRIMARY KEY NOT NULL,
	"ecosystem" text NOT NULL,
	"name" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "refs" (
	"cve_id" text NOT NULL,
	"url" text NOT NULL,
	"type" text,
	CONSTRAINT "refs_cve_id_url_pk" PRIMARY KEY("cve_id","url")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "vulnerabilities" (
	"cve_id" text PRIMARY KEY NOT NULL,
	"source_id" text NOT NULL,
	"summary" text,
	"description" text,
	"published_at" timestamp with time zone,
	"modified_at" timestamp with time zone,
	"kev" boolean DEFAULT false NOT NULL,
	"kev_added_at" timestamp with time zone
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "affected" ADD CONSTRAINT "affected_cve_id_vulnerabilities_cve_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."vulnerabilities"("cve_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "affected" ADD CONSTRAINT "affected_package_id_packages_id_fk" FOREIGN KEY ("package_id") REFERENCES "public"."packages"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "cvss_scores" ADD CONSTRAINT "cvss_scores_cve_id_vulnerabilities_cve_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."vulnerabilities"("cve_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "refs" ADD CONSTRAINT "refs_cve_id_vulnerabilities_cve_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."vulnerabilities"("cve_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_affected_cve" ON "affected" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_affected_pkg" ON "affected" USING btree ("package_id");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "uq_affected_dedupe" ON "affected" USING btree ("cve_id","package_id","source_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_cvss_cve" ON "cvss_scores" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_cvss_severity" ON "cvss_scores" USING btree ("severity");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "uq_pkg_eco_name" ON "packages" USING btree ("ecosystem","name");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_pkg_name" ON "packages" USING btree ("name");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_vuln_published" ON "vulnerabilities" USING btree ("published_at");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_vuln_modified" ON "vulnerabilities" USING btree ("modified_at");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_vuln_kev" ON "vulnerabilities" USING btree ("kev");