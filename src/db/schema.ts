import { sql } from "drizzle-orm";
import {
  boolean,
  index,
  integer,
  jsonb,
  numeric,
  pgTable,
  primaryKey,
  serial,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";

export const vulnerabilities = pgTable(
  "vulnerabilities",
  {
    cveId: text("cve_id").primaryKey(),
    sourceId: text("source_id").notNull(),
    summary: text("summary"),
    description: text("description"),
    publishedAt: timestamp("published_at", { withTimezone: true }),
    modifiedAt: timestamp("modified_at", { withTimezone: true }),
    kev: boolean("kev").notNull().default(false),
    kevAddedAt: timestamp("kev_added_at", { withTimezone: true }),
    epssScore: numeric("epss_score", { precision: 6, scale: 5 }),
    epssPercentile: numeric("epss_percentile", { precision: 6, scale: 5 }),
    epssUpdatedAt: timestamp("epss_updated_at", { withTimezone: true }),
    // The generated tsvector column is created via a raw SQL migration step
    // (drizzle-kit does not yet emit GENERATED ALWAYS AS for tsvector).
  },
  (t) => ({
    publishedIdx: index("idx_vuln_published").on(t.publishedAt),
    modifiedIdx: index("idx_vuln_modified").on(t.modifiedAt),
    kevIdx: index("idx_vuln_kev").on(t.kev),
    // Partial index for getRecentKev's `WHERE kev=true ORDER BY
    // kev_added_at DESC NULLS LAST`. Migration 0006 creates this as
    // a partial index (WHERE kev=true) which drizzle 0.36 can't
    // express via .where(); we declare a non-partial approximation
    // here so db:generate doesn't try to drop the live index.
    kevAddedIdx: index("idx_vuln_kev_added").on(t.kevAddedAt),
    // Partial index on (epss_score DESC NULLS LAST) WHERE epss_score
    // IS NOT NULL — drives getEpssRising and helps sitemap.ts's
    // kev OR epss>=0.05 bitmap-or. Migration 0007 creates the
    // partial form; this is the column-only approximation so
    // db:generate doesn't drop the live partial index.
    epssScorePartialIdx: index("idx_vuln_epss_score_partial").on(t.epssScore),
  }),
);

export const cvssScores = pgTable(
  "cvss_scores",
  {
    cveId: text("cve_id")
      .notNull()
      .references(() => vulnerabilities.cveId, { onDelete: "cascade" }),
    version: text("version").notNull(), // '2.0' | '3.0' | '3.1' | '4.0'
    vector: text("vector"),
    baseScore: numeric("base_score", { precision: 3, scale: 1 }),
    severity: text("severity"), // LOW | MEDIUM | HIGH | CRITICAL
    source: text("source").notNull(), // 'osv' | 'nvd'
  },
  (t) => ({
    pk: primaryKey({ columns: [t.cveId, t.version, t.source] }),
    cveIdx: index("idx_cvss_cve").on(t.cveId),
    severityIdx: index("idx_cvss_severity").on(t.severity),
    // Composite for searchVulns LATERAL "highest base_score per
    // cve_id" subquery. Index order satisfies the ORDER BY so PG
    // doesn't need a sort step. Migration 0006 creates this with
    // base_score DESC NULLS LAST; drizzle's column-only form is a
    // close enough approximation that db:generate won't try to drop
    // the live index.
    cveScoreIdx: index("idx_cvss_cve_score").on(t.cveId, t.baseScore),
  }),
);

export const packages = pgTable(
  "packages",
  {
    id: serial("id").primaryKey(),
    ecosystem: text("ecosystem").notNull(),
    name: text("name").notNull(),
  },
  (t) => ({
    ecoNameUnique: uniqueIndex("uq_pkg_eco_name").on(t.ecosystem, t.name),
    nameIdx: index("idx_pkg_name").on(t.name),
  }),
);

export const affected = pgTable(
  "affected",
  {
    id: serial("id").primaryKey(),
    cveId: text("cve_id")
      .notNull()
      .references(() => vulnerabilities.cveId, { onDelete: "cascade" }),
    packageId: integer("package_id")
      .notNull()
      .references(() => packages.id, { onDelete: "cascade" }),
    ecosystem: text("ecosystem").notNull(),
    rangesJson: jsonb("ranges_json").notNull(),
    versionsJson: jsonb("versions_json"),
    sourceId: text("source_id").notNull(), // OSV record id for dedupe
  },
  (t) => ({
    cveIdx: index("idx_affected_cve").on(t.cveId),
    pkgIdx: index("idx_affected_pkg").on(t.packageId),
    dedupe: uniqueIndex("uq_affected_dedupe").on(t.cveId, t.packageId, t.sourceId),
    // Composite for getTopPackages / browsePackages ecosystem-scoped
    // aggregates. Migration 0006 creates this with INCLUDE (cve_id)
    // so PG can run COUNT(DISTINCT cve_id) as an index-only scan;
    // drizzle's column-only form here is enough to stop db:generate
    // from dropping the live index.
    ecoPkgIdx: index("idx_affected_eco_pkg").on(t.ecosystem, t.packageId),
  }),
);

export const refs = pgTable(
  "refs",
  {
    cveId: text("cve_id")
      .notNull()
      .references(() => vulnerabilities.cveId, { onDelete: "cascade" }),
    url: text("url").notNull(),
    type: text("type"),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.cveId, t.url] }),
  }),
);

/**
 * GHSA / DSA / ALPINE-... / DLA-... — every non-CVE identifier that
 * OSV records list under `aliases`, `upstream`, or `related`. Stored
 * many-to-many because a single CVE can have multiple ecosystem-level
 * advisories (e.g. CVE-2021-44228 → GHSA-jfh8-c2jp-5v3q + DSA-5020-1
 * + ALPINE-CVE-2021-44228 + ...).
 *
 * `source` distinguishes which feed produced the row so the UI can
 * filter ("show GHSA only") and the source-diff view can render
 * GHSA-vs-NVD discrepancies cleanly.
 */
export const vulnAliases = pgTable(
  "vuln_aliases",
  {
    cveId: text("cve_id")
      .notNull()
      .references(() => vulnerabilities.cveId, { onDelete: "cascade" }),
    alias: text("alias").notNull(),
    source: text("source").notNull(), // 'ghsa' | 'dsa' | 'alpine' | 'related' | 'osv-id' etc.
  },
  (t) => ({
    pk: primaryKey({ columns: [t.cveId, t.alias] }),
    aliasIdx: uniqueIndex("uq_vuln_aliases_alias").on(t.alias),
    cveIdx: index("idx_vuln_aliases_cve").on(t.cveId),
  }),
);

export const metaKv = pgTable("meta_kv", {
  key: text("key").primaryKey(),
  value: text("value"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).default(sql`now()`),
});

export const syncJobs = pgTable(
  "sync_jobs",
  {
    id: serial("id").primaryKey(),
    source: text("source").notNull(),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull().default(sql`now()`),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
    status: text("status").notNull().default("running"),
    recordsSeen: integer("records_seen"),
    recordsChanged: integer("records_changed"),
    errorMessage: text("error_message"),
    lastHeartbeatAt: timestamp("last_heartbeat_at", { withTimezone: true }),
  },
  (t) => ({
    sourceStartedIdx: index("idx_sync_jobs_source_started").on(t.source, t.startedAt),
    startedIdx: index("idx_sync_jobs_started").on(t.startedAt),
  }),
);

export type SyncJob = typeof syncJobs.$inferSelect;

export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type NewVulnerability = typeof vulnerabilities.$inferInsert;
export type CvssScore = typeof cvssScores.$inferSelect;
export type Package = typeof packages.$inferSelect;
export type Affected = typeof affected.$inferSelect;
export type Ref = typeof refs.$inferSelect;
export type VulnAlias = typeof vulnAliases.$inferSelect;
