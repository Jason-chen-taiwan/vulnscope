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

export const metaKv = pgTable("meta_kv", {
  key: text("key").primaryKey(),
  value: text("value"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).default(sql`now()`),
});

export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type NewVulnerability = typeof vulnerabilities.$inferInsert;
export type CvssScore = typeof cvssScores.$inferSelect;
export type Package = typeof packages.$inferSelect;
export type Affected = typeof affected.$inferSelect;
export type Ref = typeof refs.$inferSelect;
