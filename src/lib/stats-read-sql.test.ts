import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { buildSchema } from "../../scripts/build-sqlite.js";
import { seedFixture } from "./ingest/stats-sql.test.js";
import { fullBuildStatsSql } from "./ingest/stats-sql.js";
import {
  DASHBOARD_STATS_SQL,
  VULN_TOTAL_SQL,
  TOP_PACKAGES_BY_ECO_SQL,
  TOP_PACKAGES_ALL_SQL,
  ECOSYSTEM_DEEP_DIVE_SQL,
  PACKAGE_CVE_COUNT_SQL,
  SITEMAP_TOP_PACKAGES_SQL,
  browsePackagesListSql,
} from "./stats-read-sql.js";

describe("stats read SQL", () => {
  let db: InstanceType<typeof Database>;

  beforeEach(() => {
    db = new Database(":memory:");
    buildSchema(db);
    seedFixture(db);
    for (const s of fullBuildStatsSql()) db.exec(s);
  });

  it("DASHBOARD_STATS_SQL returns one row with totals + live windows", () => {
    const row = db.prepare(DASHBOARD_STATS_SQL).get() as Record<string, number>;
    expect(row.vuln_total).toBe(3);
    expect(row.package_total).toBe(2);
    expect(row.critical_total).toBe(1);
    expect(row.kev_total).toBe(1);
    // Fixture published_at values are all in the past → live windows are 0.
    expect(row.new_today).toBe(0);
    expect(row.new_week).toBe(0);
  });

  it("DASHBOARD_STATS_SQL returns a zero row when page_stats is empty", () => {
    db.exec(`DELETE FROM page_stats`);
    const row = db.prepare(DASHBOARD_STATS_SQL).get() as Record<string, number>;
    expect(row.vuln_total).toBe(0);
    expect(row.kev_total).toBe(0);
    expect(row.new_today).toBe(0); // live part still works
  });

  it("VULN_TOTAL_SQL reads the precomputed total (and 0 rows when absent)", () => {
    expect((db.prepare(VULN_TOTAL_SQL).get() as { vuln_total: number }).vuln_total).toBe(3);
    db.exec(`DELETE FROM page_stats`);
    expect(db.prepare(VULN_TOTAL_SQL).get()).toBeUndefined();
  });

  it("TOP_PACKAGES_BY_ECO_SQL ranks by kev then cve count within an ecosystem", () => {
    const rows = db.prepare(TOP_PACKAGES_BY_ECO_SQL).all("npm", 8) as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(1);
    expect(rows[0].name).toBe("left-pad");
    expect(rows[0].cve_count).toBe(2);
    expect(rows[0].kev_count).toBe(1);
  });

  it("TOP_PACKAGES_ALL_SQL spans ecosystems with max_epss", () => {
    const rows = db.prepare(TOP_PACKAGES_ALL_SQL).all(100) as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(2);
    expect(rows[0].name).toBe("left-pad"); // kev_count 1 sorts first
    expect(rows[0].max_epss).toBeCloseTo(0.9);
  });

  it("ECOSYSTEM_DEEP_DIVE_SQL returns name-level rows", () => {
    const rows = db.prepare(ECOSYSTEM_DEEP_DIVE_SQL).all("PyPI", 200) as Array<Record<string, unknown>>;
    expect(rows).toEqual([{ name: "requests", cve_count: 1, kev_count: 0, max_epss: null }]);
  });

  it("PACKAGE_CVE_COUNT_SQL and SITEMAP_TOP_PACKAGES_SQL read package_stats", () => {
    expect((db.prepare(PACKAGE_CVE_COUNT_SQL).get(1) as { cve_count: number }).cve_count).toBe(2);
    const site = db.prepare(SITEMAP_TOP_PACKAGES_SQL).all(5000) as Array<Record<string, unknown>>;
    expect(site[0]).toEqual({ ecosystem: "npm", name: "left-pad" });
  });

  describe("browsePackagesListSql", () => {
    it("default browse (no filters, sort=cves) sorts by kev/cve and LEFT JOINs", () => {
      const sqlText = browsePackagesListSql({ nameViaFts: false, hasName: false, hasEcosystem: false, sort: "cves" });
      const rows = db.prepare(sqlText).all(50, 0) as Array<Record<string, unknown>>;
      expect(rows).toHaveLength(2);
      expect(rows[0].name).toBe("left-pad");
      expect(rows[0].kev_count).toBe(1);
    });

    it("ecosystem filter + name sort", () => {
      const sqlText = browsePackagesListSql({ nameViaFts: false, hasName: false, hasEcosystem: true, sort: "name" });
      const rows = db.prepare(sqlText).all("PyPI", 50, 0) as Array<Record<string, unknown>>;
      expect(rows).toEqual([{ ecosystem: "PyPI", name: "requests", cve_count: 1, kev_count: 0 }]);
    });

    it("LIKE name filter binds before ecosystem", () => {
      const sqlText = browsePackagesListSql({ nameViaFts: false, hasName: true, hasEcosystem: true, sort: "cves" });
      const rows = db.prepare(sqlText).all("%pad%", "npm", 50, 0) as Array<Record<string, unknown>>;
      expect(rows).toHaveLength(1);
      expect(rows[0].name).toBe("left-pad");
    });

    it("packages without stats rows still appear with zero counts", () => {
      db.exec(`INSERT INTO packages (id, ecosystem, name) VALUES (3, 'npm', 'no-cves-yet')`);
      const sqlText = browsePackagesListSql({ nameViaFts: false, hasName: false, hasEcosystem: false, sort: "name" });
      const rows = db.prepare(sqlText).all(50, 0) as Array<Record<string, unknown>>;
      const bare = rows.find((r) => r.name === "no-cves-yet");
      expect(bare).toEqual({ ecosystem: "npm", name: "no-cves-yet", cve_count: 0, kev_count: 0 });
    });
  });
});
