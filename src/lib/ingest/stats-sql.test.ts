import { describe, it, expect } from "vitest";
import Database from "better-sqlite3";
import { buildSchema } from "../../../scripts/build-sqlite.js";
import { statsDdl, fullBuildStatsSql } from "./stats-sql.js";

/** Shared fixture: 2 packages, 3 vulns (1 KEV, 1 CRITICAL), 4 affected rows. */
export function seedFixture(db: InstanceType<typeof Database>): void {
  db.exec(`
    INSERT INTO vulnerabilities (cve_id, kev, epss_score, published_at) VALUES
      ('CVE-2021-1001', 1, 0.9,  '2021-06-01T00:00:00Z'),
      ('CVE-2021-1002', 0, 0.5,  '2021-07-01T00:00:00Z'),
      ('CVE-2024-2001', 0, NULL, '2024-01-01T00:00:00Z');
    INSERT INTO packages (id, ecosystem, name) VALUES
      (1, 'npm',  'left-pad'),
      (2, 'PyPI', 'requests');
    INSERT INTO affected (cve_id, package_id, ecosystem) VALUES
      ('CVE-2021-1001', 1, 'npm'),
      ('CVE-2021-1002', 1, 'npm'),
      ('CVE-2021-1002', 1, 'npm'),   -- duplicate row: cve_count must stay DISTINCT
      ('CVE-2024-2001', 2, 'PyPI');
    INSERT INTO cvss_scores (cve_id, version, base_score, severity, source) VALUES
      ('CVE-2021-1001', '3.1', 9.8, 'CRITICAL', 'osv'),
      ('CVE-2021-1002', '3.1', 5.0, 'MEDIUM',   'osv');
  `);
}

describe("statsDdl", () => {
  it("creates page_stats, package_stats and both indexes, idempotently", () => {
    const db = new Database(":memory:");
    for (const s of statsDdl()) db.exec(s);
    for (const s of statsDdl()) db.exec(s); // IF NOT EXISTS → second run is a no-op
    const names = db
      .prepare(`SELECT name FROM sqlite_master WHERE name IN
        ('page_stats','package_stats','idx_pkgstats_eco_rank','idx_pkgstats_rank')`)
      .all()
      .map((r: unknown) => (r as { name: string }).name);
    expect(names.sort()).toEqual([
      "idx_pkgstats_eco_rank", "idx_pkgstats_rank", "package_stats", "page_stats",
    ]);
  });
});

describe("fullBuildStatsSql", () => {
  it("computes correct aggregates from a full local dataset", () => {
    const db = new Database(":memory:");
    buildSchema(db); // Task 1 adds stats tables to buildSchema
    seedFixture(db);
    for (const s of fullBuildStatsSql()) db.exec(s);

    const page = db.prepare(`SELECT * FROM page_stats WHERE id = 1`).get() as Record<string, unknown>;
    expect(page.vuln_total).toBe(3);
    expect(page.package_total).toBe(2);
    expect(page.critical_total).toBe(1);
    expect(page.kev_total).toBe(1);
    expect(page.computed_at).toBeTruthy();

    const pkg1 = db.prepare(`SELECT * FROM package_stats WHERE package_id = 1`).get() as Record<string, unknown>;
    expect(pkg1.ecosystem).toBe("npm");
    expect(pkg1.name).toBe("left-pad");
    expect(pkg1.cve_count).toBe(2);   // DISTINCT despite the duplicate affected row
    expect(pkg1.kev_count).toBe(1);
    expect(pkg1.max_epss).toBeCloseTo(0.9);

    const pkg2 = db.prepare(`SELECT * FROM package_stats WHERE package_id = 2`).get() as Record<string, unknown>;
    expect(pkg2.cve_count).toBe(1);
    expect(pkg2.kev_count).toBe(0);
    expect(pkg2.max_epss).toBeNull();
  });

  it("is idempotent (re-run replaces, not duplicates)", () => {
    const db = new Database(":memory:");
    buildSchema(db);
    seedFixture(db);
    for (const s of fullBuildStatsSql()) db.exec(s);
    for (const s of fullBuildStatsSql()) db.exec(s);
    expect((db.prepare(`SELECT COUNT(*) AS c FROM package_stats`).get() as { c: number }).c).toBe(2);
    expect((db.prepare(`SELECT COUNT(*) AS c FROM page_stats`).get() as { c: number }).c).toBe(1);
  });
});
