import { describe, it, expect } from "vitest";
import Database from "better-sqlite3";
import { buildSchema } from "../../../scripts/build-sqlite.js";
import { statsDdl, fullBuildStatsSql, deltaStatsSql, rebuildAllStatsSql } from "./stats-sql.js";
import { seedFixture } from "./stats-sql.fixtures.js";

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

/** Execute generated statements (each element = exactly one statement). */
function execAll(db: InstanceType<typeof Database>, stmts: string[]): void {
  for (const s of stmts) db.exec(s);
}

const TEST_OPTS = { yearStart: 2020, yearEndExclusive: 2026, pkgIdStep: 10, pkgIdMax: 30 };

describe("deltaStatsSql", () => {
  function freshDb() {
    const db = new Database(":memory:");
    buildSchema(db);
    seedFixture(db);
    execAll(db, fullBuildStatsSql()); // stats start correct
    return db;
  }

  it("recomputes stats for touched packages only and refreshes page_stats", () => {
    const db = freshDb();
    // Simulate the delta the daily push applies BEFORE stats refresh runs:
    // CVE-2021-1001 loses its KEV flag, and package 1 gains a new CVE.
    db.exec(`
      UPDATE vulnerabilities SET kev = 0 WHERE cve_id = 'CVE-2021-1001';
      INSERT INTO vulnerabilities (cve_id, kev, epss_score) VALUES ('CVE-2025-3001', 0, 0.2);
      INSERT INTO affected (cve_id, package_id, ecosystem) VALUES ('CVE-2025-3001', 1, 'npm');
    `);
    execAll(db, deltaStatsSql(["CVE-2021-1001", "CVE-2025-3001"], TEST_OPTS));

    const pkg1 = db.prepare(`SELECT * FROM package_stats WHERE package_id = 1`).get() as Record<string, unknown>;
    expect(pkg1.cve_count).toBe(3);
    expect(pkg1.kev_count).toBe(0);
    // Untouched package 2 remains from the full build:
    const pkg2 = db.prepare(`SELECT * FROM package_stats WHERE package_id = 2`).get() as Record<string, unknown>;
    expect(pkg2.cve_count).toBe(1);

    const page = db.prepare(`SELECT * FROM page_stats WHERE id = 1`).get() as Record<string, unknown>;
    expect(page.vuln_total).toBe(4);
    expect(page.kev_total).toBe(0);
    expect(page.critical_total).toBe(1);
    expect(page.package_total).toBe(2);
  });

  it("drops all scratch tables when done", () => {
    const db = freshDb();
    execAll(db, deltaStatsSql(["CVE-2021-1001"], TEST_OPTS));
    const scratch = db
      .prepare(`SELECT name FROM sqlite_master WHERE name LIKE '\\_%' ESCAPE '\\'`)
      .all();
    expect(scratch).toEqual([]);
  });

  it("returns [] for an empty cve list", () => {
    expect(deltaStatsSql([], TEST_OPTS)).toEqual([]);
  });

  it("escapes single quotes in ids and batches the manifest", () => {
    const ids = Array.from({ length: 450 }, (_, i) => `CVE-2021-${i}`);
    ids.push("CVE-2021-9'9");
    const stmts = deltaStatsSql(ids, { ...TEST_OPTS, idsPerInsert: 200 });
    const inserts = stmts.filter((s) => s.startsWith("INSERT OR IGNORE INTO _delta_cves"));
    expect(inserts).toHaveLength(3); // 451 ids / 200 per statement
    expect(stmts.join("\n")).toContain("'CVE-2021-9''9'");
  });

  it("never emits an unbounded scan of a big table", () => {
    // Every statement touching vulnerabilities/cvss_scores/affected must carry
    // a bounding predicate (PK range, scratch-table drive, or kev index).
    const stmts = deltaStatsSql(["CVE-2021-1001"], TEST_OPTS);
    for (const s of stmts) {
      if (/FROM (vulnerabilities|cvss_scores)\b/.test(s) && !/JOIN/.test(s)) {
        expect(
          /cve_id >=|cve_id </.test(s) || /WHERE kev = 1/.test(s),
          `unbounded statement: ${s}`,
        ).toBe(true);
      }
      if (/FROM affected\b/.test(s)) {
        expect(s).toContain("_delta_cves");
      }
    }
  });
});

describe("rebuildAllStatsSql", () => {
  it("rebuilds both tables from scratch on a stats-less database", () => {
    const db = new Database(":memory:");
    buildSchema(db);
    seedFixture(db);
    // Simulate pre-migration D1: stats tables exist (buildSchema) but empty.
    execAll(db, rebuildAllStatsSql(TEST_OPTS));

    expect((db.prepare(`SELECT COUNT(*) AS c FROM package_stats`).get() as { c: number }).c).toBe(2);
    const page = db.prepare(`SELECT * FROM page_stats WHERE id = 1`).get() as Record<string, unknown>;
    expect(page.vuln_total).toBe(3);
    expect(page.critical_total).toBe(1);
    // Scratch cleaned:
    expect(
      db.prepare(`SELECT name FROM sqlite_master WHERE name LIKE '\\_%' ESCAPE '\\'`).all(),
    ).toEqual([]);
  });

  it("starts with the DDL so it works on a database missing the tables", () => {
    const stmts = rebuildAllStatsSql(TEST_OPTS);
    expect(stmts[0]).toContain("CREATE TABLE IF NOT EXISTS page_stats");
  });
});
