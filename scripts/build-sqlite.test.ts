import { describe, it, expect, beforeAll } from "vitest";
import Database from "better-sqlite3";
import { buildSchema } from "./build-sqlite.js";

describe("buildSchema", () => {
  let db: InstanceType<typeof Database>;

  beforeAll(() => {
    db = new Database(":memory:");
    buildSchema(db);
  });

  it("creates the 6 base tables", () => {
    const tables = db
      .prepare(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '%_fts%' AND name NOT LIKE '%_content%' AND name NOT LIKE '%_data%' AND name NOT LIKE '%_idx%' AND name NOT LIKE '%_docsize%' AND name NOT LIKE '%_config%'`
      )
      .all()
      .map((r: { name: string }) => r.name);

    const expected = [
      "vulnerabilities",
      "packages",
      "affected",
      "cvss_scores",
      "vuln_aliases",
      "refs",
    ];
    for (const t of expected) {
      expect(tables, `table '${t}' should exist`).toContain(t);
    }
    expect(tables).toHaveLength(6);
  });

  it("creates the 2 FTS5 virtual tables", () => {
    const vtables = db
      .prepare(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('vulns_fts', 'packages_fts')`
      )
      .all()
      .map((r: { name: string }) => r.name);

    expect(vtables).toContain("vulns_fts");
    expect(vtables).toContain("packages_fts");
    expect(vtables).toHaveLength(2);
  });

  it("creates the 10 plain indexes", () => {
    const indexes = db
      .prepare(`SELECT name FROM sqlite_master WHERE type = 'index'`)
      .all()
      .map((r: { name: string }) => r.name);

    const expected = [
      "idx_affected_cve",
      "idx_affected_pkg",
      "idx_cvss_cve",
      "idx_aliases_cve",
      "idx_aliases_alias",
      "idx_refs_cve",
      "idx_pkg_eco_name",
      "idx_vuln_kev",
      "idx_vuln_published",
      "idx_vuln_epss",
    ];
    for (const idx of expected) {
      expect(indexes, `index '${idx}' should exist`).toContain(idx);
    }
  });
});
