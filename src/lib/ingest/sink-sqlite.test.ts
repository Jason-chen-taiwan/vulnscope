import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { buildSchema } from "../../../scripts/build-sqlite.js";
import { SqliteIngestSink } from "./sink-sqlite.js";
import type { VulnRow } from "./sink.js";

describe("SqliteIngestSink", () => {
  let db: InstanceType<typeof Database>;
  let sink: SqliteIngestSink;

  beforeEach(() => {
    db = new Database(":memory:");
    buildSchema(db);
    sink = new SqliteIngestSink(db);
  });

  const vulnA: VulnRow = {
    cveId: "CVE-2024-0001",
    sourceId: "OSV-A",
    summary: "First vuln",
    description: "desc A",
    publishedAt: new Date("2024-01-01T00:00:00Z"),
    modifiedAt: new Date("2024-01-02T00:00:00Z"),
  };
  const vulnB: VulnRow = {
    cveId: "CVE-2024-0002",
    sourceId: "OSV-B",
    summary: "Second vuln",
    description: "desc B",
    publishedAt: null,
    modifiedAt: null,
  };

  it("inserts vuln rows and they land in the table", async () => {
    await sink.flushVulns([vulnA, vulnB]);
    const rows = db
      .prepare("SELECT cve_id, source_id, summary, published_at FROM vulnerabilities ORDER BY cve_id")
      .all() as { cve_id: string; source_id: string; summary: string; published_at: string | null }[];
    expect(rows).toHaveLength(2);
    expect(rows[0].cve_id).toBe("CVE-2024-0001");
    expect(rows[0].summary).toBe("First vuln");
    // Dates stored as ISO-8601 TEXT.
    expect(rows[0].published_at).toBe("2024-01-01T00:00:00.000Z");
    expect(rows[1].published_at).toBeNull();
  });

  it("upserts on cve_id conflict rather than duplicating", async () => {
    await sink.flushVulns([vulnA]);
    // Second insert with the same cve_id: new source_id wins, summary
    // updates only if the incoming one is non-null (COALESCE semantics).
    await sink.flushVulns([
      { ...vulnA, sourceId: "OSV-A-v2", summary: "Updated summary" },
    ]);
    const rows = db
      .prepare("SELECT cve_id, source_id, summary FROM vulnerabilities")
      .all() as { cve_id: string; source_id: string; summary: string }[];
    expect(rows).toHaveLength(1); // upsert, not duplicate
    expect(rows[0].source_id).toBe("OSV-A-v2");
    expect(rows[0].summary).toBe("Updated summary");
  });

  it("COALESCE keeps existing summary when incoming is null", async () => {
    await sink.flushVulns([vulnA]);
    await sink.flushVulns([{ ...vulnA, summary: null, description: null }]);
    const row = db
      .prepare("SELECT summary, description FROM vulnerabilities WHERE cve_id = ?")
      .get("CVE-2024-0001") as { summary: string; description: string };
    expect(row.summary).toBe("First vuln");
    expect(row.description).toBe("desc A");
  });

  it("get-or-create package id is stable across calls (no duplicate rows)", async () => {
    const id1 = await sink.getOrCreatePackageId("npm", "lodash");
    const id2 = await sink.getOrCreatePackageId("npm", "lodash");
    const id3 = await sink.getOrCreatePackageId("npm", "react");
    expect(id1).toBe(id2);
    expect(id3).not.toBe(id1);
    const count = (
      db.prepare("SELECT COUNT(*) AS c FROM packages").get() as { c: number }
    ).c;
    expect(count).toBe(2);
  });

  it("normalizes PyPI package names on get-or-create", async () => {
    const id1 = await sink.getOrCreatePackageId("PyPI", "Flask_Login");
    const id2 = await sink.getOrCreatePackageId("PyPI", "flask-login");
    expect(id1).toBe(id2);
    const name = (
      db.prepare("SELECT name FROM packages WHERE id = ?").get(id1) as { name: string }
    ).name;
    expect(name).toBe("flask-login");
  });

  it("dedupes cvss / affected / refs / aliases on re-insert", async () => {
    await sink.flushVulns([vulnA]);
    const pkgId = await sink.getOrCreatePackageId("npm", "lodash");

    const cvss = { cveId: "CVE-2024-0001", version: "3.1", vector: "CVSS:3.1/AV:N", baseScore: "9.8", severity: "CRITICAL" };
    const affectedRow = { cveId: "CVE-2024-0001", packageId: pkgId, ecosystem: "npm", rangesJson: [{ type: "SEMVER" }], versionsJson: ["1.0.0"], sourceId: "OSV-A" };
    const refRow = { cveId: "CVE-2024-0001", url: "https://example.com/a", type: "WEB" };
    const aliasRow = { cveId: "CVE-2024-0001", alias: "GHSA-xxxx", source: "ghsa" };

    // Insert twice — second flush must be a no-op (DO NOTHING semantics).
    await sink.flushCvss([cvss, cvss]);
    await sink.flushCvss([cvss]);
    await sink.flushAffected([affectedRow, affectedRow]);
    await sink.flushAffected([affectedRow]);
    await sink.flushRefs([refRow, refRow]);
    await sink.flushRefs([refRow]);
    await sink.flushAliases([aliasRow, aliasRow]);
    await sink.flushAliases([aliasRow]);

    const n = (t: string) => (db.prepare(`SELECT COUNT(*) AS c FROM ${t}`).get() as { c: number }).c;
    expect(n("cvss_scores")).toBe(1);
    expect(n("affected")).toBe(1);
    expect(n("refs")).toBe(1);
    expect(n("vuln_aliases")).toBe(1);

    // jsonb columns round-trip as JSON text.
    const aff = db.prepare("SELECT ranges_json, versions_json FROM affected").get() as { ranges_json: string; versions_json: string };
    expect(JSON.parse(aff.ranges_json)).toEqual([{ type: "SEMVER" }]);
    expect(JSON.parse(aff.versions_json)).toEqual(["1.0.0"]);
    // base_score stored as REAL.
    const c = db.prepare("SELECT base_score FROM cvss_scores").get() as { base_score: number };
    expect(c.base_score).toBeCloseTo(9.8);
  });
});
