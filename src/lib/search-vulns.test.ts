import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import Database from "better-sqlite3";
import { buildSchema } from "../../scripts/build-sqlite.js";

/**
 * Regression test for the searchVulns parameter-rotation bug (Critical #1).
 *
 * The `pkg_match_cves` CTE is textually PREPENDED before the WHERE clause, so
 * SQLite/D1 bind the bare `?` markers positionally by text order. If the param
 * push order doesn't match the text order, the raw query string gets bound to
 * `vulns_fts MATCH ?` — and an exact-CVE search like "CVE-2021-44228" then
 * parses `2021` as a column ("no such column: 2021"), throwing and 500-ing the
 * whole /search endpoint.
 *
 * We back the real `pool.query` (from @/db/client) with an in-memory
 * better-sqlite3 built via buildSchema, so this test exercises the ACTUAL
 * SQL text and ACTUAL param array searchVulns produces — not a hand-corrected
 * copy. This FAILS against the buggy push order and PASSES after the fix.
 */

// `queries.ts` starts with `import "server-only"`, whose default entry
// throws outside a React Server Component build. Neutralise it for the test.
vi.mock("server-only", () => ({}));

// Shared in-memory DB the mocked pool reads from.
let db: InstanceType<typeof Database>;

vi.mock("@/db/client", () => ({
  // `searchVulns` only touches `pool.query`; `db` (drizzle) is referenced
  // solely in a `void` no-op, so a bare object satisfies the import.
  db: {},
  schema: {},
  pool: {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    query: async (sql: string, params: unknown[] = []): Promise<{ rows: any[] }> => {
      const rows = db.prepare(sql).all(...(params as unknown[]));
      return { rows };
    },
  },
}));

// Import AFTER the mock is registered.
const { searchVulns } = await import("./queries.js");

function seed(database: InstanceType<typeof Database>) {
  buildSchema(database);
  const insV = database.prepare(
    `INSERT INTO vulnerabilities
       (cve_id, source_id, summary, description, published_at, kev, epss_score, epss_percentile)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  insV.run("CVE-2021-44228", "OSV-A", "Log4Shell", "Remote code execution in Apache Log4j", "2021-12-10T00:00:00Z", 1, null, null);
  insV.run("CVE-2023-0001", "OSV-B", "SQL injection", "SQL injection in example lib", "2023-01-01T00:00:00Z", 0, null, null);
  insV.run("CVE-2020-9999", "OSV-C", "Buffer overflow", "A buffer overflow bug", "2020-05-05T00:00:00Z", 0, null, null);

  // packages / affected so the CTE's package-match path has data to bind against.
  database.prepare(`INSERT INTO packages (id, ecosystem, name) VALUES (1, 'Maven', 'log4j-core')`).run();
  database
    .prepare(`INSERT INTO affected (cve_id, package_id, ecosystem, ranges_json, versions_json, source_id) VALUES (?, ?, ?, ?, ?, ?)`)
    .run("CVE-2021-44228", 1, "Maven", "[]", "[]", "OSV-A");

  // FTS indexes (searchVulns MATCHes against these).
  database.exec(`
    INSERT INTO vulns_fts(cve_id, summary, description)
      SELECT cve_id, summary, description FROM vulnerabilities;
    INSERT INTO packages_fts(rowid, name)
      SELECT id, name FROM packages;
  `);
}

describe("searchVulns (Critical #1 regression)", () => {
  beforeAll(() => {
    db = new Database(":memory:");
    seed(db);
  });
  afterAll(() => db.close());

  it("(a) exact CVE-id search returns that CVE without throwing", async () => {
    // Before the fix this throws "no such column: 2021".
    const res = await searchVulns({ q: "CVE-2021-44228" });
    const ids = res.items.map((r) => r.cve_id);
    expect(ids).toContain("CVE-2021-44228");
    expect(res.total).toBeGreaterThanOrEqual(1);
  });

  it("(b) word search returns matching rows", async () => {
    const res = await searchVulns({ q: "injection" });
    const ids = res.items.map((r) => r.cve_id);
    expect(ids).toContain("CVE-2023-0001");
  });

  it("(c) package-name search resolves via the CTE without throwing", async () => {
    const res = await searchVulns({ q: "log4j-core" });
    const ids = res.items.map((r) => r.cve_id);
    expect(ids).toContain("CVE-2021-44228");
  });

  it("(d) no exception is thrown for a bare CVE token that looks like FTS operators", async () => {
    await expect(searchVulns({ q: "CVE-2020-9999" })).resolves.toBeTruthy();
  });
});
