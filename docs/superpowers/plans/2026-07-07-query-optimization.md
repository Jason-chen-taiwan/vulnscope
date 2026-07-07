# Request-Path Query Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate every request-path query capable of overloading D1 by precomputing aggregates at ingest time (`page_stats` + `package_stats` tables), and give `unstable_cache` a real KV backend on Workers.

**Architecture:** A pure statement-generator module (`src/lib/ingest/stats-sql.ts`) produces bounded, index-driven SQL for three contexts: local full build (full scans OK), daily D1 delta (scoped to touched packages + year/id-range chunked recounts), and one-time D1 rebuild. A read-SQL module (`src/lib/stats-read-sql.ts`, no `server-only`, vitest-testable) holds the new request-path SQL. Call sites in `queries.ts` / `insights.ts` / `sitemap.ts` swap to stats-table reads. Phase 2 wires `@opennextjs/cloudflare`'s KV incremental cache.

**Tech Stack:** TypeScript, better-sqlite3 (tests/build), vitest, bash+sqlite3 (push script), Cloudflare D1/KV, @opennextjs/cloudflare 1.20.

## Global Constraints

- **NEVER touch remote D1.** No task runs `wrangler … --remote` or `push-to-d1.sh` against any real database. Script changes are verified by inspecting generated SQL files locally. Production rollout is a documented manual step (Task 7), executed by the human after D1 recovers.
- **Every D1-bound statement must be bounded**: no full-table scan of `vulnerabilities`, `affected`, or `cvss_scores` in any single generated statement. Chunk by CVE-year PK range, integer-id range, or drive from a small scratch table. (Local-build SQL in `fullBuildStatsSql` is exempt — it runs on the build machine.)
- **No new indexes on `affected` or `cvss_scores`.** Only `package_stats` gets indexes.
- **Sentinel discipline**: every statement destined for the delta stream is followed by a line containing exactly `--@@STMT@@`.
- **`sync_state` rows must remain the LAST statements** in the generated delta SQL (watermark-after-data invariant).
- Existing test suite (231 tests) + `pnpm exec tsc --noEmit` stay green after every task.
- Run tests with `pnpm vitest run <file>`; full suite `pnpm test`.

---

## File Structure

- Create `src/lib/ingest/stats-sql.ts` — pure generators: `statsDdl()`, `fullBuildStatsSql()`, `deltaStatsSql(cveIds, opts?)`, `rebuildAllStatsSql(opts?)`.
- Create `src/lib/ingest/stats-sql.test.ts` — generator shape + real-execution tests on in-memory SQLite.
- Create `scripts/emit-stats-sql.ts` — CLI bridging the generators into `push-to-d1.sh`.
- Create `src/lib/stats-read-sql.ts` — request-path SQL constants + `browsePackagesListSql()` builder (importable by vitest — NO `server-only`).
- Create `src/lib/stats-read-sql.test.ts` — executes every constant against a fixture DB.
- Modify `scripts/build-sqlite.ts` — stats DDL in `buildSchema`, compute stats at end of `main()`.
- Modify `scripts/build-sqlite.test.ts` — table-count expectations (7 → 9).
- Modify `scripts/push-to-d1.sh` — delta appends stats SQL; new `stats-rebuild` mode; verify section stops running `count(*)` full scans.
- Modify `src/lib/queries.ts`, `src/lib/insights.ts`, `src/app/sitemap.ts` — swap to stats reads.
- Modify `open-next.config.ts`, `wrangler.jsonc`, `next.config.ts` — Phase 2 caching.
- Modify `docs/incremental-ingest.md`, `docs/d1-recovery-and-verify.md` — ops docs.

---

### Task 1: stats DDL + local full-build compute

**Files:**
- Create: `src/lib/ingest/stats-sql.ts`
- Create: `src/lib/ingest/stats-sql.test.ts`
- Modify: `scripts/build-sqlite.ts` (buildSchema + main)
- Modify: `scripts/build-sqlite.test.ts` (table count 7 → 9)

**Interfaces:**
- Consumes: nothing (pure module).
- Produces: `statsDdl(): string[]` and `fullBuildStatsSql(): string[]` — arrays of single SQL statements WITHOUT trailing semicolons or sentinels (callers add what they need). `buildSchema(db)` now also creates `page_stats` + `package_stats`.

- [ ] **Step 1: Write the failing test**

Create `src/lib/ingest/stats-sql.test.ts`:

```typescript
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
      .map((r: { name: string }) => r.name);
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run src/lib/ingest/stats-sql.test.ts`
Expected: FAIL — `Cannot find module './stats-sql.js'`

- [ ] **Step 3: Write the implementation**

Create `src/lib/ingest/stats-sql.ts`:

```typescript
/**
 * SQL statement generators for the precomputed stats tables.
 *
 * Why these tables exist: the request path previously ran full-table
 * aggregations (COUNT(*) over 74k vulnerabilities, GROUP BY over 119k
 * affected rows) on every cold render, which overloaded D1
 * ("D1 DB is overloaded. Requests queued for too long.", 2026-07-06).
 * Data changes only at ingest, so aggregates are computed at ingest and
 * the request path reads them back with O(1)/indexed queries.
 *
 * Three contexts, three generators:
 *  - fullBuildStatsSql(): local full build — full scans are fine locally.
 *  - deltaStatsSql():     daily D1 delta — every statement bounded (Task 2).
 *  - rebuildAllStatsSql():one-time D1 backfill — sharded (Task 2).
 *
 * All functions return arrays of single SQL statements WITHOUT trailing
 * semicolons — callers append ';' and/or the '--@@STMT@@' sentinel.
 */

export function statsDdl(): string[] {
  return [
    `CREATE TABLE IF NOT EXISTS page_stats (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  vuln_total INTEGER NOT NULL DEFAULT 0,
  package_total INTEGER NOT NULL DEFAULT 0,
  critical_total INTEGER NOT NULL DEFAULT 0,
  kev_total INTEGER NOT NULL DEFAULT 0,
  computed_at TEXT
)`,
    `CREATE TABLE IF NOT EXISTS package_stats (
  package_id INTEGER PRIMARY KEY,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  cve_count INTEGER NOT NULL DEFAULT 0,
  kev_count INTEGER NOT NULL DEFAULT 0,
  max_epss REAL
)`,
    `CREATE INDEX IF NOT EXISTS idx_pkgstats_eco_rank
  ON package_stats(ecosystem, kev_count DESC, cve_count DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_pkgstats_rank
  ON package_stats(kev_count DESC, cve_count DESC)`,
  ];
}

/**
 * The one aggregation SELECT shared by every package_stats writer.
 * `fromClause` supplies the driving table(s); it must expose packages as
 * `p`, affected as `a`, vulnerabilities as `v`.
 */
const PACKAGE_STATS_SELECT = `SELECT p.id, p.ecosystem, p.name,
       COUNT(DISTINCT a.cve_id),
       COUNT(DISTINCT CASE WHEN v.kev = 1 THEN a.cve_id END),
       CAST(MAX(v.epss_score) AS REAL)`;

/** Local full build: full scans are fine on the build machine. */
export function fullBuildStatsSql(): string[] {
  return [
    `DELETE FROM package_stats`,
    `INSERT INTO package_stats (package_id, ecosystem, name, cve_count, kev_count, max_epss)
${PACKAGE_STATS_SELECT}
  FROM packages p
  JOIN affected a ON a.package_id = p.id
  JOIN vulnerabilities v ON v.cve_id = a.cve_id
 GROUP BY p.id, p.ecosystem, p.name`,
    `INSERT OR REPLACE INTO page_stats
  (id, vuln_total, package_total, critical_total, kev_total, computed_at)
SELECT 1,
  (SELECT COUNT(*) FROM vulnerabilities),
  (SELECT COUNT(*) FROM packages),
  (SELECT COUNT(*) FROM cvss_scores WHERE severity = 'CRITICAL'),
  (SELECT COUNT(*) FROM vulnerabilities WHERE kev = 1),
  datetime('now')`,
  ];
}
```

(`PACKAGE_STATS_SELECT` stays module-internal — Task 2's generators live in the same file and reference it directly; nothing outside the module needs it.)

- [ ] **Step 4: Wire into buildSchema and the build entry point**

In `scripts/build-sqlite.ts`:

(a) Add the import at the top (after the existing ingest imports):

```typescript
import { statsDdl, fullBuildStatsSql } from "../src/lib/ingest/stats-sql";
```

(b) At the END of `buildSchema` (after the `db.exec(...)` block, still inside the function), add:

```typescript
  // Precomputed stats tables (see src/lib/ingest/stats-sql.ts). Part of the
  // schema so the full build, tests, and the D1 additive migration all agree.
  for (const stmt of statsDdl()) db.exec(stmt);
```

(c) In `main()`, right after `buildFts(db);`, add:

```typescript
  console.log("[stats] computing page_stats + package_stats");
  for (const stmt of fullBuildStatsSql()) db.exec(stmt);
```

(d) Extend the final counts SELECT in `main()` with two subqueries (inside the same query string, after the `packages_fts` line — add a comma after `AS packages_fts`):

```sql
         (SELECT COUNT(*) FROM package_stats)  AS package_stats,
         (SELECT vuln_total FROM page_stats WHERE id = 1) AS stats_vuln_total
```

- [ ] **Step 5: Update the schema test's expectations**

In `scripts/build-sqlite.test.ts`, the "creates the 7 base tables" test: add `"page_stats"` and `"package_stats"` to the `expected` array, change `expect(tables).toHaveLength(7)` to `expect(tables).toHaveLength(9)`, and rename the test to `"creates the 9 base tables"`. In the "creates the plain indexes" test, add `"idx_pkgstats_eco_rank"` and `"idx_pkgstats_rank"` to its expected list (keep the rest untouched).

- [ ] **Step 6: Run tests to verify they pass**

Run: `pnpm vitest run src/lib/ingest/stats-sql.test.ts scripts/build-sqlite.test.ts`
Expected: PASS (all).

- [ ] **Step 7: Type-check and commit**

```bash
pnpm exec tsc --noEmit
git add src/lib/ingest/stats-sql.ts src/lib/ingest/stats-sql.test.ts scripts/build-sqlite.ts scripts/build-sqlite.test.ts
git commit -m "feat(stats): page_stats + package_stats tables, computed in full build"
```

---

### Task 2: D1-side delta + rebuild statement generators

**Files:**
- Modify: `src/lib/ingest/stats-sql.ts`
- Modify: `src/lib/ingest/stats-sql.test.ts`

**Interfaces:**
- Consumes: `statsDdl()` and the module-internal `PACKAGE_STATS_SELECT` from Task 1 (same file).
- Produces:
  - `interface StatsSqlOptions { yearStart?: number; yearEndExclusive?: number; pkgIdStep?: number; pkgIdMax?: number; rebuildStep?: number; idsPerInsert?: number; recomputeShards?: number }`
  - `deltaStatsSql(cveIds: string[], opts?: StatsSqlOptions): string[]`
  - `rebuildAllStatsSql(opts?: StatsSqlOptions): string[]`

**Bounded-statement rules this task implements:**
- `_delta_cves` manifest INSERTs carry ≤ `idsPerInsert` (200) ids each.
- Touched-package recompute is sharded `package_id % recomputeShards` (8) — the modulo scan runs over the tiny `_touched_pkgs` scratch table, not a big table.
- `page_stats` recount: `vulnerabilities` and `cvss_scores` chunked by CVE-year PK ranges (`cve_id >= 'CVE-1999-' AND cve_id < 'CVE-2000-'` …) with an under-range chunk (`< 'CVE-<yearStart>-'`) and an open-ended final chunk (`>= 'CVE-<yearEndExclusive>-'`); `packages` chunked by id ranges of `pkgIdStep` (2000) up to `pkgIdMax` (100000) plus open-ended final chunk; `kev_total` is a single `idx_vuln_kev` statement.

- [ ] **Step 1: Write the failing tests**

Append to `src/lib/ingest/stats-sql.test.ts`:

```typescript
import { deltaStatsSql, rebuildAllStatsSql } from "./stats-sql.js";

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm vitest run src/lib/ingest/stats-sql.test.ts`
Expected: FAIL — `deltaStatsSql is not a function` (or missing export).

- [ ] **Step 3: Write the implementation**

Append to `src/lib/ingest/stats-sql.ts`:

```typescript
export interface StatsSqlOptions {
  /** First CVE year chunk (default 1999). */
  yearStart?: number;
  /** Exclusive upper year; the final chunk is open-ended `>= 'CVE-<this>-'`.
   *  Default: current UTC year + 1, so the current year is always a bounded
   *  chunk and anything newer lands in the open-ended tail. */
  yearEndExclusive?: number;
  /** packages id-range chunk size for page_stats.package_total (default 2000). */
  pkgIdStep?: number;
  /** Last bounded package id; final chunk is open-ended `>= this` (default 100000). */
  pkgIdMax?: number;
  /** package_stats rebuild id-range chunk size (default 1000). */
  rebuildStep?: number;
  /** _delta_cves manifest ids per INSERT statement (default 200). */
  idsPerInsert?: number;
  /** Modulo shards for the touched-package recompute (default 8). */
  recomputeShards?: number;
}

function resolveOpts(opts?: StatsSqlOptions): Required<StatsSqlOptions> {
  return {
    yearStart: opts?.yearStart ?? 1999,
    yearEndExclusive: opts?.yearEndExclusive ?? new Date().getUTCFullYear() + 1,
    pkgIdStep: opts?.pkgIdStep ?? 2000,
    pkgIdMax: opts?.pkgIdMax ?? 100_000,
    rebuildStep: opts?.rebuildStep ?? 1000,
    idsPerInsert: opts?.idsPerInsert ?? 200,
    recomputeShards: opts?.recomputeShards ?? 8,
  };
}

function sqlQuote(id: string): string {
  return `'${id.replace(/'/g, "''")}'`;
}

/**
 * Chunked recount of page_stats. Bounded per statement:
 *  - vuln_total / critical_total: CVE-year PK ranges + under/over catch-alls
 *  - package_total: integer id ranges + open-ended tail
 *  - kev_total: single statement via idx_vuln_kev (~1.6k rows)
 * Results accumulate in _stats_scratch, then one INSERT OR REPLACE.
 */
function pageStatsRecountSql(o: Required<StatsSqlOptions>): string[] {
  const stmts: string[] = [
    `DROP TABLE IF EXISTS _stats_scratch`,
    `CREATE TABLE _stats_scratch (k TEXT NOT NULL, v INTEGER NOT NULL)`,
  ];
  const yearRanges: Array<[string, string | null]> = [];
  yearRanges.push(["", `CVE-${o.yearStart}-`]); // under-range catch-all
  for (let y = o.yearStart; y < o.yearEndExclusive; y++) {
    yearRanges.push([`CVE-${y}-`, `CVE-${y + 1}-`]);
  }
  yearRanges.push([`CVE-${o.yearEndExclusive}-`, null]); // open-ended tail

  for (const [lo, hi] of yearRanges) {
    const bounds = [
      lo ? `cve_id >= ${sqlQuote(lo)}` : null,
      hi ? `cve_id < ${sqlQuote(hi)}` : null,
    ].filter(Boolean).join(" AND ");
    stmts.push(
      `INSERT INTO _stats_scratch (k, v) VALUES ('vuln',
  (SELECT COUNT(*) FROM vulnerabilities WHERE ${bounds}))`,
      `INSERT INTO _stats_scratch (k, v) VALUES ('crit',
  (SELECT COUNT(*) FROM cvss_scores WHERE ${bounds} AND severity = 'CRITICAL'))`,
    );
  }
  for (let lo = 0; lo < o.pkgIdMax; lo += o.pkgIdStep) {
    stmts.push(
      `INSERT INTO _stats_scratch (k, v) VALUES ('pkg',
  (SELECT COUNT(*) FROM packages WHERE id >= ${lo} AND id < ${lo + o.pkgIdStep}))`,
    );
  }
  stmts.push(
    `INSERT INTO _stats_scratch (k, v) VALUES ('pkg',
  (SELECT COUNT(*) FROM packages WHERE id >= ${o.pkgIdMax}))`,
    `INSERT INTO _stats_scratch (k, v) VALUES ('kev',
  (SELECT COUNT(*) FROM vulnerabilities WHERE kev = 1))`,
    `INSERT OR REPLACE INTO page_stats
  (id, vuln_total, package_total, critical_total, kev_total, computed_at)
SELECT 1,
  (SELECT COALESCE(SUM(v), 0) FROM _stats_scratch WHERE k = 'vuln'),
  (SELECT COALESCE(SUM(v), 0) FROM _stats_scratch WHERE k = 'pkg'),
  (SELECT COALESCE(SUM(v), 0) FROM _stats_scratch WHERE k = 'crit'),
  (SELECT COALESCE(SUM(v), 0) FROM _stats_scratch WHERE k = 'kev'),
  datetime('now')`,
    `DROP TABLE _stats_scratch`,
  );
  return stmts;
}

/**
 * Daily-delta stats refresh, run ON D1 after the data statements landed.
 * Scoped: only packages touched by the delta's CVEs are recomputed
 * (idx_affected_cve finds them; idx_affected_pkg drives each recompute).
 */
export function deltaStatsSql(cveIds: string[], opts?: StatsSqlOptions): string[] {
  if (cveIds.length === 0) return [];
  const o = resolveOpts(opts);
  const stmts: string[] = [
    `DROP TABLE IF EXISTS _delta_cves`,
    `CREATE TABLE _delta_cves (cve_id TEXT PRIMARY KEY)`,
  ];
  for (let i = 0; i < cveIds.length; i += o.idsPerInsert) {
    const batch = cveIds.slice(i, i + o.idsPerInsert);
    stmts.push(
      `INSERT OR IGNORE INTO _delta_cves (cve_id) VALUES ${batch
        .map((id) => `(${sqlQuote(id)})`)
        .join(",")}`,
    );
  }
  stmts.push(
    `DROP TABLE IF EXISTS _touched_pkgs`,
    `CREATE TABLE _touched_pkgs (package_id INTEGER PRIMARY KEY)`,
    `INSERT OR IGNORE INTO _touched_pkgs (package_id)
SELECT DISTINCT package_id FROM affected
 WHERE package_id IS NOT NULL
   AND cve_id IN (SELECT cve_id FROM _delta_cves)`,
  );
  for (let k = 0; k < o.recomputeShards; k++) {
    stmts.push(
      `DELETE FROM package_stats WHERE package_id IN
  (SELECT package_id FROM _touched_pkgs WHERE package_id % ${o.recomputeShards} = ${k})`,
      `INSERT INTO package_stats (package_id, ecosystem, name, cve_count, kev_count, max_epss)
${PACKAGE_STATS_SELECT}
  FROM _touched_pkgs t
  JOIN packages p ON p.id = t.package_id
  JOIN affected a ON a.package_id = t.package_id
  JOIN vulnerabilities v ON v.cve_id = a.cve_id
 WHERE t.package_id % ${o.recomputeShards} = ${k}
 GROUP BY p.id, p.ecosystem, p.name`,
    );
  }
  stmts.push(...pageStatsRecountSql(o));
  stmts.push(`DROP TABLE IF EXISTS _touched_pkgs`, `DROP TABLE IF EXISTS _delta_cves`);
  return stmts;
}

/**
 * One-time D1 backfill (additive migration) and disaster-recovery rebuild.
 * DDL first (IF NOT EXISTS), then package_stats sharded by id ranges, then
 * the same chunked page_stats recount the daily delta uses.
 */
export function rebuildAllStatsSql(opts?: StatsSqlOptions): string[] {
  const o = resolveOpts(opts);
  const stmts: string[] = [...statsDdl()];
  const ranges: Array<[number, number | null]> = [];
  for (let lo = 0; lo < o.pkgIdMax; lo += o.rebuildStep) ranges.push([lo, lo + o.rebuildStep]);
  ranges.push([o.pkgIdMax, null]);
  for (const [lo, hi] of ranges) {
    const bound = hi === null ? `p.id >= ${lo}` : `p.id >= ${lo} AND p.id < ${hi}`;
    const delBound = hi === null ? `package_id >= ${lo}` : `package_id >= ${lo} AND package_id < ${hi}`;
    stmts.push(
      `DELETE FROM package_stats WHERE ${delBound}`,
      `INSERT INTO package_stats (package_id, ecosystem, name, cve_count, kev_count, max_epss)
${PACKAGE_STATS_SELECT}
  FROM packages p
  JOIN affected a ON a.package_id = p.id
  JOIN vulnerabilities v ON v.cve_id = a.cve_id
 WHERE ${bound}
 GROUP BY p.id, p.ecosystem, p.name`,
    );
  }
  stmts.push(...pageStatsRecountSql(o));
  return stmts;
}
```

Note: `PACKAGE_STATS_SELECT` is the module-internal const Task 1 defined in this same file — the template literals above reference it directly.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pnpm vitest run src/lib/ingest/stats-sql.test.ts`
Expected: PASS (all, including Task 1's).

- [ ] **Step 5: Type-check and commit**

```bash
pnpm exec tsc --noEmit
git add src/lib/ingest/stats-sql.ts src/lib/ingest/stats-sql.test.ts
git commit -m "feat(stats): bounded D1 delta refresh + sharded rebuild generators"
```

---

### Task 3: emit-stats-sql CLI + push-to-d1.sh integration

**Files:**
- Create: `scripts/emit-stats-sql.ts`
- Modify: `scripts/push-to-d1.sh`

**Interfaces:**
- Consumes: `deltaStatsSql`, `rebuildAllStatsSql` from Task 2.
- Produces: CLI `tsx scripts/emit-stats-sql.ts delta <delta.sqlite>` and `tsx scripts/emit-stats-sql.ts rebuild` — each prints statements terminated by `;` and a `--@@STMT@@` sentinel line. `push-to-d1.sh` gains `stats-rebuild` mode and appends delta stats SQL between FTS and sync_state.

- [ ] **Step 1: Write the CLI**

Create `scripts/emit-stats-sql.ts`:

```typescript
/**
 * Emit stats-refresh SQL for push-to-d1.sh.
 *
 *   tsx scripts/emit-stats-sql.ts delta <delta.sqlite>
 *     → scoped package_stats recompute + chunked page_stats recount for the
 *       CVEs the delta touches. Appended to the delta stream AFTER data/FTS
 *       and BEFORE sync_state.
 *
 *   tsx scripts/emit-stats-sql.ts rebuild
 *     → DDL + full sharded backfill (one-time additive migration /
 *       disaster recovery). Pushed via push-to-d1.sh stats-rebuild mode.
 *
 * Output format: every statement is printed with a trailing ';' followed by
 * a line containing exactly '--@@STMT@@' (the push script's batching sentinel).
 */
import DatabaseCtor from "better-sqlite3";
import { deltaStatsSql, rebuildAllStatsSql } from "../src/lib/ingest/stats-sql";

function emit(stmts: string[]): void {
  for (const s of stmts) {
    process.stdout.write(`${s};\n--@@STMT@@\n`);
  }
}

function main(): void {
  const [mode, sqliteFile] = process.argv.slice(2);
  if (mode === "rebuild") {
    emit(rebuildAllStatsSql());
    return;
  }
  if (mode === "delta") {
    if (!sqliteFile) {
      console.error("usage: emit-stats-sql.ts delta <delta.sqlite>");
      process.exit(1);
    }
    const db = new DatabaseCtor(sqliteFile, { readonly: true });
    // Same touched-CVE union the push script uses for its child-table scoping.
    const rows = db
      .prepare(
        `SELECT cve_id FROM vulnerabilities
         UNION SELECT cve_id FROM affected     WHERE cve_id IS NOT NULL
         UNION SELECT cve_id FROM cvss_scores  WHERE cve_id IS NOT NULL
         UNION SELECT cve_id FROM vuln_aliases WHERE cve_id IS NOT NULL
         UNION SELECT cve_id FROM refs         WHERE cve_id IS NOT NULL`,
      )
      .all() as Array<{ cve_id: string }>;
    db.close();
    emit(deltaStatsSql(rows.map((r) => r.cve_id)));
    return;
  }
  console.error(`unknown mode '${mode}' (expected 'delta' or 'rebuild')`);
  process.exit(1);
}

main();
```

- [ ] **Step 2: Smoke-test the CLI locally**

```bash
# Build a tiny fixture delta with sqlite3 (no network):
F=$(mktemp -d)/mini.sqlite
sqlite3 "$F" "CREATE TABLE vulnerabilities (cve_id TEXT PRIMARY KEY, kev INTEGER);
CREATE TABLE affected (cve_id TEXT, package_id INTEGER);
CREATE TABLE cvss_scores (cve_id TEXT);
CREATE TABLE vuln_aliases (cve_id TEXT);
CREATE TABLE refs (cve_id TEXT);
INSERT INTO vulnerabilities VALUES ('CVE-2026-1', 0);"
pnpm exec tsx scripts/emit-stats-sql.ts delta "$F" | head -8
pnpm exec tsx scripts/emit-stats-sql.ts delta "$F" | grep -c '^--@@STMT@@$'
pnpm exec tsx scripts/emit-stats-sql.ts rebuild | head -4
```

Expected: delta output starts with `DROP TABLE IF EXISTS _delta_cves;` + sentinel lines; sentinel count > 60 (manifest + shards + year chunks); rebuild output starts with the `CREATE TABLE IF NOT EXISTS page_stats` DDL.

- [ ] **Step 3: Integrate into push-to-d1.sh delta mode**

In `scripts/push-to-d1.sh`, inside `push_delta()`, AFTER the packages_fts block (the `sqlite3 … FROM packages;` heredoc ending around line 345) and BEFORE the `(f) sync_state` comment block, insert:

```bash
  # ── (e2) Stats refresh: scoped package_stats recompute + chunked page_stats
  #        recount (src/lib/ingest/stats-sql.ts). Emitted AFTER all data/FTS
  #        statements so it aggregates post-upsert state, and BEFORE sync_state
  #        so the watermark-last invariant holds. Every statement is bounded
  #        (year/id-range chunks; scratch-table-driven recompute) — no full
  #        scans of vulnerabilities/affected/cvss_scores on D1. ──
  (cd "$ROOT" && pnpm exec tsx scripts/emit-stats-sql.ts delta "$SQLITE_FILE") >> "$DELTA_SQL"
```

And near the top of the script (right after the `SQLITE_FILE`/`D1_DATABASE` resolution block, before `PUSH_MODE=` is validated), make `SQLITE_FILE` absolute so the `cd "$ROOT"` subshell can still find it:

```bash
# emit-stats-sql runs from $ROOT; make the sqlite path absolute so it resolves.
if [[ -f "$SQLITE_FILE" ]]; then
  SQLITE_FILE="$(cd "$(dirname "$SQLITE_FILE")" && pwd)/$(basename "$SQLITE_FILE")"
fi
```

Finally, add a debug escape hatch so Step 6 (and future ops debugging) can inspect the generated SQL — the `trap` wipes `WORK_DIR` on exit. In `push_delta()`, right after the `grep -vE "$STRIP"` cleanup line, add:

```bash
  # Debug: DEBUG_KEEP_SQL=/path/file.sql preserves the generated delta SQL
  # (WORK_DIR is trap-deleted on exit).
  [[ -n "${DEBUG_KEEP_SQL:-}" ]] && cp "$DELTA_SQL" "$DEBUG_KEEP_SQL"
```

- [ ] **Step 4: Add the stats-rebuild mode**

(a) Extract the batching loop into a reusable function. Immediately BEFORE the `push_delta()` definition, add:

```bash
# Apply a sentinel-delimited SQL file to D1 in batches of 150 statements,
# retrying each batch up to 3×. Shared by delta and stats-rebuild modes.
apply_sentinel_sql() {
  local SQL_FILE="$1"
  local BATCH_DIR="$WORK_DIR/sql-batches-$RANDOM"
  mkdir -p "$BATCH_DIR"
  awk -v dir="$BATCH_DIR" -v per=150 '
    /^--@@STMT@@$/ { sc++; if (sc % per == 0) bi++; next }
    { print >> (dir "/batch-" sprintf("%05d", bi)) }
  ' "$SQL_FILE"
  local TOTAL_BATCHES N=0
  TOTAL_BATCHES=$(find "$BATCH_DIR" -name 'batch-*' | wc -l | tr -d ' ')
  for BATCH in "$BATCH_DIR"/batch-*; do
    N=$((N + 1))
    echo "[push-to-d1]   → batch $N/$TOTAL_BATCHES ($(wc -l < "$BATCH" | tr -d ' ') lines)"
    local ATTEMPT=1 OK=0
    while [[ "$ATTEMPT" -le 3 ]]; do
      if $WRANGLER d1 execute "$D1_DATABASE" --file="$BATCH" --remote --yes; then
        OK=1; break
      fi
      echo "[push-to-d1]     ⚠ batch $N attempt $ATTEMPT failed; retrying …"
      ATTEMPT=$((ATTEMPT + 1))
      sleep 5
    done
    if [[ "$OK" -ne 1 ]]; then
      echo "[push-to-d1] ERROR: batch $N failed after 3 attempts"
      return 1
    fi
  done
  echo "[push-to-d1]   → applied in $TOTAL_BATCHES batch(es)"
}
```

(b) In `push_delta()`, replace everything from `local BATCH_DIR="$WORK_DIR/delta-batches"` through the `echo "[push-to-d1]   → delta applied …"` line with:

```bash
  apply_sentinel_sql "$DELTA_SQL" || return 1
  echo "[push-to-d1]   → delta applied (no tables dropped; existing data preserved)"
```

(c) Add the new mode function after `push_delta()`:

```bash
# ─────────────────────────────────────────────────────────────────────────────
#  STATS-REBUILD MODE — one-time additive migration / disaster recovery.
#  Creates page_stats/package_stats (IF NOT EXISTS) and backfills them with
#  bounded, sharded statements. Touches NO other tables. No SQLite file needed.
# ─────────────────────────────────────────────────────────────────────────────
push_stats_rebuild() {
  local REBUILD_SQL="$WORK_DIR/stats-rebuild.sql"
  echo
  echo "[push-to-d1] [stats-rebuild 1/2] Generating sharded rebuild SQL …"
  (cd "$ROOT" && pnpm exec tsx scripts/emit-stats-sql.ts rebuild) > "$REBUILD_SQL"
  echo "[push-to-d1]   → $(grep -c '^--@@STMT@@$' "$REBUILD_SQL") statement(s)"
  echo
  echo "[push-to-d1] [stats-rebuild 2/2] Applying to D1 ($D1_DATABASE) …"
  apply_sentinel_sql "$REBUILD_SQL"
}
```

(d) Update mode validation and dispatch:

```bash
if [[ "$PUSH_MODE" != "full" && "$PUSH_MODE" != "delta" && "$PUSH_MODE" != "stats-rebuild" ]]; then
  echo "[push-to-d1] ERROR: PUSH_MODE must be 'full', 'delta' or 'stats-rebuild' (got '$PUSH_MODE')"
  exit 1
fi
```

```bash
if [[ "$PUSH_MODE" == "full" ]]; then
  push_full
elif [[ "$PUSH_MODE" == "stats-rebuild" ]]; then
  push_stats_rebuild
else
  push_delta
fi
```

(e) Skip the SQLite-file existence check for stats-rebuild: wrap the existing `if [[ ! -f "$SQLITE_FILE" ]] … fi` validation in `if [[ "$PUSH_MODE" != "stats-rebuild" ]]; then … fi`. NOTE: mode resolution (`PUSH_MODE="${ARG3:-…}"`) currently happens after the file check — move the validation block below mode resolution if needed.

(f) Full mode: add the stats tables to the refresh. In `push_full()`, `BASE_TABLES` gains `page_stats package_stats` (the full-build SQLite now contains them), and the DROP preamble gains, at the TOP (before `DROP TABLE IF EXISTS sync_state;`):

```
DROP TABLE IF EXISTS package_stats;
DROP TABLE IF EXISTS page_stats;
```

- [ ] **Step 5: Fix the Verify section's full-scan counts**

Replace the verification loop at the bottom of the script (the `for TBL in … SELECT count(*) …` block) with cheap probes — `count(*)` on the 74k-row tables is exactly the query class that overloaded D1:

```bash
echo
echo "[push-to-d1] Verification probes (existence only — no full-table counts) …"
for TBL in vulnerabilities packages affected cvss_scores vuln_aliases refs sync_jobs sync_state page_stats package_stats vulns_fts packages_fts; do
  printf "  %-20s " "$TBL:"
  $WRANGLER d1 execute "$D1_DATABASE" \
    --remote \
    --command="SELECT CASE WHEN EXISTS (SELECT 1 FROM $TBL LIMIT 1) THEN 'has rows' ELSE 'EMPTY' END AS probe" \
    2>&1 | grep -E '"probe"' | head -1 || echo "(probe failed)"
done
echo
echo "[push-to-d1] page_stats snapshot:"
$WRANGLER d1 execute "$D1_DATABASE" --remote \
  --command="SELECT vuln_total, package_total, critical_total, kev_total, computed_at FROM page_stats WHERE id = 1" \
  2>&1 | grep -E '"(vuln_total|package_total|critical_total|kev_total|computed_at)"' || echo "  (page_stats missing — run stats-rebuild)"
```

- [ ] **Step 6: Verify the generated delta SQL ordering (LOCAL ONLY — no wrangler)**

```bash
# Reuse the Task-3 Step-2 fixture, extended with a sync_state row:
F=$(mktemp -d)/mini2.sqlite
sqlite3 "$F" "CREATE TABLE vulnerabilities (cve_id TEXT PRIMARY KEY, source_id TEXT, summary TEXT, description TEXT, published_at TEXT, modified_at TEXT, kev INTEGER, kev_added_at TEXT, epss_score REAL, epss_percentile REAL, epss_updated_at TEXT);
CREATE TABLE packages (id INTEGER PRIMARY KEY, ecosystem TEXT, name TEXT);
CREATE TABLE affected (id INTEGER PRIMARY KEY, cve_id TEXT, package_id INTEGER, ecosystem TEXT, ranges_json TEXT, versions_json TEXT, source_id TEXT);
CREATE TABLE cvss_scores (cve_id TEXT, version TEXT, vector TEXT, base_score REAL, severity TEXT, source TEXT);
CREATE TABLE vuln_aliases (cve_id TEXT, alias TEXT, source TEXT);
CREATE TABLE refs (cve_id TEXT, url TEXT, type TEXT);
CREATE TABLE sync_jobs (id INTEGER PRIMARY KEY, source TEXT NOT NULL, started_at TEXT NOT NULL DEFAULT (datetime('now')), finished_at TEXT, status TEXT NOT NULL DEFAULT 'running', records_seen INTEGER, records_changed INTEGER, error_message TEXT, last_heartbeat_at TEXT);
CREATE TABLE sync_state (source TEXT PRIMARY KEY, last_modified TEXT, updated_at TEXT);
INSERT INTO vulnerabilities (cve_id, kev) VALUES ('CVE-2026-42', 0);
INSERT INTO sync_state VALUES ('osv:npm', '2026-07-01T00:00:00Z', '2026-07-01T00:00:00Z');"

# Stub wrangler so the script's apply phase is a no-op (the script prefers
# node_modules/.bin/wrangler, so temporarily swap it; restore right after).
# DEBUG_KEEP_SQL (added in Step 3) preserves the generated SQL for inspection.
mv node_modules/.bin/wrangler node_modules/.bin/wrangler.real
printf '#!/bin/sh\nexit 0\n' > node_modules/.bin/wrangler && chmod +x node_modules/.bin/wrangler
DEBUG_KEEP_SQL=/tmp/delta-inspect.sql bash scripts/push-to-d1.sh "$F" fake-db delta
mv node_modules/.bin/wrangler.real node_modules/.bin/wrangler

# Ordering assertions:
grep -n "_delta_cves\|_stats_scratch\|INSERT INTO sync_state\|INSERT INTO vulns_fts" /tmp/delta-inspect.sql | head -20
# EXPECT: all _delta_cves/_stats_scratch line numbers are AFTER the last
# vulns_fts line and BEFORE the first sync_state line.
STATS_FIRST=$(grep -n "_delta_cves" /tmp/delta-inspect.sql | head -1 | cut -d: -f1)
SYNC_FIRST=$(grep -n "INSERT INTO sync_state" /tmp/delta-inspect.sql | head -1 | cut -d: -f1)
FTS_LAST=$(grep -n "packages_fts" /tmp/delta-inspect.sql | tail -1 | cut -d: -f1)
echo "fts_last=$FTS_LAST stats_first=$STATS_FIRST sync_first=$SYNC_FIRST"
[ "$FTS_LAST" -lt "$STATS_FIRST" ] && [ "$STATS_FIRST" -lt "$SYNC_FIRST" ] && echo "ORDER OK"
```

Expected: `ORDER OK`.

- [ ] **Step 7: Type-check, run suite, commit**

```bash
pnpm exec tsc --noEmit
pnpm test
git add scripts/emit-stats-sql.ts scripts/push-to-d1.sh
git commit -m "feat(stats): delta stats refresh in push pipeline + stats-rebuild mode + cheap verify probes"
```

---

### Task 4: request-path read-SQL module

**Files:**
- Create: `src/lib/stats-read-sql.ts`
- Create: `src/lib/stats-read-sql.test.ts`

**Interfaces:**
- Consumes: schema from `buildSchema` (tests only).
- Produces (all exported from `src/lib/stats-read-sql.ts`; NO `server-only` import — Task 5's call sites keep theirs):
  - `DASHBOARD_STATS_SQL` — 1 row always; columns `new_today, new_week, critical_total, kev_total, package_total, vuln_total` (zeros when `page_stats` is empty).
  - `VULN_TOTAL_SQL` — `vuln_total` or 0 rows when `page_stats` missing.
  - `TOP_PACKAGES_BY_ECO_SQL` — params `[ecosystem, limit]`; columns `ecosystem, name, cve_count, kev_count`.
  - `TOP_PACKAGES_ALL_SQL` — params `[limit]`; columns `ecosystem, name, cve_count, kev_count, max_epss`.
  - `ECOSYSTEM_DEEP_DIVE_SQL` — params `[ecosystem, limit]`; columns `name, cve_count, kev_count, max_epss`.
  - `PACKAGE_CVE_COUNT_SQL` — params `[package_id]`; column `cve_count`.
  - `SITEMAP_TOP_PACKAGES_SQL` — params `[limit]`; columns `ecosystem, name`.
  - `browsePackagesListSql(opts: { nameViaFts: boolean; hasName: boolean; hasEcosystem: boolean; sort: "cves" | "name" }): string` — params in textual order `[nameParam?, ecosystem?, pageSize, offset]`; columns `ecosystem, name, cve_count, kev_count`.

- [ ] **Step 1: Write the failing tests**

Create `src/lib/stats-read-sql.test.ts`:

```typescript
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
```

Also, in `src/lib/ingest/stats-sql.test.ts`, `seedFixture` is already exported (Task 1 defined it with `export function`). Confirm the export exists; if Task 1's implementer inlined it, extract it now exactly as written in Task 1 Step 1.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm vitest run src/lib/stats-read-sql.test.ts`
Expected: FAIL — `Cannot find module './stats-read-sql.js'`

- [ ] **Step 3: Write the implementation**

Create `src/lib/stats-read-sql.ts`:

```typescript
/**
 * Request-path SQL for the precomputed stats tables.
 *
 * Lives in its own module (WITHOUT the `server-only` guard queries.ts
 * carries) so vitest can execute every statement against a real SQLite
 * fixture — the SQL that runs in production is the SQL that is tested.
 *
 * Background: these replace COUNT(*) full scans and 119k-row GROUP BY
 * aggregations that overloaded D1 (2026-07-06). See
 * docs/superpowers/specs/2026-07-07-query-optimization-design.md.
 */

/**
 * Homepage dashboard. The four totals come from page_stats (written by
 * ingest); new_today/new_week stay live because they are cheap
 * idx_vuln_published range scans AND are relative to "now", which a
 * once-a-day precompute would misrepresent. The LEFT JOIN from a 1-row
 * inline table guarantees exactly one result row even when page_stats
 * is empty (pre-migration D1) — totals coalesce to 0.
 */
export const DASHBOARD_STATS_SQL = `
  SELECT
    (SELECT COUNT(*) FROM vulnerabilities WHERE published_at > datetime('now','-1 day'))  AS new_today,
    (SELECT COUNT(*) FROM vulnerabilities WHERE published_at > datetime('now','-7 days')) AS new_week,
    COALESCE(ps.critical_total, 0) AS critical_total,
    COALESCE(ps.kev_total, 0)      AS kev_total,
    COALESCE(ps.package_total, 0)  AS package_total,
    COALESCE(ps.vuln_total, 0)     AS vuln_total
  FROM (SELECT 1 AS one) dummy
  LEFT JOIN page_stats ps ON ps.id = 1
`;

/** Unfiltered search total. 0 rows ⇒ caller falls back to a live COUNT. */
export const VULN_TOTAL_SQL = `SELECT vuln_total FROM page_stats WHERE id = 1`;

/** Homepage per-ecosystem ranking. Params: [ecosystem, limit]. */
export const TOP_PACKAGES_BY_ECO_SQL = `
  SELECT ecosystem, name, cve_count, kev_count
    FROM package_stats
   WHERE ecosystem = ?
   ORDER BY kev_count DESC, cve_count DESC
   LIMIT ?
`;

/** /insights/most-vulnerable-packages. Params: [limit]. */
export const TOP_PACKAGES_ALL_SQL = `
  SELECT ecosystem, name, cve_count, kev_count, max_epss
    FROM package_stats
   ORDER BY kev_count DESC, cve_count DESC
   LIMIT ?
`;

/** /insights/ecosystem/[eco]. Params: [ecosystem, limit]. */
export const ECOSYSTEM_DEEP_DIVE_SQL = `
  SELECT name, cve_count, kev_count, max_epss
    FROM package_stats
   WHERE ecosystem = ?
   ORDER BY kev_count DESC, cve_count DESC
   LIMIT ?
`;

/** generateMetadata package CVE count. Params: [package_id]. */
export const PACKAGE_CVE_COUNT_SQL = `
  SELECT cve_count FROM package_stats WHERE package_id = ?
`;

/** Sitemap package URLs. Params: [limit]. */
export const SITEMAP_TOP_PACKAGES_SQL = `
  SELECT ecosystem, name
    FROM package_stats
   ORDER BY cve_count DESC
   LIMIT ?
`;

/**
 * /packages listing. Replaces the old 119k-row agg CTE with a LEFT JOIN
 * against package_stats (16k rows). Param order is textual:
 * [nameParam?, ecosystem?, pageSize, offset].
 */
export function browsePackagesListSql(opts: {
  /** name filter uses packages_fts MATCH (≥3 chars) vs plain LIKE */
  nameViaFts: boolean;
  hasName: boolean;
  hasEcosystem: boolean;
  sort: "cves" | "name";
}): string {
  const where: string[] = [];
  if (opts.hasName) {
    where.push(
      opts.nameViaFts
        ? `p.id IN (SELECT rowid FROM packages_fts WHERE packages_fts MATCH ?)`
        : `p.name LIKE ?`,
    );
  }
  if (opts.hasEcosystem) where.push(`p.ecosystem = ?`);
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const orderBy =
    opts.sort === "name"
      ? `p.ecosystem, p.name`
      : `kev_count DESC, cve_count DESC, p.name`;
  return `
    SELECT p.ecosystem, p.name,
           COALESCE(ps.cve_count, 0) AS cve_count,
           COALESCE(ps.kev_count, 0) AS kev_count
      FROM packages p
      LEFT JOIN package_stats ps ON ps.package_id = p.id
      ${whereSql}
     ORDER BY ${orderBy}
     LIMIT ? OFFSET ?
  `;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pnpm vitest run src/lib/stats-read-sql.test.ts`
Expected: PASS (all).

- [ ] **Step 5: Type-check and commit**

```bash
pnpm exec tsc --noEmit
git add src/lib/stats-read-sql.ts src/lib/stats-read-sql.test.ts
git commit -m "feat(stats): tested request-path read SQL for stats tables"
```

---

### Task 5: swap all call sites to stats reads

**Files:**
- Modify: `src/lib/queries.ts` (getDashboardStats ~519-536, searchVulns total ~253-257, _getTopPackages ~553-580, getPackageMetadata ~365-380, _browsePackages ~590-712)
- Modify: `src/lib/insights.ts` (_getTopPackagesAllEcos, _getEcosystemDeepDive)
- Modify: `src/app/sitemap.ts` (package query ~78-89)

**Interfaces:**
- Consumes: every export from Task 4's `src/lib/stats-read-sql.ts`.
- Produces: unchanged public signatures — `getDashboardStats(): Promise<DashboardStats>`, `getTopPackages(eco, limit)`, `getTopPackagesAllEcos(limit)`, `getEcosystemDeepDive(eco, limit)`, `browsePackages(f)`, `getPackageMetadata(eco, name)`, `searchVulns(f)`. Row shapes identical to today.

- [ ] **Step 1: getDashboardStats**

In `src/lib/queries.ts`, add the import near the top (after the `./osv` import):

```typescript
import {
  DASHBOARD_STATS_SQL,
  VULN_TOTAL_SQL,
  TOP_PACKAGES_BY_ECO_SQL,
  PACKAGE_CVE_COUNT_SQL,
  browsePackagesListSql,
} from "./stats-read-sql";
```

Replace the body of `getDashboardStats` (keep the 60s Map cache wrapper — Phase 2 replaces it):

```typescript
export async function getDashboardStats(): Promise<DashboardStats> {
  const now = Date.now();
  if (dashboardStatsCache && now - dashboardStatsCache.at < DASHBOARD_STATS_TTL_MS) {
    return dashboardStatsCache.value;
  }
  // Totals come from page_stats (precomputed at ingest — COUNT(*) over the
  // 74k-row table overloaded D1, 2026-07-06). new_today/new_week stay live:
  // cheap idx_vuln_published range scans, and inherently now-relative.
  const { rows } = await pool.query<DashboardStats>(DASHBOARD_STATS_SQL);
  const value = rows[0]; // LEFT JOIN from inline 1-row table ⇒ always 1 row
  dashboardStatsCache = { at: now, value };
  return value;
}
```

Also update the comment above `dashboardStatsCache` (lines ~509-515): replace the sentence about "six COUNT(*) subqueries … 20+ seconds" with:

```typescript
// 60s in-memory cache. The totals are precomputed in page_stats so the
// query is cheap, but the homepage calls this on every render — the cache
// still saves a D1 round-trip per view. Replaced by unstable_cache in the
// KV-cache task.
```

- [ ] **Step 2: searchVulns unfiltered total**

Replace the total computation (`const totalRes = await pool.query…; const total = …;` at ~253-257) with:

```typescript
  let total = 0;
  if (where.length === 0) {
    // Unfiltered browse: COUNT(*) over 74k rows is a D1 CPU-limit risk.
    // page_stats.vuln_total is refreshed by every ingest. Fall back to the
    // live count only when the stats row is missing (pre-migration D1).
    const t = await pool.query<{ vuln_total: number }>(VULN_TOTAL_SQL);
    if (t.rows.length > 0) {
      total = t.rows[0].vuln_total;
    } else {
      const totalRes = await pool.query<{ c: number }>(
        `SELECT COUNT(*) AS c ${baseFrom}`,
        params,
      );
      total = totalRes.rows[0]?.c ?? 0;
    }
  } else {
    const totalRes = await pool.query<{ c: number }>(
      `${pkgSearchCte} SELECT COUNT(*) AS c ${baseFrom}`,
      params,
    );
    total = totalRes.rows[0]?.c ?? 0;
  }
```

- [ ] **Step 3: _getTopPackages**

Replace the whole `_getTopPackages` function body:

```typescript
async function _getTopPackages(ecosystem: string, limit: number) {
  // Reads the ingest-precomputed package_stats ranking (idx_pkgstats_eco_rank).
  // The old shape aggregated 119k affected rows per call — ×6 on the homepage —
  // and the comment claimed an idx_affected_eco_pkg index that only ever
  // existed in the Postgres schema, so every call was a full scan on D1.
  const { rows } = await pool.query(TOP_PACKAGES_BY_ECO_SQL, [ecosystem, limit]);
  return rows as Array<{ ecosystem: string; name: string; cve_count: number; kev_count: number }>;
}
```

- [ ] **Step 4: getPackageMetadata**

Replace the `COUNT(*) FROM affected` query (~375-379) with:

```typescript
  const { rows: cntRows } = await pool.query<{ cve_count: number }>(
    PACKAGE_CVE_COUNT_SQL,
    [pkg.id],
  );
  return { package: pkg, cve_count: cntRows[0]?.cve_count ?? 0 };
```

- [ ] **Step 5: _browsePackages**

Replace everything in `_browsePackages` AFTER the `total` computation (from the `// Previously this query did …` comment through the final `return { items…, total }`) with:

```typescript
  // List page: LEFT JOIN the ingest-precomputed package_stats (16k rows)
  // instead of aggregating 119k affected rows per request. Packages without
  // a stats row (no affected CVEs yet) coalesce to 0 — same semantics as the
  // old LEFT JOIN aggregate.
  const listParams: unknown[] = [];
  if (q) {
    const nm = nameMatchClause();
    listParams.push(nm.param);
  }
  if (f.ecosystem) listParams.push(f.ecosystem);
  listParams.push(pageSize, offset);
  const { rows } = await pool.query(
    browsePackagesListSql({
      nameViaFts: useFts,
      hasName: Boolean(q),
      hasEcosystem: Boolean(f.ecosystem),
      sort: f.sort === "name" ? "name" : "cves",
    }),
    listParams,
  );
  return {
    items: rows as Array<{ ecosystem: string; name: string; cve_count: number; kev_count: number }>,
    total,
  };
```

(The packages-only `total` count query above stays — it only touches the 16k-row table.)

- [ ] **Step 6: insights.ts**

Add the import at the top:

```typescript
import { TOP_PACKAGES_ALL_SQL, ECOSYSTEM_DEEP_DIVE_SQL } from "./stats-read-sql";
```

Replace `_getTopPackagesAllEcos` body:

```typescript
async function _getTopPackagesAllEcos(limit: number): Promise<TopPackageRow[]> {
  // Ingest-precomputed ranking (package_stats, idx_pkgstats_rank). The old
  // query aggregated all 119k affected rows on every view.
  const { rows } = await pool.query(TOP_PACKAGES_ALL_SQL, [limit]);
  return rows as TopPackageRow[];
}
```

Replace `_getEcosystemDeepDive` body:

```typescript
async function _getEcosystemDeepDive(ecosystem: string, limit: number) {
  // Ingest-precomputed ranking (package_stats, idx_pkgstats_eco_rank).
  const { rows } = await pool.query(ECOSYSTEM_DEEP_DIVE_SQL, [ecosystem, limit]);
  return rows as { name: string; cve_count: number; kev_count: number; max_epss: number | null }[];
}
```

Also update the module docstring (lines 7-12): replace "All are cheap enough to run on each request …" with "All read the ingest-precomputed `package_stats` table — request-path aggregation over `affected` overloaded D1 (2026-07-06)."

- [ ] **Step 7: sitemap.ts**

Add the import:

```typescript
import { SITEMAP_TOP_PACKAGES_SQL } from "@/lib/stats-read-sql";
```

Replace the package query (the `WITH agg AS …` block, ~78-89) with:

```typescript
    const { rows: pkgs } = await pool.query<{ ecosystem: string; name: string }>(
      SITEMAP_TOP_PACKAGES_SQL,
      [5000],
    );
```

- [ ] **Step 8: Type-check, full suite, commit**

```bash
pnpm exec tsc --noEmit
pnpm test
git add src/lib/queries.ts src/lib/insights.ts src/app/sitemap.ts
git commit -m "feat(stats): request path reads precomputed stats — no more full-table aggregation on D1"
```

---

### Task 6: Phase 2 — KV incremental cache + Map retirement + sitemap header

**Files:**
- Modify: `open-next.config.ts`
- Modify: `wrangler.jsonc`
- Modify: `src/lib/queries.ts` (retire both hand-rolled Maps)
- Modify: `next.config.ts` (sitemap Cache-Control)

**Interfaces:**
- Consumes: `unstable_cache` (already imported in queries.ts).
- Produces: working cross-isolate caching. Public signatures unchanged.

- [ ] **Step 1: Create the KV namespace**

The binding name is fixed by @opennextjs/cloudflare: `NEXT_INC_CACHE_KV` (verified: `node_modules/@opennextjs/cloudflare/dist/api/overrides/incremental-cache/kv-incremental-cache.d.ts` exports `BINDING_NAME = "NEXT_INC_CACHE_KV"`).

```bash
pnpm exec wrangler kv namespace create NEXT_INC_CACHE_KV
```

Copy the printed namespace `id`. This touches KV only — NOT D1. If the command fails (auth), report BLOCKED; do not guess an id.

- [ ] **Step 2: Bind it in wrangler.jsonc**

Add after the `d1_databases` array (inside the top-level object):

```jsonc
  "kv_namespaces": [
    {
      // @opennextjs/cloudflare incremental cache — makes unstable_cache a
      // real cross-isolate cache (per-isolate memory was effectively always
      // cold on Workers, exposing every heavy query to every request).
      "binding": "NEXT_INC_CACHE_KV",
      "id": "<the id from Step 1>"
    }
  ]
```

- [ ] **Step 3: Enable the incremental cache override**

Replace `open-next.config.ts` entirely:

```typescript
import { defineCloudflareConfig } from "@opennextjs/cloudflare";
import kvIncrementalCache from "@opennextjs/cloudflare/overrides/incremental-cache/kv-incremental-cache";

export default defineCloudflareConfig({
  incrementalCache: kvIncrementalCache,
});
```

- [ ] **Step 4: Retire the hand-rolled Maps in queries.ts**

(a) `getDashboardStats`: delete `dashboardStatsCache`, `DASHBOARD_STATS_TTL_MS`, and the comment block above them; replace the function with:

```typescript
async function _getDashboardStats(): Promise<DashboardStats> {
  // Totals from page_stats (precomputed at ingest); live windows are cheap
  // idx_vuln_published range scans. Cached via unstable_cache (KV-backed on
  // Workers — see open-next.config.ts), shared across isolates.
  const { rows } = await pool.query<DashboardStats>(DASHBOARD_STATS_SQL);
  return rows[0];
}
export const getDashboardStats = unstable_cache(
  _getDashboardStats,
  ["getDashboardStats"],
  { revalidate: SSR_CACHE_TTL_SEC },
);
```

(b) `getPackageWithCves`: delete `PACKAGE_BUNDLE_CACHE`, `PACKAGE_BUNDLE_TTL_MS`, `PACKAGE_BUNDLE_MAX_ENTRIES`, `bundleCacheKey`, `bundleCacheGet`, `bundleCacheSet`, and the long cache-justification comment. Rename the existing function to `_getPackageWithCves`, remove the three cache lines inside it (`const cacheKey…`, `const cached…`, `if (cached !== undefined) return cached;`, plus both `bundleCacheSet(...)` calls — return `null` / `bundle` directly), and add:

```typescript
/**
 * 60s KV-backed cache: /package/[eco]/[name] is force-dynamic and popular
 * packages (Debian/chromium, Maven/log4j-core …) carry 100-800 chunky CVE
 * rows. Key includes the limit so a 100-row render and an unlimited
 * "show all" fetch don't collide.
 */
export const getPackageWithCves = (
  ecosystem: string,
  name: string,
  limit?: number,
): Promise<PackageBundle | null> =>
  unstable_cache(
    _getPackageWithCves,
    ["getPackageWithCves", ecosystem, name, String(limit ?? "all")],
    { revalidate: SSR_CACHE_TTL_SEC },
  )(ecosystem, name, limit);
```

- [ ] **Step 5: Sitemap Cache-Control**

In `next.config.ts`, inside the `headers()` array, add one entry (sitemap changes at most daily; 1h edge cache stops crawlers re-running the 20k-row query):

```typescript
      {
        source: "/sitemap.xml",
        headers: [
          { key: "Cache-Control", value: "public, s-maxage=3600, stale-while-revalidate=86400" },
        ],
      },
```

- [ ] **Step 6: Verify build + tests**

```bash
pnpm exec tsc --noEmit
pnpm test
pnpm build      # next build must succeed (no DB access at build time)
```

Expected: all green. `pnpm build` proves the unstable_cache wrappers don't break the RSC build.

- [ ] **Step 7: Commit**

```bash
git add open-next.config.ts wrangler.jsonc src/lib/queries.ts next.config.ts
git commit -m "feat(cache): KV-backed unstable_cache on Workers; retire per-isolate Maps; sitemap edge cache"
```

---

### Task 7: docs + rollout runbook + final green

**Files:**
- Modify: `docs/incremental-ingest.md`
- Modify: `docs/d1-recovery-and-verify.md`

- [ ] **Step 1: Document the stats refresh in the ingest docs**

In `docs/incremental-ingest.md`, add a section:

```markdown
## Stats refresh (page_stats / package_stats)

Every delta push appends a stats-refresh block (generated by
`scripts/emit-stats-sql.ts delta`) after the data/FTS statements and before
the sync_state watermarks:

- `package_stats` is recomputed ONLY for packages touched by the delta's
  CVEs (scratch-table driven, index-only work).
- `page_stats` totals are recounted in bounded chunks (CVE-year ranges,
  package-id ranges) — never a whole-table COUNT on D1.

One-time backfill / disaster recovery:

    bash scripts/push-to-d1.sh vulnscope stats-rebuild

creates the tables (IF NOT EXISTS) and rebuilds both from scratch in
bounded shards. Safe to re-run; touches no other tables.
```

- [ ] **Step 2: Update the recovery runbook's rollout section**

In `docs/d1-recovery-and-verify.md`, replace the "Step 3/Step 4" CI-verification steps' preamble with a note that the query-optimization work must roll out FIRST, and append:

```markdown
## 查詢優化上線步驟(D1 恢復後,依序)

1. **確認 D1 穩定**(Step 2 的輕量查詢連續 3 次通過)。
2. **建立 stats 表並回填**(增量遷移,不動其他表、不重灌):
   `bash scripts/push-to-d1.sh vulnscope stats-rebuild`
   —— 全部是分片小語句;失敗可安全重跑。
3. **部署新查詢層**:`pnpm deploy`
   (含 KV incremental cache;需先確認 wrangler.jsonc 的 NEXT_INC_CACHE_KV id 已填。)
4. **驗證**:首頁/zh 首頁秒開;`SELECT * FROM page_stats WHERE id=1` 單列有值;
   `/packages`、`/insights/*` 正常。
5. **之後**再跑增量 CI 驗證(原 Step 3/4)—— 每日 delta 會自動帶 stats 刷新。
6. **檢查 Cloudflare Cache Rule**:next.config 的 s-maxage header 需搭配
   docs/edge-caching.md 的 Cache Rule 才會在邊緣生效 —— Dashboard → Caching →
   Cache Rules 確認存在;沒有就照該文件補上。
```

- [ ] **Step 3: Final green + commit**

```bash
pnpm exec tsc --noEmit
pnpm test
git add docs/incremental-ingest.md docs/d1-recovery-and-verify.md
git commit -m "docs: stats refresh + rollout runbook for query optimization"
```

---

## Rollout (manual, human-executed — NOT part of any task)

After D1 recovers (per `docs/d1-recovery-and-verify.md`): `stats-rebuild` → `pnpm deploy` → verify → resume incremental CI verification. No task in this plan touches remote D1.
