import DatabaseCtor from "better-sqlite3";
import type Database from "better-sqlite3";
import { fetch } from "undici";
import { createWriteStream, promises as fs } from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { streamOsvZip, type UpsertCtx } from "../src/lib/ingest/osv-batch";
import { SqliteIngestSink } from "../src/lib/ingest/sink-sqlite";
import { streamEpss } from "../src/lib/ingest/epss-core";
import { fetchKev, parseKevDate } from "../src/lib/ingest/kev-core";

/**
 * Creates the full VulnScope schema in the given better-sqlite3 Database.
 *
 * Reproduces the exact DDL from scripts/phase0-pg-to-sqlite.sh:
 *   - 6 base tables
 *   - 10 plain indexes
 *   - 2 FTS5 virtual tables (porter unicode61 for vulns, trigram for packages)
 *
 * FTS5 tables are created empty; population happens in Task 2.2 after data
 * load.  The function is safe to call on a fresh :memory: database.
 */
export function buildSchema(db: Database.Database): void {
  db.exec(`
    -- ── Base tables ────────────────────────────────────────────────────────
    CREATE TABLE vulnerabilities (
      cve_id TEXT PRIMARY KEY, source_id TEXT, summary TEXT, description TEXT,
      published_at TEXT, modified_at TEXT, kev INTEGER, kev_added_at TEXT,
      epss_score REAL, epss_percentile REAL, epss_updated_at TEXT
    );

    CREATE TABLE packages (id INTEGER PRIMARY KEY, ecosystem TEXT, name TEXT);

    CREATE TABLE affected (
      id INTEGER PRIMARY KEY, cve_id TEXT, package_id INTEGER, ecosystem TEXT,
      ranges_json TEXT, versions_json TEXT, source_id TEXT
    );

    CREATE TABLE cvss_scores (
      cve_id TEXT, version TEXT, vector TEXT, base_score REAL, severity TEXT, source TEXT
    );

    CREATE TABLE vuln_aliases (cve_id TEXT, alias TEXT, source TEXT);

    CREATE TABLE refs (cve_id TEXT, url TEXT, type TEXT);

    -- Ingest bookkeeping. Mirrors the Postgres sync_jobs table (src/db/schema.ts):
    -- timestamps as TEXT (ISO8601), counts as INTEGER. Read on the homepage
    -- (getFreshness / isIngestRunning) so it must exist in the D1 schema or
    -- those reads throw "no such table: sync_jobs" and 500 the homepage.
    CREATE TABLE sync_jobs (
      id INTEGER PRIMARY KEY,
      source TEXT NOT NULL,
      started_at TEXT NOT NULL DEFAULT (datetime('now')),
      finished_at TEXT,
      status TEXT NOT NULL DEFAULT 'running',
      records_seen INTEGER,
      records_changed INTEGER,
      error_message TEXT,
      last_heartbeat_at TEXT
    );

    -- ── Indexes ─────────────────────────────────────────────────────────────
    CREATE INDEX idx_affected_cve ON affected(cve_id);
    CREATE INDEX idx_affected_pkg ON affected(package_id);
    CREATE INDEX idx_cvss_cve ON cvss_scores(cve_id);
    CREATE INDEX idx_aliases_cve ON vuln_aliases(cve_id);
    CREATE INDEX idx_aliases_alias ON vuln_aliases(alias);
    CREATE INDEX idx_refs_cve ON refs(cve_id);
    CREATE INDEX idx_pkg_eco_name ON packages(ecosystem, name);
    CREATE INDEX idx_vuln_kev ON vulnerabilities(kev);
    CREATE INDEX idx_vuln_published ON vulnerabilities(published_at);
    CREATE INDEX idx_vuln_epss ON vulnerabilities(epss_score);
    CREATE INDEX idx_sync_jobs_source_started ON sync_jobs(source, started_at);
    CREATE INDEX idx_sync_jobs_started ON sync_jobs(started_at);

    -- ── FTS5 virtual tables (populated in Task 2.2) ─────────────────────────
    CREATE VIRTUAL TABLE vulns_fts USING fts5(
      cve_id, summary, description, tokenize='porter unicode61'
    );

    CREATE VIRTUAL TABLE packages_fts USING fts5(
      name, tokenize='trigram'
    );
  `);
}

// ─── SQLite build entry point (Task 2.2) ─────────────────────────────────────
//
// Builds a fresh vulnscope.sqlite from live OSV/KEV/EPSS feeds using the
// SqliteIngestSink. The READ/TRANSFORM half (zip streaming, EPSS/KEV parse)
// is the exact shared code the Postgres ingest uses — only the sink differs.
//
// Bounded runs: set INGEST_ECOSYSTEMS (comma-separated) to limit which OSV
// ecosystems are fetched. Defaults to the full production list. For a fast
// smoke test:  INGEST_ECOSYSTEMS=Hex pnpm build:sqlite

export const OSV_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com";

export const DEFAULT_ECOSYSTEMS = [
  "npm", "PyPI", "Maven", "Go", "RubyGems", "Packagist", "crates.io",
  "NuGet", "Hex", "Hackage", "Debian", "Alpine", "Bitnami",
];

export function canonicalizeEco(input: string): string {
  return input.split(":")[0];
}

export function classifyAlias(alias: string): string {
  const a = alias.toUpperCase();
  if (a.startsWith("GHSA-")) return "ghsa";
  if (a.startsWith("DSA-")) return "dsa";
  if (a.startsWith("DLA-")) return "dla";
  if (a.startsWith("DEBIAN-")) return "debian";
  if (a.startsWith("ALPINE-")) return "alpine";
  if (a.startsWith("RHSA-")) return "rhsa";
  if (a.startsWith("USN-")) return "usn";
  if (a.startsWith("GLSA-")) return "glsa";
  if (a.startsWith("SUSE-")) return "suse";
  if (a.startsWith("PYSEC-")) return "pysec";
  if (a.startsWith("RUSTSEC-")) return "rustsec";
  if (a.startsWith("GO-")) return "goadvisory";
  if (a.startsWith("OSV-")) return "osv-id";
  return "other";
}

async function downloadZipToFile(url: string, dest: string): Promise<void> {
  console.log(`[osv] downloading ${url}`);
  const res = await fetch(url);
  if (!res.ok || !res.body) throw new Error(`OSV fetch failed: ${res.status}`);
  await pipeline(Readable.fromWeb(res.body as never), createWriteStream(dest));
}

async function ingestOsvEcosystem(sink: SqliteIngestSink, ecoArg: string) {
  const eco = canonicalizeEco(ecoArg);
  const url = `${OSV_BASE_URL}/${encodeURIComponent(ecoArg)}/all.zip`;
  const work = await fs.mkdtemp(join(tmpdir(), "osv-sqlite-"));
  const zipPath = join(work, "all.zip");
  try {
    await downloadZipToFile(url, zipPath);
    const ctx: UpsertCtx = {
      eco,
      ecoMatch: (recordEco) => canonicalizeEco(recordEco) === eco,
      pkgCache: new Map(),
    };
    const { processed, imported } = await streamOsvZip({
      ctx,
      zipPath,
      sink,
      classifyAlias,
      log: (msg) => console.log(msg),
      onChunk({ processed: p, imported: i, chunkIndex }) {
        if (chunkIndex % 10 === 0) {
          process.stdout.write(`\r[osv:${eco}] chunk=${chunkIndex} processed=${p} imported=${i}    `);
        }
      },
    });
    console.log(`\n[osv:${eco}] processed=${processed} imported=${imported}`);
  } finally {
    await fs.rm(work, { recursive: true, force: true }).catch(() => {});
  }
}

export async function ingestKev(db: Database.Database) {
  console.log("[kev] fetching CISA KEV catalog");
  const payload = await fetchKev();
  // Upsert onto vulnerabilities: flip kev=1 and fill kev_added_at /
  // summary / description (COALESCE — don't clobber richer OSV text).
  const upsert = db.prepare(
    `INSERT INTO vulnerabilities
       (cve_id, source_id, summary, description, kev, kev_added_at)
     VALUES (@cveId, @sourceId, @summary, @description, 1, @kevAddedAt)
     ON CONFLICT (cve_id) DO UPDATE SET
       kev          = 1,
       kev_added_at = COALESCE(vulnerabilities.kev_added_at, excluded.kev_added_at),
       summary      = COALESCE(vulnerabilities.summary, excluded.summary),
       description  = COALESCE(vulnerabilities.description, excluded.description)`,
  );
  const run = db.transaction((entries: typeof payload.vulnerabilities) => {
    for (const e of entries) {
      const addedAt = parseKevDate(e.dateAdded);
      upsert.run({
        cveId: e.cveID,
        sourceId: `kev:${payload.catalogVersion}`,
        summary: e.vulnerabilityName,
        description: e.shortDescription,
        kevAddedAt: addedAt ? addedAt.toISOString() : null,
      });
    }
  });
  run(payload.vulnerabilities);
  console.log(`[kev] catalogVersion=${payload.catalogVersion} upserted=${payload.vulnerabilities.length}`);
}

export async function ingestEpss(db: Database.Database) {
  console.log("[epss] fetching EPSS scores");
  const update = db.prepare(
    `UPDATE vulnerabilities
        SET epss_score = ?, epss_percentile = ?, epss_updated_at = ?
      WHERE cve_id = ?`,
  );
  const result = await streamEpss({
    writeBatch: (rows, scoreDate) => {
      let changed = 0;
      const run = db.transaction(() => {
        for (const [cve, score, pct] of rows) {
          const r = update.run(Number(score), Number(pct), scoreDate, cve);
          changed += r.changes;
        }
      });
      run();
      return changed;
    },
  });
  console.log(`[epss] seen=${result.seen} updated=${result.changed} score_date=${result.scoreDate}`);
}

function buildFts(db: Database.Database) {
  console.log("[fts] building FTS5 indexes");
  db.exec(`
    INSERT INTO vulns_fts(cve_id, summary, description)
      SELECT cve_id, summary, description FROM vulnerabilities;
    INSERT INTO packages_fts(rowid, name)
      SELECT id, name FROM packages;
  `);
}

async function main() {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const outPath =
    process.env.SQLITE_OUT ??
    resolve(__dirname, "../scratch-phase0/vulnscope.sqlite");
  await fs.mkdir(dirname(outPath), { recursive: true });
  // Fresh build every time — the file is a disposable artifact pushed to D1.
  await fs.rm(outPath, { force: true }).catch(() => {});

  const ecosystems = (process.env.INGEST_ECOSYSTEMS
    ? process.env.INGEST_ECOSYSTEMS.split(",").map((s) => s.trim()).filter(Boolean)
    : DEFAULT_ECOSYSTEMS);

  console.log(`[build-sqlite] out=${outPath}`);
  console.log(`[build-sqlite] ecosystems=${ecosystems.join(",")}`);

  const db = new DatabaseCtor(outPath);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  buildSchema(db);

  const sink = new SqliteIngestSink(db);

  // OSV first so KEV/EPSS have vulnerability rows to attach to.
  for (const eco of ecosystems) {
    try {
      await ingestOsvEcosystem(sink, eco);
    } catch (err) {
      console.error(`[osv:${eco}] FAILED:`, err);
    }
  }

  try {
    await ingestKev(db);
  } catch (err) {
    console.error("[kev] FAILED:", err);
  }
  try {
    await ingestEpss(db);
  } catch (err) {
    console.error("[epss] FAILED:", err);
  }

  buildFts(db);

  const counts = db
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM vulnerabilities) AS vulns,
         (SELECT COUNT(*) FROM packages)        AS pkgs,
         (SELECT COUNT(*) FROM affected)        AS aff,
         (SELECT COUNT(*) FROM cvss_scores)     AS cvss,
         (SELECT COUNT(*) FROM refs)            AS refs,
         (SELECT COUNT(*) FROM vuln_aliases)    AS aliases,
         (SELECT COUNT(*) FROM vulns_fts)       AS vulns_fts,
         (SELECT COUNT(*) FROM packages_fts)    AS packages_fts`,
    )
    .get();
  console.log(`[build-sqlite] done: ${JSON.stringify(counts)}`);
  db.close();
}

// Run only when invoked as a script (not when imported by tests).
const isMain =
  typeof process !== "undefined" &&
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
