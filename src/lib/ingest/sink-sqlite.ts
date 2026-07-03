/**
 * better-sqlite3 implementation of IngestSink.
 *
 * Targets the schema built by scripts/build-sqlite.ts::buildSchema. The
 * READ/TRANSFORM half of the ingest (osv-batch.ts::bufferRecord) is
 * reused verbatim; only these writes differ from the Postgres path.
 *
 * Type mapping vs. Postgres:
 *   - timestamptz  → TEXT (ISO-8601 via Date.toISOString()).
 *   - numeric      → REAL (base_score / epss) or stored as-is TEXT->REAL.
 *   - jsonb        → TEXT (JSON.stringify).
 *   - serial id    → INTEGER PRIMARY KEY (rowid alias, autoincrementing).
 *   - boolean kev  → INTEGER 0/1.
 *
 * Every statement is a prepared `INSERT ... ON CONFLICT DO UPDATE/NOTHING`
 * matching the pg sink's conflict targets exactly. Batches are wrapped in
 * better-sqlite3 transactions so a whole flush commits atomically and
 * fast (no per-row fsync).
 */
import type Database from "better-sqlite3";

import { normalizePypiName } from "@/lib/osv";
import type {
  IngestSink,
  VulnRow,
  CvssRow,
  AffectedRow,
  RefRow,
  AliasRow,
} from "./sink";

function isoOrNull(d: Date | null): string | null {
  return d ? d.toISOString() : null;
}

export class SqliteIngestSink implements IngestSink {
  private readonly insertPkg: Database.Statement;
  private readonly selectPkg: Database.Statement;
  private readonly upsertVuln: Database.Statement;
  private readonly insertCvss: Database.Statement;
  private readonly insertAffected: Database.Statement;
  private readonly insertRef: Database.Statement;
  private readonly insertAlias: Database.Statement;

  private readonly runVulns: (rows: VulnRow[]) => void;
  private readonly runCvss: (rows: CvssRow[]) => void;
  private readonly runAffected: (rows: AffectedRow[]) => void;
  private readonly runRefs: (rows: RefRow[]) => void;
  private readonly runAliases: (rows: AliasRow[]) => void;

  constructor(private readonly db: Database.Database) {
    // packages: get-or-create. The Task-2.1 schema declares
    // idx_pkg_eco_name as a PLAIN (non-UNIQUE) index, so ON CONFLICT
    // has no constraint to target. Guard the insert with NOT EXISTS
    // instead — the build runs single-threaded so there's no race.
    this.insertPkg = db.prepare(
      `INSERT INTO packages (ecosystem, name)
       SELECT ?, ?
       WHERE NOT EXISTS (
         SELECT 1 FROM packages WHERE ecosystem = ? AND name = ?
       )`,
    );
    this.selectPkg = db.prepare(
      `SELECT id FROM packages WHERE ecosystem = ? AND name = ?`,
    );

    // vulnerabilities: ON CONFLICT (cve_id) DO UPDATE, preserving the
    // exact COALESCE precedence the Postgres path documents.
    this.upsertVuln = db.prepare(
      `INSERT INTO vulnerabilities
         (cve_id, source_id, summary, description, published_at, modified_at)
       VALUES (@cveId, @sourceId, @summary, @description, @publishedAt, @modifiedAt)
       ON CONFLICT (cve_id) DO UPDATE SET
         source_id    = excluded.source_id,
         summary      = COALESCE(excluded.summary, vulnerabilities.summary),
         description  = COALESCE(excluded.description, vulnerabilities.description),
         published_at = COALESCE(vulnerabilities.published_at, excluded.published_at),
         modified_at  = COALESCE(excluded.modified_at, vulnerabilities.modified_at)`,
    );

    // cvss: (cve_id, version, source) has no UNIQUE index in the SQLite
    // schema, so ON CONFLICT can't reference it. The core already dedupes
    // per-buffer on (cveId|version|osv); cross-chunk dups are rare and
    // harmless in a fresh build (we start from an empty file). Guard with
    // a NOT EXISTS to preserve DO-NOTHING semantics without needing an index.
    this.insertCvss = db.prepare(
      `INSERT INTO cvss_scores (cve_id, version, vector, base_score, severity, source)
       SELECT @cveId, @version, @vector, @baseScore, @severity, 'osv'
       WHERE NOT EXISTS (
         SELECT 1 FROM cvss_scores
         WHERE cve_id = @cveId AND version = @version AND source = 'osv'
       )`,
    );

    // affected: same story — no UNIQUE index on (cve_id, package_id,
    // source_id) in the SQLite schema; guard with NOT EXISTS.
    this.insertAffected = db.prepare(
      `INSERT INTO affected (cve_id, package_id, ecosystem, ranges_json, versions_json, source_id)
       SELECT @cveId, @packageId, @ecosystem, @rangesJson, @versionsJson, @sourceId
       WHERE NOT EXISTS (
         SELECT 1 FROM affected
         WHERE cve_id = @cveId AND package_id = @packageId AND source_id = @sourceId
       )`,
    );

    // refs: no UNIQUE index on (cve_id, url); guard with NOT EXISTS.
    this.insertRef = db.prepare(
      `INSERT INTO refs (cve_id, url, type)
       SELECT @cveId, @url, @type
       WHERE NOT EXISTS (
         SELECT 1 FROM refs WHERE cve_id = @cveId AND url = @url
       )`,
    );

    // aliases: dedupe on alias alone (matches the pg UNIQUE(alias)).
    this.insertAlias = db.prepare(
      `INSERT INTO vuln_aliases (cve_id, alias, source)
       SELECT @cveId, @alias, @source
       WHERE NOT EXISTS (
         SELECT 1 FROM vuln_aliases WHERE alias = @alias
       )`,
    );

    // Batch transactions: one COMMIT per flush call, per table.
    this.runVulns = db.transaction((rows: VulnRow[]) => {
      for (const r of rows) {
        this.upsertVuln.run({
          cveId: r.cveId,
          sourceId: r.sourceId,
          summary: r.summary,
          description: r.description,
          publishedAt: isoOrNull(r.publishedAt),
          modifiedAt: isoOrNull(r.modifiedAt),
        });
      }
    });
    this.runCvss = db.transaction((rows: CvssRow[]) => {
      for (const r of rows) {
        this.insertCvss.run({
          cveId: r.cveId,
          version: r.version,
          vector: r.vector,
          baseScore: r.baseScore !== null ? Number(r.baseScore) : null,
          severity: r.severity,
        });
      }
    });
    this.runAffected = db.transaction((rows: AffectedRow[]) => {
      for (const r of rows) {
        this.insertAffected.run({
          cveId: r.cveId,
          packageId: r.packageId,
          ecosystem: r.ecosystem,
          rangesJson: JSON.stringify(r.rangesJson ?? []),
          versionsJson:
            r.versionsJson != null ? JSON.stringify(r.versionsJson) : null,
          sourceId: r.sourceId,
        });
      }
    });
    this.runRefs = db.transaction((rows: RefRow[]) => {
      for (const r of rows) {
        this.insertRef.run({ cveId: r.cveId, url: r.url, type: r.type });
      }
    });
    this.runAliases = db.transaction((rows: AliasRow[]) => {
      for (const r of rows) {
        this.insertAlias.run({
          cveId: r.cveId,
          alias: r.alias,
          source: r.source,
        });
      }
    });
  }

  async getOrCreatePackageId(eco: string, name: string): Promise<number> {
    const normName = eco === "PyPI" ? normalizePypiName(name) : name;
    this.insertPkg.run(eco, normName, eco, normName);
    const row = this.selectPkg.get(eco, normName) as { id: number };
    return row.id;
  }

  async flushVulns(rows: VulnRow[]): Promise<void> {
    this.runVulns(rows);
  }
  async flushCvss(rows: CvssRow[]): Promise<void> {
    this.runCvss(rows);
  }
  async flushAffected(rows: AffectedRow[]): Promise<void> {
    this.runAffected(rows);
  }
  async flushRefs(rows: RefRow[]): Promise<void> {
    this.runRefs(rows);
  }
  async flushAliases(rows: AliasRow[]): Promise<void> {
    this.runAliases(rows);
  }
}
