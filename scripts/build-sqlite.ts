import type Database from "better-sqlite3";

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

    -- ── FTS5 virtual tables (populated in Task 2.2) ─────────────────────────
    CREATE VIRTUAL TABLE vulns_fts USING fts5(
      cve_id, summary, description, tokenize='porter unicode61'
    );

    CREATE VIRTUAL TABLE packages_fts USING fts5(
      name, tokenize='trigram'
    );
  `);
}
