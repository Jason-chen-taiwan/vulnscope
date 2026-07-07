import type Database from "better-sqlite3";

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
