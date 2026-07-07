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
