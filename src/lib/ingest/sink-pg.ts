/**
 * Postgres implementation of IngestSink.
 *
 * This is the production write-path — the exact drizzle `INSERT ...
 * ON CONFLICT` statements that lived inline in osv-batch.ts before the
 * sink abstraction was introduced. Moving them here changes NOTHING
 * about the SQL emitted; osv-batch.ts now calls these via the interface
 * so the SQLite target can slot in a sibling implementation.
 */
import { sql } from "drizzle-orm";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import type { Pool } from "pg";

import {
  vulnerabilities,
  cvssScores,
  packages,
  affected,
  refs,
  vulnAliases,
} from "@/db/schema";
import * as schema from "@/db/schema";
import { normalizePypiName } from "@/lib/osv";
import type {
  IngestSink,
  VulnRow,
  CvssRow,
  AffectedRow,
  RefRow,
  AliasRow,
} from "./sink";

export type IngestDb = NodePgDatabase<typeof schema>;
export type IngestPool = Pool;

// rows per single INSERT statement (per child table). Lowered from
// 1000 → 500 after osv:npm hit statement_timeout in production: the
// vulnerabilities table now carries GIN+trgm indexes whose maintenance
// cost scales superlinearly with batch size on Fly shared CPU.
const FLUSH_INSERT_BATCH = 500;

export class PgIngestSink implements IngestSink {
  constructor(
    private readonly db: IngestDb,
    private readonly pool: IngestPool,
  ) {}

  async getOrCreatePackageId(eco: string, name: string): Promise<number> {
    // name is already normalized by the caller (osv-batch), but the pg
    // path historically normalized PyPI here too; keep it idempotent.
    const normName = eco === "PyPI" ? normalizePypiName(name) : name;
    const inserted = await this.db
      .insert(packages)
      .values({ ecosystem: eco, name: normName })
      .onConflictDoNothing({ target: [packages.ecosystem, packages.name] })
      .returning({ id: packages.id });
    if (inserted.length > 0) return inserted[0].id;
    const { rows } = await this.pool.query(
      "SELECT id FROM packages WHERE ecosystem=$1 AND name=$2",
      [eco, normName],
    );
    return rows[0].id as number;
  }

  async flushVulns(rows: VulnRow[]): Promise<void> {
    for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
      const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
      await this.db
        .insert(vulnerabilities)
        .values(slice)
        .onConflictDoUpdate({
          target: vulnerabilities.cveId,
          set: {
            sourceId: sql`EXCLUDED.source_id`,
            summary: sql`COALESCE(EXCLUDED.summary, ${vulnerabilities.summary})`,
            description: sql`COALESCE(EXCLUDED.description, ${vulnerabilities.description})`,
            publishedAt: sql`COALESCE(${vulnerabilities.publishedAt}, EXCLUDED.published_at)`,
            modifiedAt: sql`COALESCE(EXCLUDED.modified_at, ${vulnerabilities.modifiedAt})`,
          },
        });
    }
  }

  async flushCvss(rows: CvssRow[]): Promise<void> {
    for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
      const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
      await this.db
        .insert(cvssScores)
        .values(slice.map((r) => ({ ...r, source: "osv" })))
        .onConflictDoNothing({
          target: [cvssScores.cveId, cvssScores.version, cvssScores.source],
        });
    }
  }

  async flushAffected(rows: AffectedRow[]): Promise<void> {
    for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
      const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
      await this.db
        .insert(affected)
        .values(slice)
        .onConflictDoNothing({
          target: [affected.cveId, affected.packageId, affected.sourceId],
        });
    }
  }

  async flushRefs(rows: RefRow[]): Promise<void> {
    for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
      const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
      await this.db
        .insert(refs)
        .values(slice)
        .onConflictDoNothing({ target: [refs.cveId, refs.url] });
    }
  }

  async flushAliases(rows: AliasRow[]): Promise<void> {
    for (let i = 0; i < rows.length; i += FLUSH_INSERT_BATCH) {
      const slice = rows.slice(i, i + FLUSH_INSERT_BATCH);
      // The table has TWO unique constraints: (cveId, alias) PK +
      // (alias) UNIQUE. Conflict target is `alias` because the alias-only
      // collision is the broader one.
      await this.db
        .insert(vulnAliases)
        .values(slice)
        .onConflictDoNothing({ target: [vulnAliases.alias] });
    }
  }
}
