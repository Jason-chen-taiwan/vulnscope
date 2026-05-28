/**
 * EPSS daily ingest.
 *
 * Source: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
 *   (redirects to .../epss_scores-YYYY-MM-DD.csv.gz)
 *
 * Format (CSV, gzipped):
 *   #model_version:v2025...,score_date:2026-05-27T00:00:00+0000
 *   cve,epss,percentile
 *   CVE-1999-0001,0.00321,0.42305
 *   ...
 *
 * Strategy: pull, gunzip, batch UPDATE only the CVEs we already have in
 * vulnerabilities — no need to insert stubs (we'll never look up a CVE that
 * isn't in any OSV record). Batch size 1000 to keep round-trips down.
 */
import "./_shared";
import { fetch } from "undici";
import { createGunzip } from "node:zlib";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createInterface } from "node:readline";
import { pool } from "../../src/db/client";

const URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

async function main() {
  console.log(`[epss] fetching ${URL}`);
  const res = await fetch(URL, { redirect: "follow" });
  if (!res.ok || !res.body) throw new Error(`EPSS fetch failed: ${res.status}`);

  const gunzip = createGunzip();
  const sourceStream = Readable.fromWeb(res.body as never);
  // Run pipeline in parallel; we read from gunzip via readline below.
  const pipePromise = pipeline(sourceStream, gunzip).catch((e) => {
    console.error("[epss] gunzip error:", e);
  });

  const rl = createInterface({ input: gunzip, crlfDelay: Infinity });
  const BATCH = 1000;
  let header: string[] | null = null;
  let batch: [string, string, string][] = [];
  let processed = 0;
  let updated = 0;
  let scoreDate: string | null = null;

  async function flush() {
    if (batch.length === 0) return;
    // VALUES (cve, score, pct), (cve, score, pct), ...
    const valuesSql: string[] = [];
    const params: unknown[] = [];
    let p = 0;
    for (const [c, s, pct] of batch) {
      params.push(c, s, pct);
      valuesSql.push(`($${++p}::text, $${++p}::numeric, $${++p}::numeric)`);
    }
    const sql = `
      UPDATE vulnerabilities v
         SET epss_score = src.s,
             epss_percentile = src.p,
             epss_updated_at = $${++p}::timestamptz
        FROM (VALUES ${valuesSql.join(",")}) AS src(cve, s, p)
       WHERE v.cve_id = src.cve
    `;
    params.push(scoreDate ?? new Date().toISOString());
    const res = await pool.query(sql, params);
    updated += res.rowCount ?? 0;
    batch = [];
  }

  for await (const line of rl) {
    if (line.startsWith("#")) {
      const m = line.match(/score_date:([^,\s]+)/);
      if (m) scoreDate = m[1];
      continue;
    }
    if (!header) {
      header = line.split(",");
      if (header[0] !== "cve") {
        console.warn(`[epss] unexpected header: ${line}`);
      }
      continue;
    }
    const cols = line.split(",");
    if (cols.length < 3) continue;
    batch.push([cols[0], cols[1], cols[2]]);
    processed++;
    if (batch.length >= BATCH) {
      await flush();
      if (processed % 10000 === 0) process.stdout.write(`\r[epss] processed ${processed}        `);
    }
  }
  await flush();
  await pipePromise;
  process.stdout.write(`\n[epss] processed=${processed} matched/updated=${updated} score_date=${scoreDate}\n`);

  const { rows } = await pool.query(
    `SELECT COUNT(*) FILTER (WHERE epss_score IS NOT NULL)::int AS with_epss,
            COUNT(*)::int AS total
       FROM vulnerabilities`,
  );
  console.log(`[epss] vulnerabilities: ${rows[0].with_epss} / ${rows[0].total} now have EPSS`);
  await pool.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
