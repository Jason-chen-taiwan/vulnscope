import "server-only";
import { fetch } from "undici";
import { ingestPool as pool } from "@/db/ingest-pool";
import { startJob } from "@/lib/sync-jobs";
import { severityFromScore } from "@/lib/osv";

// NVD 2.0 API. No API key required, but anonymous callers are rate
// limited to 5 requests per 30-second rolling window. We sleep 6.5s
// between requests to stay well under that.
//
// Strategy: fetch only CVEs that exist in our DB but have NO base_score
// in cvss_scores. OSV omits scores for ~30-40% of records (especially
// older CVE-2019/2020 ones), so this fills real gaps rather than
// re-fetching everything.
const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const PAGE_SIZE = 100;
const REQUEST_DELAY_MS = 6500;
const MAX_CVES_PER_RUN = 500; // cap so a single run can't run for hours

interface NvdMetric {
  cvssData: {
    version: string;
    vectorString: string;
    baseScore: number;
    baseSeverity?: string;
  };
}

interface NvdVuln {
  cve: {
    id: string;
    metrics?: {
      cvssMetricV40?: NvdMetric[];
      cvssMetricV31?: NvdMetric[];
      cvssMetricV30?: NvdMetric[];
      cvssMetricV2?: NvdMetric[];
    };
  };
}

interface NvdResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: NvdVuln[];
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export interface RunNvdOptions {
  signal?: AbortSignal;
}

export async function runNvdIngest(
  opts?: RunNvdOptions,
): Promise<{ seen: number; changed: number }> {
  const job = await startJob("nvd");
  let seen = 0;
  let changed = 0;
  try {
    // Pull a batch of CVE IDs that we have in our DB but lack any score.
    // ORDER BY published_at DESC means newer CVEs (most likely to be in
    // someone's lockfile) get backfilled first.
    const { rows } = await pool.query<{ cve_id: string }>(
      `SELECT v.cve_id
         FROM vulnerabilities v
         LEFT JOIN cvss_scores cs ON cs.cve_id = v.cve_id
        WHERE cs.cve_id IS NULL
        ORDER BY v.published_at DESC NULLS LAST
        LIMIT $1`,
      [MAX_CVES_PER_RUN],
    );
    if (rows.length === 0) {
      console.log("[nvd] no score gaps to fill");
      await job.finish({ seen: 0, changed: 0 });
      return { seen: 0, changed: 0 };
    }
    console.log(`[nvd] backfilling scores for ${rows.length} CVE(s)`);

    // Batch 100 at a time — NVD supports cveId as a single-value param
    // only, so we fan out one HTTP request per CVE. Sleep between to
    // respect the 5-req/30s anonymous quota.
    for (const { cve_id } of rows) {
      if (opts?.signal?.aborted) throw new Error("aborted: nvd");
      seen += 1;
      try {
        const url = `${NVD_URL}?cveId=${encodeURIComponent(cve_id)}`;
        const res = await fetch(url, {
          headers: { "user-agent": "vulnscope-tw (https://vulnscope-tw.fly.dev)" },
          signal: opts?.signal,
        });
        if (res.status === 404) continue; // CVE not in NVD
        if (!res.ok) {
          // 503 means we hit the rate limit — back off harder.
          if (res.status === 503 || res.status === 429) {
            await sleep(30_000);
            continue;
          }
          console.warn(`[nvd] ${cve_id}: HTTP ${res.status}`);
          continue;
        }
        const body = (await res.json()) as NvdResponse;
        const vuln = body.vulnerabilities?.[0];
        if (!vuln) continue;
        const metrics = vuln.cve.metrics;
        if (!metrics) continue;

        // Prefer newest CVSS version; NVD sometimes provides several.
        const all: { version: string; metric: NvdMetric }[] = [];
        for (const m of metrics.cvssMetricV40 ?? []) all.push({ version: "4.0", metric: m });
        for (const m of metrics.cvssMetricV31 ?? []) all.push({ version: "3.1", metric: m });
        for (const m of metrics.cvssMetricV30 ?? []) all.push({ version: "3.0", metric: m });
        for (const m of metrics.cvssMetricV2 ?? []) all.push({ version: "2.0", metric: m });

        for (const { version, metric } of all) {
          const score = metric.cvssData.baseScore;
          const vector = metric.cvssData.vectorString;
          const sev = metric.cvssData.baseSeverity ?? severityFromScore(score);
          const r = await pool.query(
            `INSERT INTO cvss_scores (cve_id, version, vector, base_score, severity, source)
                  VALUES ($1, $2, $3, $4, $5, 'nvd')
             ON CONFLICT (cve_id, version, source) DO UPDATE
                  SET vector = EXCLUDED.vector,
                      base_score = EXCLUDED.base_score,
                      severity = EXCLUDED.severity`,
            [cve_id, version, vector, score, sev],
          );
          if ((r.rowCount ?? 0) > 0) changed += 1;
        }
      } catch (e) {
        console.warn(`[nvd] ${cve_id} failed: ${(e as Error).message}`);
      }
      await sleep(REQUEST_DELAY_MS);
    }

    await job.finish({ seen, changed });
    return { seen, changed };
  } catch (e) {
    await job.finish({ seen, changed, error: e as Error });
    throw e;
  }
}
