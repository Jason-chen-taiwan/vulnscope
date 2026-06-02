import "server-only";
import { runKevIngest } from "./kev";
import { runOsvIngest } from "./osv";
import { runEpssIngest } from "./epss";
import { runNvdIngest } from "./nvd";

const ALL_ECOSYSTEMS = [
  "npm",
  "PyPI",
  "Maven",
  "Go",
  "RubyGems",
  "Packagist",
  "crates.io",
  "NuGet",
  "Hex",
  "Hackage",
  "Debian",
  "Alpine",
  "Bitnami",
];

/**
 * Operators can restrict which ecosystems the scheduler refreshes via
 * INGEST_ECOSYSTEMS env (comma-separated). Useful when the DB has size
 * constraints (e.g. Neon free tier @ 500 MB) — limiting to npm/PyPI/Maven
 * keeps the footprint under ~200 MB while still covering the bulk of
 * "what package am I using" questions.
 */
export const DEFAULT_ECOSYSTEMS = process.env.INGEST_ECOSYSTEMS
  ? process.env.INGEST_ECOSYSTEMS.split(",").map((s) => s.trim()).filter(Boolean)
  : ALL_ECOSYSTEMS;

export interface RefreshResult {
  startedAt: Date;
  finishedAt: Date;
  durationMs: number;
  steps: { source: string; ok: boolean; seen?: number; changed?: number; error?: string }[];
}

/**
 * Run a full refresh: KEV, then each OSV ecosystem, then EPSS.
 *
 * Each source runs independently — a failure in one does not abort the
 * others. This matches the SRE principle from PRD §12.3: never let a
 * single upstream outage break the whole UI.
 */
export async function runFullRefresh(options?: {
  ecosystems?: string[];
  skipOsv?: boolean;
}): Promise<RefreshResult> {
  const startedAt = new Date();
  const ecosystems = options?.ecosystems ?? DEFAULT_ECOSYSTEMS;
  const steps: RefreshResult["steps"] = [];

  async function attempt(label: string, fn: () => Promise<{ seen: number; changed: number }>) {
    const t0 = Date.now();
    try {
      const r = await fn();
      steps.push({ source: label, ok: true, seen: r.seen, changed: r.changed });
      console.log(`[refresh] ${label}: ok seen=${r.seen} changed=${r.changed} (${Date.now() - t0}ms)`);
    } catch (e) {
      const msg = (e as Error).message;
      steps.push({ source: label, ok: false, error: msg });
      console.error(`[refresh] ${label}: FAILED ${msg}`);
    }
  }

  await attempt("kev", runKevIngest);
  if (!options?.skipOsv) {
    for (const eco of ecosystems) {
      await attempt(`osv:${eco}`, () => runOsvIngest(eco));
    }
  }
  await attempt("epss", runEpssIngest);
  // NVD backfill runs last. It only touches CVEs that have no CVSS
  // score after OSV ingest, capped at 500/run to respect NVD's 5-req-
  // per-30-second anonymous quota (~55 min worst case). Even if this
  // hits the cap, the next refresh continues filling.
  await attempt("nvd", runNvdIngest);

  const finishedAt = new Date();
  return {
    startedAt,
    finishedAt,
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    steps,
  };
}
