import "server-only";
import { runKevIngest } from "./kev";
import { runOsvIngest } from "./osv";
import { runEpssIngest } from "./epss";

export const DEFAULT_ECOSYSTEMS = [
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

  const finishedAt = new Date();
  return {
    startedAt,
    finishedAt,
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    steps,
  };
}
