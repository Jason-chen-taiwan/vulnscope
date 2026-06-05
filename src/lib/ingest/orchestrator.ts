import "server-only";
import { runKevIngest } from "./kev";
import { runOsvIngest } from "./osv";
import { runEpssIngest } from "./epss";
import { runNvdIngest } from "./nvd";
import { runExploitsIngest } from "./exploits";
import { markTimedOut } from "@/lib/sync-jobs";

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
 * Per-source timeout budgets. Picked from observed runtimes with healthy
 * headroom for cold caches and upstream slowness:
 *
 *   kev       1.2s  → 60s   (50× headroom)
 *   osv:npm   ~3min  → 10min (3× headroom after batched ingest)
 *   osv:Debian ~2min → 10min (second largest after npm)
 *   osv:*     <30s   → 5min  (covers any unexpected slow ecosystem)
 *   epss      135s   → 10min (8× headroom)
 *   nvd       up to 55min via 5-req/30s rate limit → 70min
 *   exploits  ~80s   → 5min  (4× headroom)
 *
 * A timeout fires the `attempt` catch path which: (1) sends abort to
 * the source via the AbortSignal so its loop exits cooperatively at the
 * next chunk boundary, (2) calls markTimedOut() to flip the sync_jobs
 * row from `running` to `failed` (the zombie's eventual finish() now
 * no-ops thanks to its `WHERE status='running'` guard), (3) moves on
 * to the next source so one stuck ingest can't hang the refresh window.
 *
 * Defense in depth: even if the JS timeout's abort doesn't reach a
 * stuck pg query (node-postgres has no cancel API), the ingest pool's
 * 60s statement_timeout kills it server-side and the connection
 * returns to the pool.
 */
const DEFAULT_INGEST_TIMEOUT_MS = 5 * 60_000;
const SOURCE_TIMEOUTS_MS: Record<string, number> = {
  kev: 60_000,
  epss: 10 * 60_000,
  nvd: 70 * 60_000,
  exploits: 5 * 60_000,
  // npm + Debian are the two largest OSV ecosystems by record count
  // (220k and 60k respectively). After v34 yauzl-streaming, expected
  // wall time is ~5min for npm, ~2min for Debian — but the entry-walk
  // rate hasn't been validated under prod shared-CPU contention.
  // Timeouts catch hangs, not slow-but-progressing work; 15min gives
  // headroom for bad days without forcing a v35.
  "osv:npm": 15 * 60_000,
  "osv:Debian": 15 * 60_000,
};

function limitFor(source: string): number {
  return SOURCE_TIMEOUTS_MS[source] ?? DEFAULT_INGEST_TIMEOUT_MS;
}

/**
 * Run `fn(signal)` and reject after `ms` with a labelled timeout error.
 * The signal is passed into fn so cooperative cancellation can take
 * effect (chunk-boundary checks in OSV; per-record checks in others).
 * Cancellation does NOT cancel in-flight pg queries — see SOURCE_TIMEOUTS_MS
 * doc above for the layered defense.
 */
async function withTimeout<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  ms: number,
  label: string,
): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await Promise.race([
      fn(ctrl.signal),
      new Promise<never>((_, reject) => {
        ctrl.signal.addEventListener("abort", () =>
          reject(new Error(`timeout: ${label} exceeded ${ms}ms`)),
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Run a full refresh: KEV, then each OSV ecosystem, then EPSS, then NVD
 * backfill, then exploits backfill.
 *
 * Each source runs independently — a failure in one (including a
 * timeout) does not abort the others. This matches the SRE principle
 * from PRD §12.3: never let a single upstream outage break the whole UI.
 *
 * Orchestrator deliberately uses the web pool (via sync-jobs.markTimedOut)
 * because the ingest pool's 3 slots might be held by the zombie source we
 * just timed out — going via web pool ensures the failure marker lands.
 */
export async function runFullRefresh(options?: {
  ecosystems?: string[];
  skipOsv?: boolean;
}): Promise<RefreshResult> {
  const startedAt = new Date();
  const ecosystems = options?.ecosystems ?? DEFAULT_ECOSYSTEMS;
  const steps: RefreshResult["steps"] = [];

  async function attempt(
    label: string,
    fn: (signal: AbortSignal) => Promise<{ seen: number; changed: number }>,
  ) {
    const t0 = Date.now();
    const attemptStart = new Date();
    const limit = limitFor(label);
    try {
      const r = await withTimeout(fn, limit, label);
      steps.push({ source: label, ok: true, seen: r.seen, changed: r.changed });
      console.log(`[refresh] ${label}: ok seen=${r.seen} changed=${r.changed} (${Date.now() - t0}ms)`);
    } catch (e) {
      const msg = (e as Error).message;
      const timedOut = msg.startsWith("timeout:");
      steps.push({ source: label, ok: false, error: msg });
      console.error(`[refresh] ${label}: FAILED ${msg}`);
      if (timedOut) {
        // The zombie source is still in-flight and holds its own JobHandle.
        // markTimedOut goes via the WEB pool so it lands even if the
        // ingest pool's 3 slots are starved by the zombie. The zombie's
        // eventual finish() will no-op against the now-failed row
        // (`WHERE status='running'` guard in sync-jobs.ts).
        //
        // Cosmetic race: if the zombie's pg query completes and its
        // finish() lands BEFORE this markTimedOut, the row will show
        // `success` while RefreshResult.steps shows `failed`. The work
        // actually completed; only the two surfaces disagree. Acceptable.
        try {
          await markTimedOut(label, attemptStart, msg);
        } catch (markErr) {
          console.error(`[refresh] ${label}: markTimedOut failed`, markErr);
        }
      }
    }
  }

  await attempt("kev", (signal) => runKevIngest({ signal }));
  if (!options?.skipOsv) {
    for (const eco of ecosystems) {
      await attempt(`osv:${eco}`, (signal) => runOsvIngest(eco, { signal }));
    }
  }
  await attempt("epss", (signal) => runEpssIngest({ signal }));
  // NVD backfill runs last. It only touches CVEs that have no CVSS
  // score after OSV ingest, capped at 500/run to respect NVD's 5-req-
  // per-30-second anonymous quota (~55 min worst case). Even if this
  // hits the cap, the next refresh continues filling.
  await attempt("nvd", (signal) => runNvdIngest({ signal }));
  // Exploits backfill: only ~80ms latency per CVE, capped at 400/run.
  // Worst case ~80s of HTTP work, but in steady state most CVEs are
  // already mapped and we skip them via the LEFT JOIN filter.
  await attempt("exploits", (signal) => runExploitsIngest({ signal }));

  const finishedAt = new Date();
  return {
    startedAt,
    finishedAt,
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    steps,
  };
}
