/**
 * Node-runtime-only boot work. Loaded by Next exclusively in the
 * nodejs runtime (see instrumentation.ts) so unzipper/pg/etc. never
 * leak into the Edge bundle.
 *
 *   1. ensureIngestSchema(): self-healing DDL that adds missing
 *      columns (e.g. sync_jobs.last_heartbeat_at) under an advisory
 *      lock. Runs BEFORE the scheduler so the first ingest tick can
 *      rely on schema features that newer code expects but the prod
 *      migration may not have applied yet.
 *
 *   2. startScheduler(): in-process 24h refresh + reaper. Single boot
 *      via Next's register() hook avoids the doubled-tick bug we hit
 *      when this lived as a top-level side effect in lib/queries.ts.
 */
import { ensureIngestSchema } from "@/lib/ingest/ensure-schema";
import { startScheduler } from "@/lib/scheduler";

try {
  await ensureIngestSchema();
} catch (e) {
  // Don't block server boot if DB is briefly unavailable — the ingest
  // path will retry on its next tick via the same ensure-schema call.
  console.error("[instrumentation] ensureIngestSchema failed at boot:", e);
}

startScheduler();
