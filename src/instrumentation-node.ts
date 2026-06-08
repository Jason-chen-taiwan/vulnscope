/**
 * Node-runtime-only boot work. Loaded by Next exclusively in the
 * nodejs runtime (see instrumentation.ts) so unzipper/pg/etc. never
 * leak into the Edge bundle.
 *
 * Process-role gated. The deployment runs two Fly process groups
 * sharing one Docker image:
 *
 *   PROCESS_ROLE=web    — Next.js HTTP server only. No scheduler.
 *   PROCESS_ROLE=worker — scheduler + ingest. HTTP server runs but
 *                         is unused (Fly's http_service only routes
 *                         to the web process group).
 *
 * Default is "web" so any environment without PROCESS_ROLE set
 * (local dev, docker-compose, etc.) behaves like the public-facing
 * server. To run the scheduler locally, set PROCESS_ROLE=worker.
 *
 * Worker boot does two things in order:
 *   1. ensureIngestSchema(): self-healing DDL that adds missing
 *      columns (e.g. sync_jobs.last_heartbeat_at) under an advisory
 *      lock. Worker owns DDL so the web process never touches it.
 *   2. startScheduler(): in-process 24h refresh + reaper.
 */
// Top-level `await` requires this file to be a module. The dynamic
// imports below are the only static dependencies; an explicit empty
// export makes TS treat the file as ESM.
export {};

const role = process.env.PROCESS_ROLE ?? "web";

if (role === "worker") {
  const { ensureIngestSchema } = await import("@/lib/ingest/ensure-schema");
  const { startScheduler } = await import("@/lib/scheduler");
  try {
    await ensureIngestSchema();
  } catch (e) {
    console.error("[instrumentation] ensureIngestSchema failed at boot:", e);
  }
  startScheduler();
  console.log("[instrumentation] booted as PROCESS_ROLE=worker");
} else {
  console.log(`[instrumentation] booted as PROCESS_ROLE=${role} (scheduler disabled)`);
}
