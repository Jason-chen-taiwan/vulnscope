/**
 * Next.js calls register() exactly once per server process (App Router
 * docs: "Use instrumentation to integrate observability tooling..."),
 * which is the right place to boot the in-process scheduler. Doing it
 * via a top-level side effect in lib/queries.ts caused doubled tick()
 * runs because Route Handler and SSR module graphs each evaluated the
 * module separately, racing the globalThis dedup flag.
 *
 * The nodejs runtime guard skips Edge (middleware) — scheduler uses
 * pg + node:fs, which Edge can't load.
 */
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;

  // Boot-time schema repair. Runs BEFORE the scheduler starts so the
  // first ingest tick can rely on columns that newer code expects but
  // the production migration may not have applied yet (this repo's
  // deploy story is half-manual; we lean on self-healing DDL with
  // advisory-lock serialization to make new schema self-deploying).
  // Without this, kev — first source in orchestrator — would crash on
  // startJob INSERT when last_heartbeat_at doesn't exist yet.
  try {
    const { ensureIngestSchema } = await import("@/lib/ingest/ensure-schema");
    await ensureIngestSchema();
  } catch (e) {
    // Don't block server boot if DB is briefly unavailable — the
    // ingest path will retry on its next tick.
    console.error("[instrumentation] ensureIngestSchema failed at boot:", e);
  }

  const { startScheduler } = await import("@/lib/scheduler");
  startScheduler();
}
