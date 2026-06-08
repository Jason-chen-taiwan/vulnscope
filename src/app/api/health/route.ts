export const dynamic = "force-dynamic";

/**
 * Liveness probe used by Fly.io's HTTP check.
 *
 * Deliberately does NOT touch the database. Fly's health check has a
 * 5-second timeout; if we issue a `SELECT 1` here and Postgres is
 * mid-checkpoint, swapping cache, or under contention from an active
 * ingest, the query can stall past 5s and Fly marks the whole web
 * machine unhealthy. With min_machines_running=0 that produces a
 * "could not find a good candidate within 40 attempts at load
 * balancing" outage even though the Node process itself is fine.
 *
 * Liveness = "Node process is alive and accepting HTTP" — that's
 * exactly what this endpoint now answers. DB health is its own
 * concern; surface it elsewhere (sync_jobs dashboard, logs) rather
 * than letting it cascade into a routing decision.
 */
export async function GET() {
  return new Response(JSON.stringify({ status: "ok" }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}
