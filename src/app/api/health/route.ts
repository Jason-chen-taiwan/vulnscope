import { pool } from "@/db/client";

export const dynamic = "force-dynamic";

/**
 * Health endpoint used by Fly.io's HTTP check.
 * Returns 200 only if the database is reachable — Fly will route around
 * unhealthy instances.
 */
export async function GET() {
  try {
    await pool.query("SELECT 1");
    return new Response(JSON.stringify({ status: "ok" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ status: "unhealthy", error: (e as Error).message }), {
      status: 503,
      headers: { "content-type": "application/json" },
    });
  }
}
