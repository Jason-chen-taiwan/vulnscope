/**
 * Better Auth catch-all. Handles OAuth callbacks, sign-in / sign-out,
 * session lookups, and the rest of the Better Auth surface. The
 * actual handler lives in /pro/auth/config.ts; this OSS-side file
 * loads it lazily so self-host (PRO_ENABLED=0 / no /pro folder)
 * still builds and 404s these routes.
 */
import { proAuth } from "@/lib/pro-bridge";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

async function handle(req: Request) {
  const pro = await proAuth();
  if (!pro) {
    return new Response("Not found", { status: 404 });
  }
  return pro.auth.handler(req);
}

export const GET = handle;
export const POST = handle;
