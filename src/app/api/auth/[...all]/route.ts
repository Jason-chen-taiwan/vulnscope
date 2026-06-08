/**
 * Better Auth catch-all. Handles OAuth callbacks, sign-in / sign-out,
 * session lookups, and the rest of the Better Auth surface. The
 * actual handler lives in /pro/auth/config.ts; this OSS-side file
 * loads it lazily so self-host (PRO_ENABLED=0 / no /pro folder)
 * still builds and 404s these routes.
 */
import type { NextRequest } from "next/server";
import { proAuth } from "@/lib/pro-bridge";
import { withRateLimit } from "@/lib/rate-limit";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Credential-stuffing target. IP-keyed limiter even though this is the
// auth route itself — getCurrentUser() inside the limiter would race
// the very session being created. 10 req/min/IP is fine for legit OAuth
// (sign-in is rare) and brutal on automated abuse.
const handle = withRateLimit(
  "auth",
  async (req: NextRequest) => {
    const pro = await proAuth();
    if (!pro) return new Response("Not found", { status: 404 });
    return pro.auth.handler(req);
  },
  { identityHint: "ip-only" },
);

export const GET = handle;
export const POST = handle;
