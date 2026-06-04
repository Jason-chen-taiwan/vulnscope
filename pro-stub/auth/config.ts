/**
 * OSS-mode stub for the Better Auth instance. The hosted Pro tier
 * replaces this via the @pro/* alias in next.config.ts.
 *
 * Returns the minimal surface pro-bridge expects: an `auth.handler`
 * that 404s every request, so the /api/auth/[...all] route handler
 * compiles and runs without auth code in the bundle.
 */
const notFound = () => new Response("Not found", { status: 404 });

export const auth = {
  handler: notFound as (req: Request) => Promise<Response> | Response,
  api: {
    getSession: async (_: { headers: Headers }) => null,
  },
  // Better Auth exposes a $Infer.Session type; mirror an empty one so
  // type imports from src/lib/pro-bridge don't break the OSS build.
  $Infer: {
    Session: null as unknown as {
      user: { id: string; email: string };
    } | null,
  },
};

export type AuthSession = typeof auth.$Infer.Session;
