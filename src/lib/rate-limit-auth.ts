/**
 * Auth-aware identity helper for the rate limiter.
 *
 * Lives in its own module so that `./rate-limit.ts` can reach it via
 * an obfuscated dynamic import that webpack's Edge-bundle tracer
 * can't follow. The pro-bridge → Better Auth → kysely-adapter chain
 * has Edge-incompatible paths (bun-sqlite-dialect references kysely
 * exports that don't exist in the Edge sandbox); pulling it into the
 * middleware bundle fails the production build.
 *
 * Only API-route callers ever reach this branch (they pass no
 * `identityHint`); middleware always passes `identityHint: "ip-only"`,
 * so the dynamic import never executes on the Edge.
 */
import "server-only";
import { proAuth } from "./pro-bridge";

export async function lookupSignedInUser(): Promise<{ id: string } | null> {
  const pro = await proAuth();
  if (!pro) return null;
  const user = await pro.getCurrentUser();
  if (!user?.id) return null;
  return { id: user.id };
}
