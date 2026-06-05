/**
 * DELETE /api/v1/watchlist/[id] — remove a watch.
 *
 * The pro/lib helper scopes the DELETE to (id, user_id) so users
 * can't remove each other's rows; we surface "not found" as 404
 * regardless of whether the id doesn't exist at all or belongs to
 * someone else.
 */
import { fail, ok } from "@/lib/envelope";
import { proAuth } from "@/lib/pro-bridge";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function DELETE(
  _req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const pro = await proAuth();
  if (!pro) return fail(503, "pro_unavailable", "Pro features are not enabled on this build");

  let user;
  try {
    user = await pro.getCurrentUser();
  } catch (e) {
    console.error("[watchlist DELETE] getCurrentUser failed:", e);
    return fail(503, "upstream_down", "Auth service is unavailable");
  }
  if (!user) return fail(401, "unauthenticated", "Sign in to modify your watchlist");

  const { id } = await ctx.params;
  if (!id) return fail(400, "missing_id", "Watchlist id is required");

  try {
    const { removed } = await pro.removeWatch(user.id, id);
    if (!removed) return fail(404, "not_found", "Watchlist entry not found");
    return ok({ id });
  } catch (e) {
    console.error("[watchlist DELETE] failed:", e);
    return fail(502, "delete_failed", "Could not remove from watchlist");
  }
}
