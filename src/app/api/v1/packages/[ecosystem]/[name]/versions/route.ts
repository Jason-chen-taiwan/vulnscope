/**
 * GET /api/v1/packages/[ecosystem]/[name]/versions
 *
 * Returns distinct concrete versions OSV has on file for the package
 * (deduped from versions_json + ranges_json events). Used by the
 * dashboard watchlist add flow to render a version dropdown after
 * the user picks a package from autocomplete.
 *
 * Empty array if the package is unknown OR if OSV only has open-ended
 * range data — callers should fall back to a free-text input.
 */
import type { NextRequest } from "next/server";
import { ok } from "@/lib/envelope";
import { getPackageVersions } from "@/lib/queries";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export const GET = async (_req: NextRequest, ctx: { params: Promise<{ ecosystem: string; name: string }> }) => {
  const { ecosystem, name } = await ctx.params;
  const versions = await getPackageVersions(
    decodeURIComponent(ecosystem),
    decodeURIComponent(name),
  );
  return ok(versions);
};
