import { NextRequest } from "next/server";
import { getCveBundle } from "@/lib/queries";
import { ok, fail } from "@/lib/envelope";
import { withRateLimit } from "@/lib/rate-limit";

export const dynamic = "force-dynamic";

export const GET = withRateLimit(
  "vuln_detail",
  async (_req: NextRequest, ctx: { params: Promise<{ id: string }> }) => {
    const { id } = await ctx.params;
    const cveId = decodeURIComponent(id).toUpperCase();
    if (!/^CVE-\d{4}-\d+$/.test(cveId)) {
      return fail(400, "INVALID_CVE_ID", `'${cveId}' is not a valid CVE identifier`, "id");
    }
    const bundle = await getCveBundle(cveId);
    if (!bundle) return fail(404, "NOT_FOUND", `${cveId} not in database`, "id");
    return ok(bundle);
  },
  { identityHint: "ip-only" },
);
