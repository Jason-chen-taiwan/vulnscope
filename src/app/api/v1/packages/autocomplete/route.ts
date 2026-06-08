import { NextRequest } from "next/server";
import { autocompletePackages } from "@/lib/queries";
import { ok } from "@/lib/envelope";
import { withRateLimit } from "@/lib/rate-limit";

export const dynamic = "force-dynamic";

export const GET = withRateLimit(
  "autocomplete",
  async (req: NextRequest) => {
    const q = req.nextUrl.searchParams.get("q") ?? "";
    const limit = Math.min(20, parseInt(req.nextUrl.searchParams.get("limit") ?? "10", 10) || 10);
    const items = await autocompletePackages(q, limit);
    return ok(items);
  },
  { identityHint: "ip-only" },
);
