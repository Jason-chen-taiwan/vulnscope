import { NextRequest } from "next/server";
import { z } from "zod";
import pLimit from "p-limit";
import { checkPackageVersion, type VersionCheckResult } from "@/lib/queries";
import { normalizePypiName } from "@/lib/osv";
import { ok, fail, corsPreflight } from "@/lib/envelope";
import { withRateLimit } from "@/lib/rate-limit";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Hard ceiling before we even try to parse JSON. zod's max(500) on
// the array doesn't help if the request is 100 MB of garbage — the
// parser allocates the whole string first.
const MAX_BODY_BYTES = 1_000_000;

/**
 * Batch version check used by the `vulnscope` CLI. Submitting hundreds
 * of single-version requests would be slow and rude; this endpoint
 * accepts up to 500 (ecosystem, name, version) tuples in one POST and
 * returns the results in input order.
 *
 * Unknown packages (not in our DB) come back with `unknown: true` and
 * `is_vulnerable: false` so the CLI can surface them to the user
 * instead of silently dropping the row.
 */

const BatchInputSchema = z.object({
  packages: z
    .array(
      z.object({
        ecosystem: z.enum(["npm", "PyPI"]),
        name: z.string().min(1).max(214),
        version: z.string().min(1).max(64),
      }),
    )
    .min(1)
    .max(500),
});

export const POST = withRateLimit(
  "check_batch",
  async (req: NextRequest) => {
    // Body size guard. Reject before calling req.json() so we don't
    // even read a megabyte of attacker payload into memory.
    const contentLength = parseInt(req.headers.get("content-length") ?? "0", 10);
    if (contentLength > MAX_BODY_BYTES) {
      return fail(413, "REQUEST_TOO_LARGE", `request body must be ≤ ${MAX_BODY_BYTES} bytes`);
    }

    let body: unknown;
    try {
      body = await req.json();
    } catch {
      return fail(400, "INVALID_JSON", "request body must be JSON");
    }
    const parsed = BatchInputSchema.safeParse(body);
    if (!parsed.success) {
      return fail(400, "INVALID_BODY", parsed.error.issues[0]?.message ?? "schema validation failed");
    }

    // p-limit(10) so a 500-package request doesn't saturate the pg pool.
    const limit = pLimit(10);
    const results: VersionCheckResult[] = await Promise.all(
      parsed.data.packages.map((p) =>
        limit(async () => {
          const normalized = p.ecosystem === "PyPI" ? normalizePypiName(p.name) : p.name;
          const r = await checkPackageVersion(p.ecosystem, normalized, p.version);
          if (r) return r;
          // Unknown package — synthesize a clean response so the order is preserved.
          return {
            package: { ecosystem: p.ecosystem, name: p.name },
            version: p.version,
            is_vulnerable: false,
            affected_by: [],
            recommended_version: null,
            unknown: true,
          };
        }),
      ),
    );

    const unknown_count = results.filter((r) => r.unknown).length;
    const vulnerable_count = results.filter((r) => r.is_vulnerable).length;
    return ok(results, {
      count: results.length,
      unknown_count,
      vulnerable_count,
    });
  },
  { identityHint: "ip-only" },
);

export async function OPTIONS() {
  return corsPreflight();
}
