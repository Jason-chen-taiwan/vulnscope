import { NextRequest } from "next/server";
import { checkPackageVersion } from "@/lib/queries";
import { ok, fail } from "@/lib/envelope";
import { normalizePypiName } from "@/lib/osv";

export const dynamic = "force-dynamic";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ ecosystem: string; name: string }> },
) {
  const { ecosystem: ecoRaw, name: nameRaw } = await params;
  const ecosystem = decodeURIComponent(ecoRaw);
  const name = decodeURIComponent(nameRaw);
  const version = req.nextUrl.searchParams.get("version");
  if (!version || version.trim() === "") {
    return fail(400, "MISSING_VERSION", "version query param is required", "version");
  }
  if (ecosystem !== "npm" && ecosystem !== "PyPI") {
    return fail(400, "UNSUPPORTED_ECOSYSTEM", `Phase 0 supports npm + PyPI only`, "ecosystem");
  }
  const normalized = ecosystem === "PyPI" ? normalizePypiName(name) : name;
  const result = await checkPackageVersion(ecosystem, normalized, version.trim());
  if (!result) return fail(404, "NOT_FOUND", `pkg:${ecosystem}/${normalized} unknown`);
  return ok(result);
}
