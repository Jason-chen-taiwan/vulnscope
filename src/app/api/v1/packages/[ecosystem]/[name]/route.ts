import { NextRequest } from "next/server";
import { getPackageWithCves } from "@/lib/queries";
import { ok, fail } from "@/lib/envelope";
import { normalizePypiName } from "@/lib/osv";

export const dynamic = "force-dynamic";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ ecosystem: string; name: string }> },
) {
  const { ecosystem: ecoRaw, name: nameRaw } = await params;
  const ecosystem = decodeURIComponent(ecoRaw);
  const name = decodeURIComponent(nameRaw);
  const normalized = ecosystem === "PyPI" ? normalizePypiName(name) : name;
  const bundle = await getPackageWithCves(ecosystem, normalized);
  if (!bundle) return fail(404, "NOT_FOUND", `pkg:${ecosystem}/${normalized} unknown`);
  return ok(bundle);
}
