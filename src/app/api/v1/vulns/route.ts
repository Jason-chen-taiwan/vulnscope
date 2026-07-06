import { NextRequest } from "next/server";
import { searchVulns } from "@/lib/queries";
import { ok } from "@/lib/envelope";

export const dynamic = "force-dynamic";

export const GET = async (req: NextRequest) => {
  const sp = req.nextUrl.searchParams;
  const q = sp.get("q") ?? undefined;
  const severity = sp.get("severity")?.split(",").filter(Boolean);
  const ecosystem = sp.get("ecosystem")?.split(",").filter(Boolean);
  const kev = sp.get("kev") === "true";
  // Cap deep pagination. Beyond page 50 with the default pageSize=25
  // is mostly bot territory and offset-scanning is hostile to PG.
  const page = Math.min(50, parseInt(sp.get("page") ?? "1", 10) || 1);
  const pageSize = Math.min(100, parseInt(sp.get("pageSize") ?? "25", 10) || 25);

  const { items, total } = await searchVulns({ q, severity, ecosystem, kev, page, pageSize });
  return ok(items, { total, page, pageSize });
};
