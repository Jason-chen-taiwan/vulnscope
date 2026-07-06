import { describe, it, expect } from "vitest";
import DatabaseCtor from "better-sqlite3";
// ".js" extension matches the proven convention in sink-sqlite.test.ts.
import { buildSchema } from "./build-sqlite.js";
import { SYNC_STATE_DDL, readWatermark } from "../src/lib/ingest/sync-state";
import { sevenDaysAgoIso, ingestOsvIncremental } from "./build-sqlite-incremental";

describe("sevenDaysAgoIso", () => {
  it("returns an ISO string 7 days before the given ms", () => {
    const now = Date.parse("2026-07-08T00:00:00.000Z");
    expect(sevenDaysAgoIso(now)).toBe("2026-07-01T00:00:00.000Z");
  });
});

function db() {
  const d = new DatabaseCtor(":memory:");
  buildSchema(d);
  d.exec(SYNC_STATE_DDL);
  return d;
}

describe("ingestOsvIncremental spike guard", () => {
  it("skips the ecosystem and does NOT advance the watermark when changed > threshold", async () => {
    const d = db();
    // 5001 changed ids in the csv → over SPIKE_THRESHOLD (5000).
    const lines = Array.from({ length: 5001 }, (_, i) =>
      `2026-07-05T00:00:${String(i % 60).padStart(2, "0")}.000Z,CVE-2026-${1000 + i}`,
    ).join("\n");
    const res = await ingestOsvIncremental({
      eco: "Hex",
      db: d,
      nowMs: Date.parse("2026-07-06T00:00:00.000Z"),
      fetchCsv: async () => lines,
      // fetchZip must NOT be called when the spike guard trips.
      fetchZipToFile: async () => {
        throw new Error("fetchZip should not run on spike");
      },
    });
    expect(res.skippedBySpike).toBe(true);
    expect(readWatermark(d, "osv:Hex")).toBeNull(); // watermark untouched
  });

  it("skips (no write) when csv has no changes since watermark", async () => {
    const d = db();
    const res = await ingestOsvIncremental({
      eco: "Hex",
      db: d,
      nowMs: Date.parse("2026-07-06T00:00:00.000Z"),
      // Only one row, exactly at the watermark we seed → empty changed set.
      fetchCsv: async () => "2026-07-01T00:00:00.000Z,CVE-2026-0001",
      fetchZipToFile: async () => {
        throw new Error("fetchZip should not run when nothing changed");
      },
      // seed watermark = the only row's ts → nothing newer.
      watermarkOverride: "2026-07-01T00:00:00.000Z",
    });
    expect(res.changedCount).toBe(0);
    expect(res.imported).toBe(0);
  });
});
