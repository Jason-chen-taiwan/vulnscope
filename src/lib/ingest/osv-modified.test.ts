import { describe, it, expect } from "vitest";
import { parseModifiedCsv, MODIFIED_CSV_URL } from "./osv-modified";

// Reverse-chronological CSV (newest first), matching OSV's format.
const CSV = [
  "2026-07-05T23:00:00.000Z,GHSA-aaaa-bbbb-cccc",
  "2026-07-05T22:00:00.000Z,CVE-2026-1234",
  "2026-07-05T21:00:00.000Z,MAL-2026-0001",
  "2026-07-04T10:00:00.000Z,CVE-2026-0099",
  "2026-07-01T09:00:00.000Z,CVE-2025-8888",
].join("\n");

describe("parseModifiedCsv", () => {
  it("collects primary ids newer than the watermark and stops at <= watermark", () => {
    // watermark = the 2026-07-04 line's timestamp → that line and older excluded.
    const { changedIds, newWatermark } = parseModifiedCsv(
      CSV,
      "2026-07-04T10:00:00.000Z",
    );
    expect([...changedIds].sort()).toEqual(
      ["CVE-2026-1234", "GHSA-aaaa-bbbb-cccc", "MAL-2026-0001"].sort(),
    );
    // primary ids kept verbatim — NOT pre-filtered to CVE-.
    expect(newWatermark).toBe("2026-07-05T23:00:00.000Z");
  });

  it("returns all rows when watermark is null (cold-ish, but bounded by caller)", () => {
    const { changedIds, newWatermark } = parseModifiedCsv(CSV, null);
    expect(changedIds.size).toBe(5);
    expect(newWatermark).toBe("2026-07-05T23:00:00.000Z");
  });

  it("returns empty set + null watermark for empty input", () => {
    const { changedIds, newWatermark } = parseModifiedCsv("", "2026-01-01T00:00:00.000Z");
    expect(changedIds.size).toBe(0);
    expect(newWatermark).toBeNull();
  });

  it("returns empty set when every row is <= watermark, but still sets newWatermark from the newest line", () => {
    const { changedIds, newWatermark } = parseModifiedCsv(CSV, "2026-07-05T23:00:00.000Z");
    expect(changedIds.size).toBe(0);
    expect(newWatermark).toBe("2026-07-05T23:00:00.000Z");
  });

  it("builds the per-ecosystem URL", () => {
    expect(MODIFIED_CSV_URL("npm")).toBe(
      "https://osv-vulnerabilities.storage.googleapis.com/npm/modified_id.csv",
    );
    expect(MODIFIED_CSV_URL("crates.io")).toContain("/crates.io/modified_id.csv");
    // A space must be percent-encoded (proves encodeURIComponent is applied).
    expect(MODIFIED_CSV_URL("Go Modules")).toBe(
      "https://osv-vulnerabilities.storage.googleapis.com/Go%20Modules/modified_id.csv",
    );
  });
});
