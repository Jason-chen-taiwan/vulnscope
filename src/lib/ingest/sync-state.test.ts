import { describe, it, expect } from "vitest";
import DatabaseCtor from "better-sqlite3";
import { SYNC_STATE_DDL, readWatermark, writeWatermark } from "./sync-state";

function freshDb() {
  const db = new DatabaseCtor(":memory:");
  db.exec(SYNC_STATE_DDL);
  return db;
}

describe("sync-state", () => {
  it("returns null for a missing source (cold start)", () => {
    const db = freshDb();
    expect(readWatermark(db, "osv:npm")).toBeNull();
  });

  it("writes then reads a watermark", () => {
    const db = freshDb();
    writeWatermark(db, "osv:npm", "2026-07-05T23:00:00.000Z", "2026-07-06T05:00:00.000Z");
    expect(readWatermark(db, "osv:npm")).toBe("2026-07-05T23:00:00.000Z");
  });

  it("upserts (second write for same source overwrites)", () => {
    const db = freshDb();
    writeWatermark(db, "osv:npm", "2026-07-05T23:00:00.000Z", "2026-07-06T05:00:00.000Z");
    writeWatermark(db, "osv:npm", "2026-07-06T23:00:00.000Z", "2026-07-07T05:00:00.000Z");
    expect(readWatermark(db, "osv:npm")).toBe("2026-07-06T23:00:00.000Z");
    const rows = db.prepare("SELECT count(*) AS c FROM sync_state WHERE source='osv:npm'").get() as { c: number };
    expect(rows.c).toBe(1);
  });

  it("keeps sources independent", () => {
    const db = freshDb();
    writeWatermark(db, "osv:npm", "2026-07-05T00:00:00.000Z", "x");
    writeWatermark(db, "osv:PyPI", "2026-07-01T00:00:00.000Z", "x");
    expect(readWatermark(db, "osv:npm")).toBe("2026-07-05T00:00:00.000Z");
    expect(readWatermark(db, "osv:PyPI")).toBe("2026-07-01T00:00:00.000Z");
  });
});
