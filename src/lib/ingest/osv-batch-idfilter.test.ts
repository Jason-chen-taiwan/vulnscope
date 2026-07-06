import { describe, it, expect, beforeAll, afterAll } from "vitest";
import DatabaseCtor from "better-sqlite3";
import type Database from "better-sqlite3";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { streamOsvZip, type UpsertCtx } from "./osv-batch";
import { SqliteIngestSink } from "./sink-sqlite";
// NOTE: match the existing convention in sink-sqlite.test.ts — this repo's
// test imports of scripts/build-sqlite use the ".js" extension.
import { buildSchema } from "../../../scripts/build-sqlite.js";

// Minimal valid OSV records. Two resolve to CVEs (one in-set, one out-of-set),
// primary-id-keyed like real npm data.
function osvJson(id: string, cve: string) {
  return JSON.stringify({
    id,
    modified: "2026-07-05T00:00:00Z",
    aliases: [cve],
    affected: [
      { package: { ecosystem: "Hex", name: "demo" }, ranges: [] },
    ],
    references: [],
  });
}

let work: string;
let zipPath: string;

beforeAll(async () => {
  work = await fs.mkdtemp(join(tmpdir(), "idfilter-"));
  const dir = join(work, "z");
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(join(dir, "GHSA-in-set-0001.json"), osvJson("GHSA-in-set-0001", "CVE-2026-1111"));
  await fs.writeFile(join(dir, "GHSA-out-set-0002.json"), osvJson("GHSA-out-set-0002", "CVE-2026-2222"));
  await fs.writeFile(join(dir, "GHSA-out-set-0003.json"), osvJson("GHSA-out-set-0003", "CVE-2026-3333"));
  zipPath = join(work, "all.zip");
  // Use the system `zip` to create the archive with flat entry names.
  execFileSync("zip", ["-j", "-q", zipPath, ...[
    "GHSA-in-set-0001.json",
    "GHSA-out-set-0002.json",
    "GHSA-out-set-0003.json",
  ].map((f) => join(dir, f))]);
});

afterAll(async () => {
  await fs.rm(work, { recursive: true, force: true }).catch(() => {});
});

function sinkDb(): Database.Database {
  const db = new DatabaseCtor(":memory:");
  buildSchema(db);
  return db;
}

function ctx(): UpsertCtx {
  return {
    eco: "Hex",
    ecoMatch: () => true,
    pkgCache: new Map(),
  };
}

describe("streamOsvZip idFilter", () => {
  it("with idFilter, only in-set primary ids are written", async () => {
    const db = sinkDb();
    const sink = new SqliteIngestSink(db);
    const { imported } = await streamOsvZip({
      ctx: ctx(),
      zipPath,
      sink,
      classifyAlias: () => "ghsa",
      idFilter: new Set(["GHSA-in-set-0001"]),
    });
    expect(imported).toBe(1);
    const cves = db.prepare("SELECT cve_id FROM vulnerabilities ORDER BY cve_id").all() as { cve_id: string }[];
    expect(cves.map((r) => r.cve_id)).toEqual(["CVE-2026-1111"]);
  });

  it("without idFilter, all records are written (regression)", async () => {
    const db = sinkDb();
    const sink = new SqliteIngestSink(db);
    const { imported } = await streamOsvZip({
      ctx: ctx(),
      zipPath,
      sink,
      classifyAlias: () => "ghsa",
    });
    expect(imported).toBe(3);
  });
});
