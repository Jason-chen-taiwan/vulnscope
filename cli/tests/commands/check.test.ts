import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runCheck } from "../../src/commands/check.js";
import type { VersionCheckResult } from "../../src/api.js";

function envelope(data: VersionCheckResult[]) {
  return {
    data,
    meta: { count: data.length, unknown_count: 0, vulnerable_count: data.filter((d) => d.is_vulnerable).length },
    errors: null,
  };
}

function mockFetchOnce(payload: unknown, status = 200) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } })),
  );
}

function capturedIO() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { out: (s: string) => out.push(s), err: (s: string) => err.push(s) },
    out,
    err,
  };
}

describe("runCheck (integration)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "vs-check-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    vi.unstubAllGlobals();
  });

  it("exits 0 when no vulnerabilities are found", async () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/clean-pkg": { version: "1.0.0" } },
      }),
    );
    mockFetchOnce(
      envelope([
        {
          package: { ecosystem: "npm", name: "clean-pkg" },
          version: "1.0.0",
          is_vulnerable: false,
          affected_by: [],
          recommended_version: null,
        },
      ]),
    );
    const { io, out } = capturedIO();
    const code = await runCheck({ path: dir, noColor: true }, io);
    expect(code).toBe(0);
    expect(out.join("\n")).toContain("No known vulnerabilities");
  });

  it("exits 1 when vulnerabilities are found", async () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/lodash": { version: "4.17.20" } },
      }),
    );
    mockFetchOnce(
      envelope([
        {
          package: { ecosystem: "npm", name: "lodash" },
          version: "4.17.20",
          is_vulnerable: true,
          affected_by: [
            {
              cve_id: "CVE-2021-23337",
              severity: "HIGH",
              base_score: 7.2,
              kev: false,
              epss_score: 0.04,
              fixed_in: "4.17.21",
              summary: "Command Injection in lodash",
            },
          ],
          recommended_version: "4.17.21",
        },
      ]),
    );
    const { io, out } = capturedIO();
    const code = await runCheck({ path: dir, noColor: true }, io);
    expect(code).toBe(1);
    const stdout = out.join("\n");
    expect(stdout).toContain("CVE-2021-23337");
    expect(stdout).toContain("lodash");
    expect(stdout).toContain("Found 1 vulnerabilities");
  });

  it("--exit-zero suppresses exit-1 even with findings", async () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/lodash": { version: "4.17.20" } },
      }),
    );
    mockFetchOnce(
      envelope([
        {
          package: { ecosystem: "npm", name: "lodash" },
          version: "4.17.20",
          is_vulnerable: true,
          affected_by: [
            { cve_id: "CVE-X", severity: "HIGH", base_score: 7, kev: false,
              epss_score: null, fixed_in: null, summary: null },
          ],
          recommended_version: null,
        },
      ]),
    );
    const { io } = capturedIO();
    const code = await runCheck({ path: dir, exitZero: true, noColor: true }, io);
    expect(code).toBe(0);
  });

  it("--severity filter excludes lower severities", async () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/pkg": { version: "1.0.0" } },
      }),
    );
    mockFetchOnce(
      envelope([
        {
          package: { ecosystem: "npm", name: "pkg" },
          version: "1.0.0",
          is_vulnerable: true,
          affected_by: [
            { cve_id: "CVE-LOW", severity: "LOW", base_score: 3, kev: false, epss_score: null, fixed_in: null, summary: null },
          ],
          recommended_version: null,
        },
      ]),
    );
    const { io, out } = capturedIO();
    const code = await runCheck({ path: dir, severity: "CRITICAL,HIGH", noColor: true }, io);
    expect(code).toBe(0); // LOW filtered out → 0 findings
    expect(out.join("\n")).toContain("No known vulnerabilities");
  });

  it("--ignore suppresses specific CVE IDs", async () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/p": { version: "1.0.0" } },
      }),
    );
    mockFetchOnce(
      envelope([
        {
          package: { ecosystem: "npm", name: "p" },
          version: "1.0.0",
          is_vulnerable: true,
          affected_by: [
            { cve_id: "CVE-IGNORE-ME", severity: "HIGH", base_score: 7, kev: false, epss_score: null, fixed_in: null, summary: null },
          ],
          recommended_version: null,
        },
      ]),
    );
    const { io } = capturedIO();
    const code = await runCheck(
      { path: dir, ignore: ["CVE-IGNORE-ME"], noColor: true },
      io,
    );
    expect(code).toBe(0);
  });

  it("--json emits parseable JSON with summary", async () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/p": { version: "1.0.0" } },
      }),
    );
    mockFetchOnce(
      envelope([
        {
          package: { ecosystem: "npm", name: "p" },
          version: "1.0.0",
          is_vulnerable: false,
          affected_by: [],
          recommended_version: null,
        },
      ]),
    );
    const { io, out } = capturedIO();
    await runCheck({ path: dir, json: true, noColor: true }, io);
    const json = JSON.parse(out.join("\n"));
    expect(json.schema_version).toBe(1);
    expect(json.summary.total_packages).toBe(1);
    expect(Array.isArray(json.results)).toBe(true);
  });

  it("exits 2 on parse error", async () => {
    writeFileSync(join(dir, "package-lock.json"), "not json");
    const { io, err } = capturedIO();
    const code = await runCheck({ path: dir, noColor: true }, io);
    expect(code).toBe(2);
    expect(err.join("\n")).toContain("not valid JSON");
  });

  it("exits 2 on API error", async () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/p": { version: "1.0.0" } },
      }),
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ data: null, meta: null, errors: [{ code: "X", message: "oops" }] }), {
          status: 500,
        }),
      ),
    );
    const { io, err } = capturedIO();
    const code = await runCheck({ path: dir, noColor: true }, io);
    expect(code).toBe(2);
    expect(err.join("\n")).toContain("oops");
  });

  it("exits 2 when lockfile is missing", async () => {
    const { io, err } = capturedIO();
    const code = await runCheck({ path: dir, noColor: true }, io);
    expect(code).toBe(2);
    expect(err.join("\n")).toMatch(/no lockfile found/i);
  });
});
