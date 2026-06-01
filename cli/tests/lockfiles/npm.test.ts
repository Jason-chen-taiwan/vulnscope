import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseNpmLockfile } from "../../src/lockfiles/npm.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixture = readFileSync(join(__dirname, "../fixtures/package-lock.simple.json"), "utf8");

describe("parseNpmLockfile", () => {
  it("extracts top-level + nested + scoped packages", () => {
    const pkgs = parseNpmLockfile(fixture);
    const map = new Map(pkgs.map((p) => [p.name, p.version]));
    expect(map.get("lodash")).toBe("4.17.20");
    expect(map.get("express")).toBe("4.18.0");
    expect(map.get("@scope/pkg")).toBe("1.0.0");
    expect(map.get("qs")).toBe("6.11.0");
  });

  it("dedupes packages appearing at multiple nesting depths", () => {
    const pkgs = parseNpmLockfile(fixture);
    const lodashCount = pkgs.filter((p) => p.name === "lodash").length;
    expect(lodashCount).toBe(1);
  });

  it("skips workspace symlinks (link: true)", () => {
    const pkgs = parseNpmLockfile(fixture);
    expect(pkgs.find((p) => p.name === "local-link")).toBeUndefined();
  });

  it("skips the root project entry (key '')", () => {
    const pkgs = parseNpmLockfile(fixture);
    expect(pkgs.find((p) => p.name === "demo")).toBeUndefined();
  });

  it("tags every package as ecosystem 'npm'", () => {
    const pkgs = parseNpmLockfile(fixture);
    expect(pkgs.every((p) => p.ecosystem === "npm")).toBe(true);
  });

  it("rejects lockfileVersion 1 with a clear error", () => {
    const v1 = JSON.stringify({ lockfileVersion: 1, dependencies: {} });
    expect(() => parseNpmLockfile(v1)).toThrow(/v2 or v3/);
  });

  it("rejects non-JSON input", () => {
    expect(() => parseNpmLockfile("not json")).toThrow(/not valid JSON/);
  });
});
