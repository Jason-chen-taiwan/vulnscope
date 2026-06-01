import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parsePnpmLockfile, parsePackagesKey } from "../../src/lockfiles/pnpm.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixture = readFileSync(join(__dirname, "../fixtures/pnpm-lock.simple.yaml"), "utf8");

describe("parsePackagesKey", () => {
  it("handles bare name@version", () => {
    expect(parsePackagesKey("lodash@4.17.20")).toEqual({ name: "lodash", version: "4.17.20" });
  });

  it("strips leading slash (pre-v9 form)", () => {
    expect(parsePackagesKey("/lodash@4.17.20")).toEqual({ name: "lodash", version: "4.17.20" });
  });

  it("handles scoped names with the last-@ rule", () => {
    expect(parsePackagesKey("@types/node@22.10.0")).toEqual({
      name: "@types/node",
      version: "22.10.0",
    });
  });

  it("strips peer-deps suffix", () => {
    expect(parsePackagesKey("react-dom@19.0.0(react@19.0.0)")).toEqual({
      name: "react-dom",
      version: "19.0.0",
    });
  });

  it("strips multiple peer-deps", () => {
    expect(parsePackagesKey("some-pkg@1.0.0(a@1.0.0)(b@2.0.0)")).toEqual({
      name: "some-pkg",
      version: "1.0.0",
    });
  });

  it("rejects file: and link: pseudo-versions", () => {
    expect(parsePackagesKey("foo@file:./local")).toBeNull();
    expect(parsePackagesKey("foo@link:../sibling")).toBeNull();
  });

  it("rejects scope-only keys", () => {
    expect(parsePackagesKey("@scope")).toBeNull();
  });
});

describe("parsePnpmLockfile (fixture)", () => {
  it("extracts plain + scoped + peer-dep keys", () => {
    const pkgs = parsePnpmLockfile(fixture);
    const map = new Map(pkgs.map((p) => [p.name, p.version]));
    expect(map.get("lodash")).toBe("4.17.20");
    expect(map.get("express")).toBe("4.18.0");
    expect(map.get("@scope/pkg")).toBe("1.0.0");
    expect(map.get("react-dom")).toBe("19.0.0");
    expect(map.get("@types/node")).toBe("22.10.0");
    expect(map.get("some-pkg")).toBe("1.0.0");
  });

  it("tags every package as ecosystem 'npm'", () => {
    const pkgs = parsePnpmLockfile(fixture);
    expect(pkgs.every((p) => p.ecosystem === "npm")).toBe(true);
  });

  it("rejects non-YAML input", () => {
    expect(() => parsePnpmLockfile(":\n:\n:")).toThrow();
  });

  it("rejects YAML without packages map", () => {
    expect(() => parsePnpmLockfile("lockfileVersion: '9.0'\nimporters: {}")).toThrow(
      /missing `packages`/,
    );
  });
});
