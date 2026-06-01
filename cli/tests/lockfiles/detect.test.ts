import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { detectLockfile, kindFromPath, loadLockfile } from "../../src/lockfiles/detect.js";

describe("detectLockfile", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "vs-detect-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns null when no lockfile present", () => {
    expect(detectLockfile(dir)).toBeNull();
  });

  it("finds package-lock.json", () => {
    writeFileSync(join(dir, "package-lock.json"), "{}");
    expect(detectLockfile(dir)).toEqual({ kind: "npm", path: join(dir, "package-lock.json") });
  });

  it("finds pnpm-lock.yaml", () => {
    writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    expect(detectLockfile(dir)).toEqual({ kind: "pnpm", path: join(dir, "pnpm-lock.yaml") });
  });

  it("prefers pnpm over npm when both exist", () => {
    writeFileSync(join(dir, "package-lock.json"), "{}");
    writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    expect(detectLockfile(dir)?.kind).toBe("pnpm");
  });
});

describe("kindFromPath", () => {
  it("recognizes standard filenames", () => {
    expect(kindFromPath("/foo/package-lock.json")).toBe("npm");
    expect(kindFromPath("/foo/pnpm-lock.yaml")).toBe("pnpm");
    expect(kindFromPath("/foo/npm-shrinkwrap.json")).toBe("npm");
  });
  it("returns null for unknown filenames", () => {
    expect(kindFromPath("/foo/yarn.lock")).toBeNull();
    expect(kindFromPath("/foo/bun.lockb")).toBeNull();
  });
});

describe("loadLockfile", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "vs-load-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("loads a directory by auto-detecting", () => {
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/foo": { version: "1.0.0" } },
      }),
    );
    const res = loadLockfile(dir);
    expect(res.kind).toBe("npm");
    expect(res.packages).toEqual([{ ecosystem: "npm", name: "foo", version: "1.0.0" }]);
  });

  it("loads an explicit file", () => {
    const p = join(dir, "package-lock.json");
    writeFileSync(
      p,
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/bar": { version: "2.0.0" } },
      }),
    );
    const res = loadLockfile(p);
    expect(res.packages).toEqual([{ ecosystem: "npm", name: "bar", version: "2.0.0" }]);
  });

  it("throws when path doesn't exist", () => {
    expect(() => loadLockfile(join(dir, "nope"))).toThrow(/not found/);
  });
});
