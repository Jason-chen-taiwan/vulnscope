import { describe, it, expect } from "vitest";
import { hexComparator } from "../hex";

const cmp = hexComparator.cmp;

describe("hexComparator (strict SemVer)", () => {
  it("equal", () => expect(cmp("1.2.3", "1.2.3")).toBe(0));
  it("major higher wins", () => expect(cmp("1.99.99", "2.0.0")).toBeLessThan(0));
  it("minor higher wins", () => expect(cmp("1.0.0", "1.1.0")).toBeLessThan(0));
  it("patch higher wins", () => expect(cmp("1.0.0", "1.0.1")).toBeLessThan(0));
  it("pre-release < release", () => {
    expect(cmp("1.0.0-rc.1", "1.0.0")).toBeLessThan(0);
  });
  it("pre-release ordering", () => {
    expect(cmp("1.0.0-alpha", "1.0.0-beta")).toBeLessThan(0);
    expect(cmp("1.0.0-rc.1", "1.0.0-rc.2")).toBeLessThan(0);
  });
  it("build metadata ignored", () => {
    expect(cmp("1.0.0+build.1", "1.0.0+build.2")).toBe(0);
  });
  it("digit run integer (1.10 > 1.9)", () => {
    expect(cmp("1.9.0", "1.10.0")).toBeLessThan(0);
  });
  it("real: phoenix 1.6.16 < 1.7.0", () => {
    expect(cmp("1.6.16", "1.7.0")).toBeLessThan(0);
  });
  it("real: ecto 3.9.5 < 3.10.0", () => {
    expect(cmp("3.9.5", "3.10.0")).toBeLessThan(0);
  });
  it("real: plug 1.13.6 < 1.14.0", () => {
    expect(cmp("1.13.6", "1.14.0")).toBeLessThan(0);
  });
  it("strict: invalid version falls back to lex", () => {
    // Hex won't accept "1.0" (not 3-part) — both unparseable
    const r = cmp("1.0", "1.0");
    expect(r).toBe(0);
  });
  it("antisymmetric", () => {
    expect(Math.sign(cmp("1.0.0", "2.0.0"))).toBe(
      -Math.sign(cmp("2.0.0", "1.0.0")),
    );
  });
});
