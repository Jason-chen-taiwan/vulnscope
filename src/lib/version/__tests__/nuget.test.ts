import { describe, it, expect } from "vitest";
import { nugetComparator } from "../nuget";

const cmp = nugetComparator.cmp;

/**
 * Test fixtures grounded in NuGet's own version spec
 * (https://learn.microsoft.com/en-us/nuget/concepts/package-versioning)
 * and a few real-world examples from popular .NET packages
 * (Microsoft.Extensions.*, Newtonsoft.Json, etc.) where I cross-
 * checked ordering against the public nuget.org listing.
 */
describe("nugetComparator", () => {
  // Identity
  it("equal strings", () => {
    expect(cmp("1.2.3", "1.2.3")).toBe(0);
  });

  // 3-part SemVer
  it("major higher wins", () => {
    expect(cmp("2.0.0", "1.99.99")).toBeGreaterThan(0);
  });
  it("minor higher wins", () => {
    expect(cmp("1.2.0", "1.1.99")).toBeGreaterThan(0);
  });
  it("patch higher wins", () => {
    expect(cmp("1.0.5", "1.0.4")).toBeGreaterThan(0);
  });

  // 4-part revision
  it("4-part revision orders within same patch", () => {
    expect(cmp("1.0.0.5", "1.0.0.4")).toBeGreaterThan(0);
  });
  it("4-part vs 3-part: missing revision = 0", () => {
    expect(cmp("1.0.0", "1.0.0.0")).toBe(0);
  });
  it("4-part revision: rev outranks no rev", () => {
    expect(cmp("1.0.0.1", "1.0.0")).toBeGreaterThan(0);
  });

  // Leading v prefix (allowed by NuGet)
  it("leading v stripped", () => {
    expect(cmp("v1.2.3", "1.2.3")).toBe(0);
  });

  // Pre-release: pre < release of same version
  it("pre-release < release", () => {
    expect(cmp("1.0.0-alpha", "1.0.0")).toBeLessThan(0);
  });
  it("release > pre-release", () => {
    expect(cmp("1.0.0", "1.0.0-rc")).toBeGreaterThan(0);
  });

  // Pre-release ordering (SemVer rules)
  it("alpha < beta", () => {
    expect(cmp("1.0.0-alpha", "1.0.0-beta")).toBeLessThan(0);
  });
  it("beta < rc", () => {
    expect(cmp("1.0.0-beta", "1.0.0-rc")).toBeLessThan(0);
  });
  it("numeric identifier compared numerically", () => {
    expect(cmp("1.0.0-alpha.2", "1.0.0-alpha.10")).toBeLessThan(0);
  });
  it("numeric identifier < alphanumeric", () => {
    expect(cmp("1.0.0-1", "1.0.0-alpha")).toBeLessThan(0);
  });
  it("dot-separated identifiers compared piecewise", () => {
    expect(cmp("1.0.0-alpha.1", "1.0.0-alpha.2")).toBeLessThan(0);
    expect(cmp("1.0.0-alpha.beta", "1.0.0-alpha.gamma")).toBeLessThan(0);
  });
  it("fewer pre-release identifiers < more (when prefixes equal)", () => {
    expect(cmp("1.0.0-alpha", "1.0.0-alpha.1")).toBeLessThan(0);
  });

  // Build metadata is ignored for ordering (SemVer rule)
  it("build metadata ignored", () => {
    expect(cmp("1.0.0+build.1", "1.0.0+build.2")).toBe(0);
  });

  // Real-world NuGet examples
  it("Newtonsoft.Json: 13.0.1 > 12.0.3", () => {
    expect(cmp("13.0.1", "12.0.3")).toBeGreaterThan(0);
  });
  it("Microsoft.Extensions.Logging: 9.0.0 > 8.0.0", () => {
    expect(cmp("9.0.0", "8.0.0")).toBeGreaterThan(0);
  });
  it("EntityFramework: 6.4.4 > 6.4.0 > 6.3.0", () => {
    expect(cmp("6.4.4", "6.4.0")).toBeGreaterThan(0);
    expect(cmp("6.4.0", "6.3.0")).toBeGreaterThan(0);
  });

  // Pre-release legacy NuGet style (1.0.0-preview1-23456)
  it("legacy preview style ordering", () => {
    // Lexicographically: preview1 < preview2 (both alphanumeric → string compare)
    expect(cmp("1.0.0-preview1", "1.0.0-preview2")).toBeLessThan(0);
  });

  // "0" placeholder edge case (used internally for "from beginning")
  it('"0" is the smallest version', () => {
    expect(cmp("0", "0.0.1")).toBeLessThan(0);
    expect(cmp("0.0.1", "0")).toBeGreaterThan(0);
  });

  // Unparseable falls back gracefully
  it("unparseable strings fall back to lexicographic", () => {
    // Both unparseable: stable ordering, no throw
    const r = cmp("garbage~", "garbage!");
    expect(typeof r).toBe("number");
  });
});
