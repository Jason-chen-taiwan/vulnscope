import { describe, it, expect } from "vitest";
import { rubygemsComparator } from "../rubygems";

const cmp = rubygemsComparator.cmp;

/**
 * Cross-checked against Ruby's Gem::Version.create("a") <=> Gem::Version.create("b").
 */

function lt(a: string, b: string) {
  expect(cmp(a, b)).toBeLessThan(0);
  expect(cmp(b, a)).toBeGreaterThan(0);
}
function eq(a: string, b: string) {
  expect(cmp(a, b)).toBe(0);
}

describe("rubygemsComparator", () => {
  it("equal: 1.0.0 == 1.0 == 1", () => {
    eq("1.0.0", "1");
    eq("1.0", "1");
  });
  it("major higher wins", () => lt("1.99.99", "2.0.0"));
  it("digit run integer (1.10 > 1.9)", () => lt("1.9", "1.10"));
  it("prerelease string < release", () => {
    lt("1.0.0.beta1", "1.0.0");
    lt("1.0.0.rc1", "1.0.0");
  });
  it("prerelease ordering by lex within same prefix", () => {
    lt("1.0.0.alpha", "1.0.0.beta");
    lt("1.0.0.beta", "1.0.0.rc");
  });
  it("alpha1 vs alpha2 numeric", () => lt("1.0.0.alpha1", "1.0.0.alpha2"));
  it("dash and dot interchangeable", () => eq("1.0.0-rc1", "1.0.0.rc1"));
  it("trailing zeros normalize", () => {
    eq("1.0.0.0", "1");
    eq("1.5", "1.5.0");
  });
  it("real: rails 7.0.4.3 > 7.0.4", () => lt("7.0.4", "7.0.4.3"));
  it("real: rack 2.2.6 < 2.2.6.4 (security release)", () => {
    lt("2.2.6", "2.2.6.4");
  });
  it("real: nokogiri 1.13.10 < 1.14.0", () => lt("1.13.10", "1.14.0"));
  it("real: devise 4.8.1 < 4.9.0", () => lt("4.8.1", "4.9.0"));
  it("real: actionpack 7.0.4 < 7.1.0", () => lt("7.0.4", "7.1.0"));
  it("antisymmetric", () => {
    const pairs: [string, string][] = [
      ["1.0", "2.0"],
      ["1.0.0.beta1", "1.0.0"],
      ["1.0.0.rc1", "1.0.0.rc2"],
    ];
    for (const [x, y] of pairs) {
      expect(Math.sign(cmp(x, y))).toBe(-Math.sign(cmp(y, x)));
    }
  });
});
