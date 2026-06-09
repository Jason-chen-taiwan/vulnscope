import { describe, it, expect } from "vitest";
import { hackageComparator } from "../hackage";

const cmp = hackageComparator.cmp;

function lt(a: string, b: string) {
  expect(cmp(a, b)).toBeLessThan(0);
  expect(cmp(b, a)).toBeGreaterThan(0);
}

describe("hackageComparator (PVP)", () => {
  it("identical", () => expect(cmp("1.2.3.4", "1.2.3.4")).toBe(0));
  it("trailing zero is significant... no wait, PVP treats missing as 0", () => {
    // 1.0 and 1.0.0.0 both compare positions as integers, missing = 0
    expect(cmp("1.0", "1.0.0.0")).toBe(0);
  });
  it("major higher", () => lt("1.0", "2.0"));
  it("minor higher", () => lt("1.0", "1.1"));
  it("third position", () => lt("1.0.0", "1.0.1"));
  it("digit run integer (1.10 > 1.9)", () => lt("1.9", "1.10"));
  it("any number of segments", () => {
    lt("1.0.0.0.1", "1.0.0.0.2");
    lt("1.0", "1.0.0.0.1"); // adding more segments past 1.0
  });
  it("real: aeson 2.1.0.0 < 2.1.1.0", () => lt("2.1.0.0", "2.1.1.0"));
  it("real: text 1.2.5.0 < 2.0.0.0", () => lt("1.2.5.0", "2.0.0.0"));
  it("real: lens 5.2 < 5.2.1", () => lt("5.2", "5.2.1"));
  it("real: conduit 1.3.4 < 1.3.5", () => lt("1.3.4", "1.3.5"));
  it("non-numeric → lex fallback", () => {
    // PVP doesn't have qualifiers; "1.0-rc1" isn't valid PVP
    const r = cmp("1.0-rc1", "1.0");
    expect(typeof r).toBe("number");
  });
});
