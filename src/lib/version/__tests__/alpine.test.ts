import { describe, it, expect } from "vitest";
import { alpineComparator } from "../alpine";

const cmp = alpineComparator.cmp;

function lt(a: string, b: string) {
  expect(cmp(a, b)).toBeLessThan(0);
  expect(cmp(b, a)).toBeGreaterThan(0);
}
function eq(a: string, b: string) {
  expect(cmp(a, b)).toBe(0);
}

/**
 * Cross-checked against apk version output:
 *   apk version -t "$A" "$B"  # prints <, =, or >
 * Several fixtures are real Alpine package versions taken from
 * pkgs.alpinelinux.org.
 */

describe("alpineComparator", () => {
  it("identical", () => eq("1.2.3", "1.2.3"));
  it("major higher", () => lt("1.99.99", "2.0.0"));
  it("digit run as integer", () => lt("1.9", "1.10"));
  it("revision -rN higher wins", () => lt("1.2.3-r0", "1.2.3-r1"));
  it("revision compared numerically (-r9 < -r10)", () => {
    lt("1.2.3-r9", "1.2.3-r10");
  });
  it("trailing letter > no letter", () => {
    lt("1.2.3", "1.2.3a");
  });
  it("letter ordering: a < b", () => lt("1.2.3a", "1.2.3b"));
  it("_alpha < release", () => lt("1.2.3_alpha1", "1.2.3"));
  it("_beta < _rc < release", () => {
    lt("1.2.3_beta1", "1.2.3_rc1");
    lt("1.2.3_rc1", "1.2.3");
  });
  it("_alpha1 < _alpha2", () => lt("1.2.3_alpha1", "1.2.3_alpha2"));
  it("_pre < _rc", () => lt("1.2.3_pre1", "1.2.3_rc1"));
  it("_p (patch) > release", () => lt("1.2.3", "1.2.3_p1"));
  it("_git suffix between release and patch", () => {
    lt("1.2.3", "1.2.3_git20230101");
  });

  // Real Alpine package versions
  it("real: openssl 1.1.1n-r0 < 1.1.1u-r0", () => {
    lt("1.1.1n-r0", "1.1.1u-r0");
  });
  it("real: openssl 3.0.7-r2 < 3.0.10-r0", () => {
    lt("3.0.7-r2", "3.0.10-r0");
  });
  it("real: alpine-baselayout 3.4.0-r0 < 3.4.3-r1", () => {
    lt("3.4.0-r0", "3.4.3-r1");
  });
  it("real: curl 7.83.1-r3 < 7.88.1-r1", () => {
    lt("7.83.1-r3", "7.88.1-r1");
  });

  it("antisymmetric", () => {
    const pairs: [string, string][] = [
      ["1.2.3", "1.2.4"],
      ["1.2.3_alpha1", "1.2.3"],
      ["1.2.3-r0", "1.2.3-r1"],
      ["1.2.3", "1.2.3_p1"],
    ];
    for (const [x, y] of pairs) {
      expect(Math.sign(cmp(x, y))).toBe(-Math.sign(cmp(y, x)));
    }
  });
});
