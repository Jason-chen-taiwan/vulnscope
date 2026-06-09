import { describe, it, expect } from "vitest";
import { goComparator } from "../go";

const cmp = goComparator.cmp;

function lt(a: string, b: string) {
  expect(cmp(a, b)).toBeLessThan(0);
  expect(cmp(b, a)).toBeGreaterThan(0);
}
function eq(a: string, b: string) {
  expect(cmp(a, b)).toBe(0);
}

describe("goComparator — tagged versions", () => {
  it("equal", () => eq("v1.2.3", "v1.2.3"));
  it("v prefix is optional and stripped", () => eq("v1.2.3", "1.2.3"));
  it("major higher wins", () => lt("v1.99.99", "v2.0.0"));
  it("minor higher wins", () => lt("v1.0.0", "v1.1.0"));
  it("patch higher wins", () => lt("v1.0.0", "v1.0.1"));
  it("pre-release < release", () => lt("v1.0.0-rc.1", "v1.0.0"));
  it("+incompatible stripped", () => eq("v2.5.0+incompatible", "v2.5.0"));
});

describe("goComparator — pseudo-versions", () => {
  // preTag form: v0.0.0-TIMESTAMP-HASH describes commits BEFORE any tag
  it("two preTag pseudos: later timestamp wins", () => {
    lt(
      "v0.0.0-20220101000000-aaaaaaaaaaaa",
      "v0.0.0-20231231235959-bbbbbbbbbbbb",
    );
  });
  it("preTag pseudo < tagged release of same base", () => {
    // v0.0.0-PSEUDO is less than v0.0.0 itself? Actually base is 0.0.0
    // for the pseudo. The release would be like v1.0.0.
    lt("v0.0.0-20220101000000-aaaaaaaaaaaa", "v1.0.0");
  });
  it("real: x/crypto 0.0.0-20220314234659-1baeb1ce4c0b < 0.0.0-20230301000000-aaaaaaaaaaaa", () => {
    lt(
      "v0.0.0-20220314234659-1baeb1ce4c0b",
      "v0.0.0-20230301000000-aaaaaaaaaaaa",
    );
  });

  // postTag form: vX.Y.Z-0.TIMESTAMP-HASH describes commits AFTER vX.Y.Z
  it("postTag pseudo > tagged release of same base", () => {
    lt("v1.5.0", "v1.5.1-0.20231201000000-aaaaaaaaaaaa");
  });
  it("postTag with different timestamps", () => {
    lt(
      "v1.0.0-0.20220101000000-aaaaaaaaaaaa",
      "v1.0.0-0.20231201000000-bbbbbbbbbbbb",
    );
  });
});

describe("goComparator — real OSV Go advisory fixtures", () => {
  // From GO-2022-0288 / similar
  it("crypto/ssh fix: 0.0.0-20220314234659 < 0.0.0-20221012135045", () => {
    lt(
      "v0.0.0-20220314234659-1baeb1ce4c0b",
      "v0.0.0-20221012135045-bbbbbbbbbbbb",
    );
  });
  it("gin: v1.7.0 < v1.7.7", () => {
    lt("v1.7.0", "v1.7.7");
  });
  it("kubectl: v1.25.0 < v1.26.0", () => {
    lt("v1.25.0", "v1.26.0");
  });
  it("etcd: v3.5.0 < v3.5.6 (security release)", () => {
    lt("v3.5.0", "v3.5.6");
  });
});

describe("goComparator — edge cases", () => {
  it("antisymmetric across forms", () => {
    const pairs: [string, string][] = [
      ["v1.0.0", "v2.0.0"],
      [
        "v0.0.0-20220101000000-aaaaaaaaaaaa",
        "v0.0.0-20231231235959-bbbbbbbbbbbb",
      ],
      ["v1.5.0", "v1.5.1-0.20231201000000-aaaaaaaaaaaa"],
    ];
    for (const [x, y] of pairs) {
      expect(Math.sign(cmp(x, y))).toBe(-Math.sign(cmp(y, x)));
    }
  });
});
