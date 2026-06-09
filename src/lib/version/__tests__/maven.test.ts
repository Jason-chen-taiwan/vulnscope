import { describe, it, expect } from "vitest";
import { mavenComparator } from "../maven";

const cmp = mavenComparator.cmp;

/**
 * Test fixtures grounded in Maven's ComparableVersion behavior. The
 * reference behavior is documented + asserted in Maven's own test
 * suite at:
 *   maven-artifact/src/test/java/org/apache/maven/artifact/versioning/ComparableVersionTest.java
 *
 * Several "surprising" cases here (e.g. 1.0.0 == 1 == 1.0) come
 * straight from that suite. They look wrong at first glance but
 * they're how Maven itself sorts versions, so this is what users
 * (and OSV's Maven advisories) actually mean.
 */

function lt(a: string, b: string) {
  expect(cmp(a, b)).toBeLessThan(0);
  expect(cmp(b, a)).toBeGreaterThan(0);
}
function eq(a: string, b: string) {
  expect(cmp(a, b)).toBe(0);
  expect(cmp(b, a)).toBe(0);
}

describe("mavenComparator — numeric ordering", () => {
  it("1.0 < 1.1", () => lt("1.0", "1.1"));
  it("2.0 > 1.99", () => lt("1.99", "2.0"));
  it("digit run as integer (1.10 > 1.9)", () => lt("1.9", "1.10"));
  it("4-part vs 3-part: trailing zeros normalize away", () => {
    eq("1.0.0", "1");
    eq("1.0", "1");
    eq("1.0.0.0", "1");
  });
  it("explicit zero patch == implicit", () => eq("1.0.0", "1.0"));
});

describe("mavenComparator — qualifier ordering", () => {
  it("alpha < beta < milestone < rc < snapshot < release < sp", () => {
    lt("1.0-alpha", "1.0-beta");
    lt("1.0-beta", "1.0-milestone");
    lt("1.0-milestone", "1.0-rc");
    lt("1.0-rc", "1.0-snapshot");
    lt("1.0-snapshot", "1.0");
    lt("1.0", "1.0-sp");
  });
  it("aliases: a == alpha, b == beta, m == milestone, cr == rc", () => {
    eq("1.0-a", "1.0-alpha");
    eq("1.0-b", "1.0-beta");
    eq("1.0-m", "1.0-milestone");
    eq("1.0-cr", "1.0-rc");
  });
  it("ga / final / release all equal to bare version", () => {
    eq("1.0-ga", "1.0");
    eq("1.0-final", "1.0");
    eq("1.0-release", "1.0");
  });
  it("known qualifier < unknown qualifier", () => {
    lt("1.0-rc", "1.0-zeta");
  });
  it("unknown qualifiers compared alphabetically", () => {
    lt("1.0-aardvark", "1.0-zebra");
  });
});

describe("mavenComparator — qualifier with number", () => {
  it("alpha1 < alpha2 (string+number → split into sublist)", () => {
    lt("1.0-alpha1", "1.0-alpha2");
  });
  it("alpha-1 == alpha1 (Maven treats `-` and char-class boundary equally)", () => {
    eq("1.0-alpha1", "1.0-alpha-1");
  });
  it("rc1 < rc2 < snapshot", () => {
    lt("1.0-rc1", "1.0-rc2");
    lt("1.0-rc2", "1.0-snapshot");
  });
});

describe("mavenComparator — SNAPSHOT case insensitivity", () => {
  it("SNAPSHOT (uppercase) == snapshot", () => {
    eq("1.0-SNAPSHOT", "1.0-snapshot");
  });
  it("1.0-SNAPSHOT < 1.0", () => lt("1.0-SNAPSHOT", "1.0"));
});

describe("mavenComparator — real package versions", () => {
  it("log4j-core 2.14.1 < 2.17.0 (the famous CVE-2021-44228 fix)", () => {
    lt("2.14.1", "2.17.0");
  });
  it("log4j-core 2.16.0 < 2.17.0 < 2.17.1", () => {
    lt("2.16.0", "2.17.0");
    lt("2.17.0", "2.17.1");
  });
  it("spring-core 5.3.20 < 5.3.21", () => lt("5.3.20", "5.3.21"));
  it("spring-core 5.3.31 < 6.0.0", () => lt("5.3.31", "6.0.0"));
  it("guava 31.0.1-jre < 32.0.0-jre", () => {
    lt("31.0.1-jre", "32.0.0-jre");
  });
  it("jackson-databind 2.13.4.1 (the security patch) > 2.13.4", () => {
    lt("2.13.4", "2.13.4.1");
  });
});

describe("mavenComparator — edge cases", () => {
  it("antisymmetric", () => {
    const pairs: [string, string][] = [
      ["1.0", "2.0"],
      ["1.0-alpha", "1.0-beta"],
      ["1.0", "1.0-sp"],
    ];
    for (const [x, y] of pairs) {
      expect(Math.sign(cmp(x, y))).toBe(-Math.sign(cmp(y, x)));
    }
  });
});
