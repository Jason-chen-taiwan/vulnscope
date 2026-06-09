import { describe, it, expect } from "vitest";
import { composerComparator } from "../composer";

const cmp = composerComparator.cmp;

function lt(a: string, b: string) {
  expect(cmp(a, b)).toBeLessThan(0);
  expect(cmp(b, a)).toBeGreaterThan(0);
}
function eq(a: string, b: string) {
  expect(cmp(a, b)).toBe(0);
}

describe("composerComparator", () => {
  it("identical", () => eq("1.2.3", "1.2.3"));
  it("v prefix stripped", () => eq("v1.2.3", "1.2.3"));
  it("trailing zeros normalize", () => {
    eq("1.0.0", "1");
    eq("1.5.0", "1.5");
  });
  it("major higher wins", () => lt("1.99.99", "2.0.0"));
  it("digit run integer", () => lt("1.9", "1.10"));
  it("stability rank: dev < alpha < beta < rc < stable", () => {
    lt("1.0.0-dev", "1.0.0-alpha");
    lt("1.0.0-alpha", "1.0.0-beta");
    lt("1.0.0-beta", "1.0.0-rc");
    lt("1.0.0-rc", "1.0.0");
  });
  it("a == alpha alias", () => eq("1.0.0-a", "1.0.0-alpha"));
  it("b == beta alias", () => eq("1.0.0-b", "1.0.0-beta"));
  it("numbered prereleases", () => lt("1.0.0-rc1", "1.0.0-rc2"));
  it("build metadata stripped", () => eq("1.0.0+build.1", "1.0.0+build.2"));
  it("patch outranks release int", () => lt("1.0.0", "1.0.0-patch"));
  it("real: laravel/framework 8.83.27 < 9.0.0", () => {
    lt("8.83.27", "9.0.0");
  });
  it("real: symfony/http-foundation 4.4.46 < 5.4.13", () => {
    lt("4.4.46", "5.4.13");
  });
  it("real: drupal/core 9.5.10 < 10.0.0", () => lt("9.5.10", "10.0.0"));
  it("real: monolog 2.8.0 < 3.0.0", () => lt("2.8.0", "3.0.0"));
  it("antisymmetric", () => {
    const pairs: [string, string][] = [
      ["1.0", "2.0"],
      ["1.0-alpha", "1.0-beta"],
      ["1.0-rc", "1.0"],
    ];
    for (const [x, y] of pairs) {
      expect(Math.sign(cmp(x, y))).toBe(-Math.sign(cmp(y, x)));
    }
  });
});
