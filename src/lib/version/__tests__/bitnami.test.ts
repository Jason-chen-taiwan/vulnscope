import { describe, it, expect } from "vitest";
import { bitnamiComparator } from "../bitnami";

const cmp = bitnamiComparator.cmp;

function lt(a: string, b: string) {
  expect(cmp(a, b)).toBeLessThan(0);
  expect(cmp(b, a)).toBeGreaterThan(0);
}

describe("bitnamiComparator", () => {
  it("identical", () => expect(cmp("8.0.30-debian-11-r12", "8.0.30-debian-11-r12")).toBe(0));
  it("upstream major wins over distro", () => {
    lt("8.0.30-debian-11-r1", "9.0.0-debian-11-r1");
  });
  it("upstream minor wins", () => {
    lt("8.0.30-debian-11-r1", "8.1.0-debian-11-r1");
  });
  it("upstream patch wins", () => {
    lt("8.0.30-debian-11-r1", "8.0.31-debian-11-r1");
  });
  it("same upstream + distro: revision orders", () => {
    lt("8.0.30-debian-11-r1", "8.0.30-debian-11-r2");
  });
  it("revision compared numerically (r10 > r9)", () => {
    lt("8.0.30-debian-11-r9", "8.0.30-debian-11-r10");
  });
  it("plain semver without distro suffix", () => {
    lt("8.0.30", "8.0.31");
  });
  it("revision-only difference parses", () => {
    lt("8.0.30-r1", "8.0.30-r2");
  });
  it("real: postgres 15.4.0-debian-11-r12 < 15.5.0-debian-11-r0", () => {
    lt("15.4.0-debian-11-r12", "15.5.0-debian-11-r0");
  });
  it("real: redis 7.2.3-debian-11-r0 < 7.2.4-debian-11-r0", () => {
    lt("7.2.3-debian-11-r0", "7.2.4-debian-11-r0");
  });
  it("real: nginx 1.25.3-debian-11-r0 < 1.25.4-debian-11-r0", () => {
    lt("1.25.3-debian-11-r0", "1.25.4-debian-11-r0");
  });
  it("different distro version (debian-10 vs debian-11) — same upstream", () => {
    // lex on distro string: "debian-10" < "debian-11"
    const r = cmp("8.0.30-debian-10-r1", "8.0.30-debian-11-r1");
    expect(r).toBeLessThan(0);
  });
});
