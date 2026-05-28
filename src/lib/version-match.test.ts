import { describe, it, expect } from "vitest";
import { isAffected, describeRange } from "./version-match";
import type { OsvRange } from "./osv";

const SEMVER = "SEMVER" as const;
const ECOSYSTEM = "ECOSYSTEM" as const;

function range(events: { introduced?: string; fixed?: string; last_affected?: string; limit?: string }[]): OsvRange {
  return { type: SEMVER, events } as OsvRange;
}

function pypiRange(events: { introduced?: string; fixed?: string; last_affected?: string; limit?: string }[]): OsvRange {
  return { type: ECOSYSTEM, events } as OsvRange;
}

describe("isAffected — npm semver", () => {
  it("introduced + fixed: queried below introduced is clean", () => {
    const r = range([{ introduced: "4.0.0" }, { fixed: "4.17.21" }]);
    expect(isAffected("3.10.0", [r], null, "npm").affected).toBe(false);
  });

  it("introduced + fixed: queried within range is affected", () => {
    const r = range([{ introduced: "4.0.0" }, { fixed: "4.17.21" }]);
    expect(isAffected("4.17.20", [r], null, "npm").affected).toBe(true);
  });

  it("introduced + fixed: queried at fixed boundary is NOT affected (fixed is exclusive)", () => {
    const r = range([{ introduced: "4.0.0" }, { fixed: "4.17.21" }]);
    expect(isAffected("4.17.21", [r], null, "npm").affected).toBe(false);
  });

  it("introduced + fixed: queried above fixed is clean", () => {
    const r = range([{ introduced: "4.0.0" }, { fixed: "4.17.21" }]);
    expect(isAffected("5.0.0", [r], null, "npm").affected).toBe(false);
  });

  it("introduced from 0: all versions affected up to fixed", () => {
    const r = range([{ introduced: "0" }, { fixed: "1.0.0" }]);
    expect(isAffected("0.0.1", [r], null, "npm").affected).toBe(true);
    expect(isAffected("0.99.99", [r], null, "npm").affected).toBe(true);
    expect(isAffected("1.0.0", [r], null, "npm").affected).toBe(false);
  });

  it("last_affected inclusive: queried equal to last_affected is affected", () => {
    const r = range([{ introduced: "2.0.0" }, { last_affected: "2.5.0" }]);
    expect(isAffected("2.5.0", [r], null, "npm").affected).toBe(true);
    expect(isAffected("2.5.1", [r], null, "npm").affected).toBe(false);
  });

  it("limit treated like fixed (exclusive upper bound)", () => {
    const r = range([{ introduced: "1.0.0" }, { limit: "3.0.0" }]);
    expect(isAffected("2.9.9", [r], null, "npm").affected).toBe(true);
    expect(isAffected("3.0.0", [r], null, "npm").affected).toBe(false);
  });

  it("multiple ranges OR'd together", () => {
    const r1 = range([{ introduced: "1.0.0" }, { fixed: "1.5.0" }]);
    const r2 = range([{ introduced: "2.0.0" }, { fixed: "2.5.0" }]);
    expect(isAffected("1.2.0", [r1, r2], null, "npm").affected).toBe(true);
    expect(isAffected("2.4.0", [r1, r2], null, "npm").affected).toBe(true);
    expect(isAffected("1.6.0", [r1, r2], null, "npm").affected).toBe(false);
    expect(isAffected("3.0.0", [r1, r2], null, "npm").affected).toBe(false);
  });

  it("fixedIn reports the smallest fix boundary above queried", () => {
    const r1 = range([{ introduced: "1.0.0" }, { fixed: "1.5.0" }]);
    const r2 = range([{ introduced: "2.0.0" }, { fixed: "2.5.0" }]);
    const res = isAffected("1.2.0", [r1, r2], null, "npm");
    expect(res.affected).toBe(true);
    expect(res.fixedIn).toBe("1.5.0");
  });

  it("pre-release: 1.0.0-rc.1 < 1.0.0", () => {
    const r = range([{ introduced: "1.0.0-alpha.1" }, { fixed: "1.0.0" }]);
    expect(isAffected("1.0.0-rc.1", [r], null, "npm").affected).toBe(true);
    expect(isAffected("1.0.0", [r], null, "npm").affected).toBe(false);
  });

  it("explicit versions list: only exact matches are affected", () => {
    expect(
      isAffected("4.17.20", null, ["4.17.19", "4.17.20"], "npm").affected,
    ).toBe(true);
    expect(
      isAffected("4.17.21", null, ["4.17.19", "4.17.20"], "npm").affected,
    ).toBe(false);
  });

  it("no ranges and no explicit versions → not affected", () => {
    expect(isAffected("1.0.0", [], null, "npm").affected).toBe(false);
    expect(isAffected("1.0.0", null, null, "npm").affected).toBe(false);
  });

  it("queried at introduced boundary is affected (introduced is inclusive)", () => {
    const r = range([{ introduced: "4.0.0" }, { fixed: "4.17.21" }]);
    expect(isAffected("4.0.0", [r], null, "npm").affected).toBe(true);
  });
});

describe("isAffected — PyPI / PEP 440", () => {
  it("simple range", () => {
    const r = pypiRange([{ introduced: "3.0.0" }, { fixed: "3.2.13" }]);
    expect(isAffected("3.2.0", [r], null, "PyPI").affected).toBe(true);
    expect(isAffected("3.2.13", [r], null, "PyPI").affected).toBe(false);
    expect(isAffected("2.2.0", [r], null, "PyPI").affected).toBe(false);
  });

  it("PEP 440 epoch versions sort correctly: 1!0.1 > 99.0", () => {
    const r = pypiRange([{ introduced: "1!0.0" }, { fixed: "1!1.0" }]);
    expect(isAffected("1!0.5", [r], null, "PyPI").affected).toBe(true);
    expect(isAffected("99.0", [r], null, "PyPI").affected).toBe(false);
  });

  it("PEP 440 pre-releases: 1.0a1 < 1.0", () => {
    const r = pypiRange([{ introduced: "1.0" }, { fixed: "2.0" }]);
    expect(isAffected("1.0a1", [r], null, "PyPI").affected).toBe(false);
    expect(isAffected("1.0", [r], null, "PyPI").affected).toBe(true);
  });
});

describe("describeRange", () => {
  it("formats >= introduced, < fixed", () => {
    expect(describeRange(range([{ introduced: "1.0.0" }, { fixed: "2.0.0" }]))).toBe(
      ">= 1.0.0, < 2.0.0",
    );
  });
  it("formats 'from 0' when introduced is 0", () => {
    expect(describeRange(range([{ introduced: "0" }, { fixed: "1.0.0" }]))).toBe(
      "from 0, < 1.0.0",
    );
  });
  it("formats <= last_affected", () => {
    expect(describeRange(range([{ introduced: "1.0.0" }, { last_affected: "2.5.0" }]))).toBe(
      ">= 1.0.0, <= 2.5.0",
    );
  });
});
