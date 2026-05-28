import { describe, it, expect } from "vitest";
import { cvss3BaseScore } from "./cvss";

describe("cvss3BaseScore", () => {
  // Known cases from the CVSS v3.1 specification examples.
  it("Log4Shell CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")).toBe(10);
  });
  it("Heartbleed-ish CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N ≈ 7.5", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")).toBe(7.5);
  });
  it("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H = 8.1 (high attack complexity)", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(8.1);
  });
  it("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8 (local privilege escalation)", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")).toBe(7.8);
  });
  it("returns null on unknown format", () => {
    expect(cvss3BaseScore("not a vector")).toBeNull();
    expect(cvss3BaseScore("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")).toBeNull();
  });
});
