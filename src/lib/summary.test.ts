import { describe, it, expect } from "vitest";
import { summarize } from "./summary";

describe("summarize", () => {
  it("prefers summary when present", () => {
    expect(summarize("short summary", "much longer description goes here")).toBe("short summary");
  });

  it("trims summary whitespace", () => {
    expect(summarize("  trimmed  ", null)).toBe("trimmed");
  });

  it("returns null when both empty", () => {
    expect(summarize(null, null)).toBeNull();
    expect(summarize("", "")).toBeNull();
    expect(summarize("   ", "   ")).toBeNull();
  });

  it("falls back to first sentence of description", () => {
    const d = "This is the first sentence. This is the second one that we don't want.";
    expect(summarize(null, d)).toBe("This is the first sentence.");
  });

  it("hard-truncates very long single sentences with ellipsis", () => {
    const long = "x".repeat(200);
    const result = summarize(null, long, 100)!;
    expect(result.length).toBeLessThanOrEqual(100);
    expect(result.endsWith("…")).toBe(true);
  });

  it("collapses internal whitespace", () => {
    expect(summarize(null, "line one\n\n  line two")).toBe("line one line two");
  });

  it("returns short descriptions whole when no sentence break", () => {
    expect(summarize(null, "no period here")).toBe("no period here");
  });
});
