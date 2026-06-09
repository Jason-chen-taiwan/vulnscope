/**
 * NuGet (.NET).
 *
 * NuGet versions are SemVer 2 plus an optional fourth "revision"
 * segment (`Major.Minor.Patch.Revision`). When the revision is
 * present we compare as four integer segments then by pre-release
 * tag; when absent the rest is plain SemVer.
 *
 * Reference: https://learn.microsoft.com/en-us/nuget/concepts/package-versioning
 */
import semver from "semver";
import { lexicographic, type Comparator } from "./types";

function parse4Part(v: string): {
  nums: number[];
  pre: string;
  build: string;
} | null {
  // Strip optional leading "v"
  const s = v.startsWith("v") ? v.slice(1) : v;
  // Split metadata first
  const [base, build = ""] = s.split("+", 2);
  const [core, pre = ""] = base.split("-", 2);
  const parts = core.split(".");
  if (parts.length < 1 || parts.length > 4) return null;
  const nums: number[] = [];
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    nums.push(Number(p));
  }
  while (nums.length < 4) nums.push(0);
  return { nums, pre, build };
}

function comparePre(a: string, b: string): number {
  // NuGet pre-release ordering matches SemVer: dot-separated
  // identifiers, numeric < alphanumeric, numeric compared as
  // numbers, alpha lexicographically. No pre-release > any
  // pre-release.
  if (a === "" && b === "") return 0;
  if (a === "") return 1;
  if (b === "") return -1;
  const al = a.split(".");
  const bl = b.split(".");
  for (let i = 0; i < Math.max(al.length, bl.length); i++) {
    const x = al[i];
    const y = bl[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) {
      const xi = Number(x);
      const yi = Number(y);
      if (xi !== yi) return xi - yi < 0 ? -1 : 1;
    } else if (xn) {
      return -1;
    } else if (yn) {
      return 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

export const nugetComparator: Comparator = {
  cmp(a, b) {
    if (a === b) return 0;
    if (a === "0") return -1;
    if (b === "0") return 1;
    const pa = parse4Part(a);
    const pb = parse4Part(b);
    // Fallback: try semver if 4-part parse failed (handles weird
    // versions like "1.0.0-alpha+build.1" that the simple parser
    // chokes on).
    if (!pa || !pb) {
      const sa = semver.coerce(a);
      const sb = semver.coerce(b);
      if (sa && sb) return semver.compare(sa.version, sb.version);
      return lexicographic(a, b);
    }
    for (let i = 0; i < 4; i++) {
      if (pa.nums[i] !== pb.nums[i]) return pa.nums[i] < pb.nums[i] ? -1 : 1;
    }
    return comparePre(pa.pre, pb.pre);
  },
};
