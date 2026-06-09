/**
 * RubyGems version comparator.
 *
 * Reference: Gem::Version in Ruby stdlib
 * (https://github.com/rubygems/rubygems/blob/master/lib/rubygems/version.rb).
 *
 * Algorithm:
 *   1. Split on `.` and `-` boundaries, plus letter/digit transitions.
 *      `1.0.beta1` → segments [1, 0, "beta", 1].
 *   2. Compare segment-by-segment with mixed-kind rules:
 *      - integer vs integer: numeric
 *      - string vs string: lexicographic (lowercase)
 *      - integer vs string: integer wins (release > prerelease)
 *   3. Missing segments at end default to 0 (or empty string when the
 *      other side has a string). `1.0` == `1.0.0`.
 *
 * Edge cases:
 *   - `1.0.0.pre.1` < `1.0.0` (any string segment makes it pre-release)
 *   - `1.0.0-1` and `1.0.0.1` are equivalent
 */
import { lexicographic, type Comparator } from "./types";

type Seg = { kind: "int"; value: bigint } | { kind: "str"; value: string };

function tokenize(version: string): Seg[] {
  const segs: Seg[] = [];
  // Normalize: lowercase, replace dashes with dots, then split on
  // anywhere a letter touches a digit.
  const norm = version.toLowerCase().replace(/-/g, ".");
  const parts = norm.split(".");
  for (const p of parts) {
    if (p === "") continue;
    // Split letter/digit transitions inside each part:
    // "beta1" → ["beta", "1"]
    const tokens = p.split(/(?<=\d)(?=\D)|(?<=\D)(?=\d)/);
    for (const t of tokens) {
      if (/^\d+$/.test(t)) segs.push({ kind: "int", value: BigInt(t) });
      else segs.push({ kind: "str", value: t });
    }
  }
  return segs;
}

function cmpSeg(a: Seg, b: Seg): number {
  if (a.kind === "int" && b.kind === "int") {
    if (a.value === b.value) return 0;
    return a.value < b.value ? -1 : 1;
  }
  if (a.kind === "str" && b.kind === "str") {
    if (a.value === b.value) return 0;
    return a.value < b.value ? -1 : 1;
  }
  // Mixed: integer (release) > string (prerelease)
  return a.kind === "int" ? 1 : -1;
}

export const rubygemsComparator: Comparator = {
  cmp(a, b) {
    if (a === b) return 0;
    if (a === "0") return -1;
    if (b === "0") return 1;
    const sa = tokenize(a);
    const sb = tokenize(b);
    if (sa.length === 0 || sb.length === 0) return lexicographic(a, b);

    // Strip trailing-zero int segments from both so 1.0.0 == 1.0
    while (sa.length > 0) {
      const last = sa[sa.length - 1];
      if (last.kind === "int" && last.value === 0n) sa.pop();
      else break;
    }
    while (sb.length > 0) {
      const last = sb[sb.length - 1];
      if (last.kind === "int" && last.value === 0n) sb.pop();
      else break;
    }

    const n = Math.max(sa.length, sb.length);
    for (let i = 0; i < n; i++) {
      const x: Seg = sa[i] ?? { kind: "int", value: 0n };
      const y: Seg = sb[i] ?? { kind: "int", value: 0n };
      const r = cmpSeg(x, y);
      if (r !== 0) return r;
    }
    return 0;
  },
};
