/**
 * Packagist / Composer version comparator.
 *
 * Composer extends SemVer with stability flags:
 *   dev < alpha < beta < RC < stable < patch
 * The "patch" stability is rarely seen in practice; we mainly need
 * the leading 4 (dev → RC).
 *
 * Reference: Composer's `Composer\Semver\Comparator` and the
 * `version_compare()` shim with the "no-arg" stability flag.
 *
 * In practice this is "semver-with-numbered-prereleases-allowed +
 * stability keyword". We tokenize like Gem::Version but use the
 * Composer stability ranking on string segments.
 */
import { lexicographic, type Comparator } from "./types";

type Seg = { kind: "int"; value: bigint } | { kind: "str"; value: string };

const STABILITY_RANK: Record<string, number> = {
  dev: -4,
  alpha: -3,
  a: -3,
  beta: -2,
  b: -2,
  rc: -1,
  "": 0,
  stable: 0,
  patch: 1,
  p: 1,
  pl: 1,
};

function tokenize(version: string): Seg[] {
  const segs: Seg[] = [];
  // Strip leading "v" Composer accepts.
  let norm = version.toLowerCase();
  if (norm.startsWith("v")) norm = norm.slice(1);
  // Treat `-` `+` `.` as separators; `+build` metadata is ignored for
  // ordering (matches SemVer).
  norm = norm.replace(/\+.*$/, "");
  norm = norm.replace(/-/g, ".");
  const parts = norm.split(".");
  for (const p of parts) {
    if (p === "") continue;
    const tokens = p.split(/(?<=\d)(?=\D)|(?<=\D)(?=\d)/);
    for (const t of tokens) {
      if (/^\d+$/.test(t)) segs.push({ kind: "int", value: BigInt(t) });
      else segs.push({ kind: "str", value: t });
    }
  }
  return segs;
}

function stringRank(s: string): number {
  if (s in STABILITY_RANK) return STABILITY_RANK[s];
  // Unknown qualifier sorts AFTER known qualifiers, lex by name.
  // We pick a high baseline (100) plus name compare via natural cmp.
  return 100;
}

function cmpSeg(a: Seg, b: Seg): number {
  if (a.kind === "int" && b.kind === "int") {
    if (a.value === b.value) return 0;
    return a.value < b.value ? -1 : 1;
  }
  if (a.kind === "str" && b.kind === "str") {
    const ra = stringRank(a.value);
    const rb = stringRank(b.value);
    if (ra !== rb) return ra < rb ? -1 : 1;
    if (ra === 100) {
      // Both unknown — fall back to lex on name
      if (a.value === b.value) return 0;
      return a.value < b.value ? -1 : 1;
    }
    return 0;
  }
  // Mixed: stability "stable" (rank 0, treated like integer release)
  // wins over prerelease strings; but a "patch" string can outrank
  // the int. Simplification: any qualifier with rank > 0 wins over
  // pure integer; rank < 0 (prerelease) loses to integer; rank = 0
  // is equivalent to integer (release).
  if (a.kind === "str") {
    const ra = stringRank(a.value);
    if (ra < 0) return -1; // prerelease < release int
    if (ra > 0) return 1;
    return 0;
  }
  // b is str (a was int per the earlier branch)
  if (b.kind !== "str") return 0; // unreachable; satisfies TS narrowing
  const rb = stringRank(b.value);
  if (rb < 0) return 1;
  if (rb > 0) return -1;
  return 0;
}

export const composerComparator: Comparator = {
  cmp(a, b) {
    if (a === b) return 0;
    if (a === "0") return -1;
    if (b === "0") return 1;
    const sa = tokenize(a);
    const sb = tokenize(b);
    if (sa.length === 0 || sb.length === 0) return lexicographic(a, b);

    // Strip trailing-zero int segments
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
