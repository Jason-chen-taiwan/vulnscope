/**
 * Alpine apk-tools version comparator.
 *
 * Alpine versions look like:
 *   `[<digit>.]+[<letter>][_<suffix><number>]...[-r<revision>]`
 *
 * Examples (real Alpine packages):
 *   `1.2.3`, `1.2.3-r4`, `1.2.3_alpha1-r2`, `2.0p1`
 *
 * Components in comparison order:
 *   1. numeric segments separated by `.`
 *   2. optional single letter (a-z) — `2.0a` > `2.0`
 *   3. zero or more `_<suffix><number>` — suffix ordering:
 *        alpha < beta < pre < rc < "" (no suffix) < cvs < svn < git < hg < p
 *      (where p suffix means "patch")
 *   4. `-r<revision>` — numeric, missing == 0
 *
 * Reference: apk-tools source
 * (https://gitlab.alpinelinux.org/alpine/apk-tools/-/blob/master/src/version.c)
 */
import { lexicographic, type Comparator } from "./types";

const SUFFIX_RANK: Record<string, number> = {
  alpha: 0,
  beta: 1,
  pre: 2,
  rc: 3,
  "": 4,
  cvs: 5,
  svn: 6,
  git: 7,
  hg: 8,
  p: 9,
};

interface AlpineVersion {
  numerics: bigint[];
  letter: string; // "" or single a-z
  suffixes: { name: string; num: bigint }[];
  revision: bigint;
}

function parseAlpine(v: string): AlpineVersion | null {
  if (!v) return null;
  let s = v;

  // Strip -rN
  let revision = 0n;
  const revMatch = /-r(\d+)$/.exec(s);
  if (revMatch) {
    revision = BigInt(revMatch[1]);
    s = s.slice(0, revMatch.index);
  }

  // Collect _suffix groups at end
  const suffixes: { name: string; num: bigint }[] = [];
  while (true) {
    const m = /_([a-z]+)(\d*)$/.exec(s);
    if (!m) break;
    suffixes.unshift({
      name: m[1],
      num: m[2] ? BigInt(m[2]) : 0n,
    });
    s = s.slice(0, m.index);
  }

  // Trailing letter (single a-z) — only when preceded by a digit
  let letter = "";
  const letMatch = /(\d)([a-z])$/.exec(s);
  if (letMatch) {
    letter = letMatch[2];
    s = s.slice(0, s.length - 1);
  }

  // Remaining s should be dotted numbers
  const parts = s.split(".");
  const numerics: bigint[] = [];
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    numerics.push(BigInt(p));
  }
  return { numerics, letter, suffixes, revision };
}

export const alpineComparator: Comparator = {
  cmp(a, b) {
    if (a === b) return 0;
    if (a === "0") return -1;
    if (b === "0") return 1;
    const pa = parseAlpine(a);
    const pb = parseAlpine(b);
    if (!pa || !pb) return lexicographic(a, b);

    // 1. Numeric segments
    const n = Math.max(pa.numerics.length, pb.numerics.length);
    for (let i = 0; i < n; i++) {
      const x = i < pa.numerics.length ? pa.numerics[i] : 0n;
      const y = i < pb.numerics.length ? pb.numerics[i] : 0n;
      if (x !== y) return x < y ? -1 : 1;
    }

    // 2. Optional trailing letter
    if (pa.letter !== pb.letter) {
      if (pa.letter === "") return -1;
      if (pb.letter === "") return 1;
      return pa.letter < pb.letter ? -1 : 1;
    }

    // 3. Suffixes (chained _alpha1_beta2 etc.)
    const sn = Math.max(pa.suffixes.length, pb.suffixes.length);
    for (let i = 0; i < sn; i++) {
      const sa = pa.suffixes[i];
      const sb = pb.suffixes[i];
      if (!sa) {
        // missing suffix on a side. If the OTHER side has a
        // "negative" suffix (alpha/beta/pre/rc), the missing-side
        // is greater. Otherwise (cvs/svn/git/hg/p), the missing
        // side is less.
        const rb = SUFFIX_RANK[sb.name] ?? 100;
        return rb < SUFFIX_RANK[""] ? 1 : -1;
      }
      if (!sb) {
        const ra = SUFFIX_RANK[sa.name] ?? 100;
        return ra < SUFFIX_RANK[""] ? -1 : 1;
      }
      if (sa.name !== sb.name) {
        const ra = SUFFIX_RANK[sa.name] ?? 100;
        const rb = SUFFIX_RANK[sb.name] ?? 100;
        if (ra !== rb) return ra < rb ? -1 : 1;
        // Both unknown — lex
        return sa.name < sb.name ? -1 : 1;
      }
      if (sa.num !== sb.num) return sa.num < sb.num ? -1 : 1;
    }

    // 4. Revision (-rN)
    if (pa.revision !== pb.revision) {
      return pa.revision < pb.revision ? -1 : 1;
    }
    return 0;
  },
};
