/**
 * npm + crates.io: strict SemVer 2.0.
 *
 * crates.io declared its versioning to be SemVer (with very minor
 * deviations like leading zeros being banned), so it shares this
 * comparator. Rust's own SemVer impl matches semver.org closely
 * enough that `semver` npm package is correct for both ecosystems.
 *
 * Falls back to lexicographic for unparseable strings rather than
 * throwing — OSV occasionally contains version strings that don't
 * round-trip cleanly (e.g. "1.x" placeholders), and a wrong-but-
 * deterministic answer is better than a crashed page.
 */
import semver from "semver";
import { lexicographic, type Comparator } from "./types";

function canonicalize(v: string): string | null {
  if (v === "0") return v;
  const valid = semver.valid(v);
  if (valid) return valid;
  const coerced = semver.coerce(v);
  return coerced ? coerced.version : null;
}

export const npmComparator: Comparator = {
  cmp(a, b) {
    if (a === b) return 0;
    if (a === "0") return -1;
    if (b === "0") return 1;
    const av = canonicalize(a);
    const bv = canonicalize(b);
    if (!av || !bv) return lexicographic(a, b);
    return semver.compare(av, bv);
  },
};
