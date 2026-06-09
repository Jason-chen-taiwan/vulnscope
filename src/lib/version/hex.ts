/**
 * Hex (Erlang/Elixir) version comparator.
 *
 * Hex follows SemVer 2.0 strictly — Erlang/Elixir community rallied
 * on strict SemVer when designing the Hex package manager. So we
 * delegate to the same `semver` lib as npm, but reject anything
 * semver can't parse (no `semver.coerce` rescue here — Hex
 * publishers must commit to canonical SemVer).
 *
 * Reference: https://hex.pm/docs/publish (Versioning section).
 */
import semver from "semver";
import { lexicographic, type Comparator } from "./types";

export const hexComparator: Comparator = {
  cmp(a, b) {
    if (a === b) return 0;
    if (a === "0") return -1;
    if (b === "0") return 1;
    const av = semver.valid(a);
    const bv = semver.valid(b);
    if (!av || !bv) return lexicographic(a, b);
    return semver.compare(av, bv);
  },
};
