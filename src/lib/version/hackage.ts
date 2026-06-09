/**
 * Hackage (Haskell) version comparator.
 *
 * Hackage uses PVP (Package Versioning Policy): pure dotted decimal,
 * any number of segments, lexicographic on the integer tuple.
 * No qualifiers, no pre-releases (Haskell convention prepends
 * `something.0` for "pre-1.0" work, etc.). Trailing zeros are kept
 * as significant (1.0 != 1.0.0).
 *
 * Reference: https://pvp.haskell.org/
 */
import { lexicographic, type Comparator } from "./types";

function parsePvp(v: string): bigint[] | null {
  const parts = v.split(".");
  const out: bigint[] = [];
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    out.push(BigInt(p));
  }
  return out;
}

export const hackageComparator: Comparator = {
  cmp(a, b) {
    if (a === b) return 0;
    if (a === "0") return -1;
    if (b === "0") return 1;
    const pa = parsePvp(a);
    const pb = parsePvp(b);
    if (!pa || !pb) return lexicographic(a, b);
    const n = Math.max(pa.length, pb.length);
    for (let i = 0; i < n; i++) {
      const x = i < pa.length ? pa[i] : 0n;
      const y = i < pb.length ? pb[i] : 0n;
      if (x !== y) return x < y ? -1 : 1;
    }
    return 0;
  },
};
