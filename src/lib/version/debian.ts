/**
 * Debian (dpkg --compare-versions) version comparator.
 *
 * Reference: dpkg/lib/dpkg/version.c, function `verrevcmp`.
 * https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/version.c
 *
 * Version syntax: `[epoch:]upstream[-revision]`
 *   - epoch: optional non-negative integer; absent means 0
 *   - upstream: vendor version, may contain dashes (last dash splits revision)
 *   - revision: Debian-side packaging revision (optional; absent means "")
 *
 * Comparing two version strings:
 *   1. Compare epoch as integers.
 *   2. If equal, compare upstream parts via verrevcmp.
 *   3. If equal, compare revision parts via verrevcmp.
 *
 * verrevcmp algorithm:
 *   Walks both strings in lockstep, alternating between "non-digit
 *   block" and "digit block":
 *     - Non-digit block: char-by-char compare with custom ordering
 *         `~` < empty(end-of-string) < letter < non-letter
 *         (So `1.0~rc1` < `1.0` < `1.0+a`.)
 *     - Digit block: parse leading digits of each side, compare as
 *       integers (ignoring leading zeros).
 *   The first difference wins. If both strings exhaust together, they're
 *   equal.
 */
import { lexicographic, type Comparator } from "./types";

interface DebianVersion {
  epoch: number;
  upstream: string;
  revision: string;
}

function parseDebianVersion(v: string): DebianVersion | null {
  if (!v) return null;
  let epoch = 0;
  let rest = v;
  const colonIdx = v.indexOf(":");
  if (colonIdx >= 0) {
    const ep = v.slice(0, colonIdx);
    if (!/^\d+$/.test(ep)) return null;
    epoch = Number(ep);
    rest = v.slice(colonIdx + 1);
  }
  // The LAST hyphen separates upstream from revision per Debian
  // policy. If no hyphen, revision is the empty string and the
  // whole thing is upstream (this also means revision "0" sorts
  // greater than no revision, which matches dpkg behavior).
  let upstream: string;
  let revision: string;
  const dashIdx = rest.lastIndexOf("-");
  if (dashIdx >= 0) {
    upstream = rest.slice(0, dashIdx);
    revision = rest.slice(dashIdx + 1);
  } else {
    upstream = rest;
    revision = "";
  }
  return { epoch, upstream, revision };
}

/**
 * Per-character ordering inside a non-digit block.
 *   `~` (tilde) sorts BEFORE end-of-string (so 1.0~rc1 < 1.0)
 *   Then end-of-string (treated below by passing -1)
 *   Then letters (a-z, A-Z)
 *   Then any other character ($, +, ., :, ...) per ASCII order
 */
function charOrder(c: string): number {
  if (c === "~") return -1;
  if (c === "") return 0; // end-of-string sentinel — caller doesn't actually pass ""
  const code = c.charCodeAt(0);
  // Letters: keep their natural ASCII order but they all sort below
  // non-letter symbols. Shift letters into [1..52], everything else
  // into [53..].
  if ((code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a)) {
    // A-Z: 0x41..0x5a → 1..26
    // a-z: 0x61..0x7a → 27..52
    if (code <= 0x5a) return 1 + (code - 0x41);
    return 27 + (code - 0x61);
  }
  return 53 + code;
}

function verrevcmp(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    // Non-digit block — char-by-char with the custom ordering.
    // `~` is special: it sorts before even end-of-string, so we
    // compare it explicitly when only one side has the tilde.
    while (
      (i < a.length && !isDigit(a[i])) ||
      (j < b.length && !isDigit(b[j]))
    ) {
      const ac = i < a.length ? a[i] : "";
      const bc = j < b.length ? b[j] : "";
      // Tilde sorts before end-of-string. If one is `~` and the
      // other is empty (or anything non-tilde), tilde loses.
      if (ac === "~" && bc !== "~") return -1;
      if (bc === "~" && ac !== "~") return 1;
      // End-of-string vs anything (except `~` handled above) →
      // shorter string wins.
      if (ac === "" && bc !== "") return -1;
      if (bc === "" && ac !== "") return 1;
      // Both have a non-digit char (or both are at EOS — exit loop).
      if (ac === "" && bc === "") break;
      const ao = charOrder(ac);
      const bo = charOrder(bc);
      if (ao !== bo) return ao < bo ? -1 : 1;
      i++;
      j++;
    }
    // Digit block — strip leading zeros and compare as integers.
    let aStart = i;
    while (i < a.length && isDigit(a[i])) i++;
    let bStart = j;
    while (j < b.length && isDigit(b[j])) j++;
    while (aStart < i && a[aStart] === "0") aStart++;
    while (bStart < j && b[bStart] === "0") bStart++;
    const aDig = a.slice(aStart, i);
    const bDig = b.slice(bStart, j);
    if (aDig.length !== bDig.length) {
      return aDig.length < bDig.length ? -1 : 1;
    }
    if (aDig !== bDig) {
      return aDig < bDig ? -1 : 1;
    }
  }
  return 0;
}

function isDigit(c: string): boolean {
  return c >= "0" && c <= "9";
}

export const debianComparator: Comparator = {
  cmp(a, b) {
    if (a === b) return 0;
    if (a === "0") return -1;
    if (b === "0") return 1;
    const pa = parseDebianVersion(a);
    const pb = parseDebianVersion(b);
    if (!pa || !pb) return lexicographic(a, b);
    if (pa.epoch !== pb.epoch) return pa.epoch < pb.epoch ? -1 : 1;
    const u = verrevcmp(pa.upstream, pb.upstream);
    if (u !== 0) return u;
    return verrevcmp(pa.revision, pb.revision);
  },
};

// Exposed for fixture-grounded testing without poking implementation
// details from outside.
export const __debianInternals = { parseDebianVersion, verrevcmp };
