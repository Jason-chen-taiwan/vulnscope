/**
 * Go modules version comparator.
 *
 * Go versions look like `vX.Y.Z` (SemVer with `v` prefix required).
 * Plus pseudo-versions for unreleased commits:
 *   `v0.0.0-YYYYMMDDhhmmss-abcdef012345`
 *   `vX.Y.Z-0.YYYYMMDDhhmmss-abcdef012345` (after a real tag)
 *   `vX.Y.(Z+1)-0.YYYYMMDDhhmmss-abcdef012345` (pre-release of next)
 *
 * Ordering:
 *   1. Strip leading `v`, compare semver (without the timestamp tail)
 *   2. If equal AND both have a pseudo-version timestamp, compare
 *      timestamps as integers (later commit > earlier commit)
 *
 * OSV Go advisories use the same pseudo-version syntax in
 * `introduced` / `fixed` events, so both sides come from the same
 * parser and round-trip correctly.
 *
 * Reference: https://go.dev/ref/mod#pseudo-versions
 */
import semver from "semver";
import { lexicographic, type Comparator } from "./types";

// Pseudo-version trailing: `-[PRE.]TIMESTAMP-HASH`
// TIMESTAMP is 14 digits (YYYYMMDDhhmmss), HASH is 12 lowercase hex.
const PSEUDO_TAIL_RE = /-(?:0\.)?(\d{14})-([0-9a-f]{12})$/;

interface GoVersion {
  base: string; // semver part (no v prefix); may itself contain a -pre identifier
  timestamp: string | null;
  // form === "preTag": v0.0.0-YYYYMMDDhhmmss-hash (commits BEFORE any tag)
  // form === "postTag": vX.Y.Z-0.YYYYMMDDhhmmss-hash (commits AFTER tag vX.Y.(Z-1) or pre of vX.Y.Z)
  form: "preTag" | "postTag" | "tag";
}

function parseGo(v: string): GoVersion | null {
  if (!v) return null;
  let s = v.startsWith("v") ? v.slice(1) : v;
  // Strip optional `+incompatible` suffix Go uses for major>=2
  // modules that don't follow the v2+ path convention.
  s = s.replace(/\+incompatible$/, "");

  const m = PSEUDO_TAIL_RE.exec(s);
  if (m) {
    // Was the matched tail of form `-0.TIMESTAMP-HASH` (postTag) or
    // `-TIMESTAMP-HASH` (preTag)? Check the literal preceding chars.
    const tailIdx = m.index;
    const isPostTag = s.slice(tailIdx, tailIdx + 3) === "-0.";
    const base = s.slice(0, tailIdx);
    return {
      base: base || "0.0.0",
      timestamp: m[1],
      form: isPostTag ? "postTag" : "preTag",
    };
  }
  return { base: s, timestamp: null, form: "tag" };
}

export const goComparator: Comparator = {
  cmp(a, b) {
    if (a === b) return 0;
    if (a === "0") return -1;
    if (b === "0") return 1;
    const pa = parseGo(a);
    const pb = parseGo(b);
    if (!pa || !pb) return lexicographic(a, b);

    // Compare base via semver (coerce to handle pseudo-version base
    // forms like "0.0.0" exactly, plus 2-part bases).
    const sa = semver.valid(pa.base) ?? semver.coerce(pa.base)?.version;
    const sb = semver.valid(pb.base) ?? semver.coerce(pb.base)?.version;
    if (!sa || !sb) return lexicographic(a, b);
    const baseCmp = semver.compare(sa, sb);
    if (baseCmp !== 0) return baseCmp;

    // Same base. Pseudo-version ordering vs tagged release:
    //   preTag pseudo:  vX.Y.Z-YYYY...   describes commits BEFORE
    //                   any tag. Treated as a pre-release of vX.Y.Z.
    //   postTag pseudo: vX.Y.Z-0.YYYY... describes commits AFTER
    //                   the previous tag. Greater than that tag.
    //
    // When both are pseudo-versions with same base: timestamp wins.
    // postTag also > preTag if base equal (different lineages but
    // postTag is structurally "newer" by definition).
    if (pa.form !== "tag" && pb.form !== "tag") {
      if (pa.form !== pb.form) {
        return pa.form === "postTag" ? 1 : -1;
      }
      if (pa.timestamp === pb.timestamp) return 0;
      return pa.timestamp! < pb.timestamp! ? -1 : 1;
    }
    if (pa.form === "tag" && pb.form === "preTag") return 1; // tag > preTag of same base
    if (pa.form === "preTag" && pb.form === "tag") return -1;
    if (pa.form === "tag" && pb.form === "postTag") return -1; // tag < postTag
    if (pa.form === "postTag" && pb.form === "tag") return 1;
    return 0;
  },
};
