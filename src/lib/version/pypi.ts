/**
 * PyPI: PEP 440.
 *
 * Includes epoch syntax (`1!1.0` > all non-epoch versions), pre-
 * releases (`1.0a1` < `1.0`), post-releases, dev releases, and
 * local version segments.
 *
 * Delegated to `@renovatebot/pep440` which is the same lib Renovate
 * uses for its (huge) Python ecosystem support.
 */
import * as pep440 from "@renovatebot/pep440";
import { lexicographic, type Comparator } from "./types";

export const pypiComparator: Comparator = {
  cmp(a, b) {
    if (a === b) return 0;
    if (a === "0") return -1;
    if (b === "0") return 1;
    if (!pep440.valid(a) || !pep440.valid(b)) return lexicographic(a, b);
    return pep440.compare(a, b);
  },
};
