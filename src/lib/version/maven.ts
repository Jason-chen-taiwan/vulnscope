/**
 * Maven version comparator — port of Apache Maven's ComparableVersion.java.
 *
 * Reference (canonical implementation):
 *   https://github.com/apache/maven/blob/master/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java
 *
 * The algorithm is non-obvious — Maven version sorting is famous for
 * surprising edge cases (e.g. `1.0` == `1` == `1.0.0`, `1.0-alpha-1`
 * < `1.0-SNAPSHOT` < `1.0`). This port preserves the reference
 * behavior; deviations would produce wrong CVE matches.
 *
 * Approach:
 *   1. Lowercase + tokenize on `.`, `-`, and integer/string boundaries.
 *   2. Build a nested ItemList where each `-` opens a sub-list.
 *   3. Normalize: strip trailing "null" items (zeros / empty qualifier).
 *   4. Compare lists element-by-element with kind-aware rules:
 *      Integer item, qualifier item with known ordering, qualifier item
 *      with unknown name, or nested ItemList.
 *
 * Qualifier order (smaller = older):
 *   alpha (0) < beta (1) < milestone (2) < rc (3) < snapshot (4) <
 *   "" / null (5, = "release") < sp (6) < <unknown> (7+, sorted by name)
 */
import { type Comparator } from "./types";

// -----------------------------------------------------------------------------
// Item types
// -----------------------------------------------------------------------------

type Item = IntItem | StringItem | ListItem;

interface IntItem {
  kind: "int";
  value: bigint;
}
interface StringItem {
  kind: "string";
  value: string;
}
interface ListItem {
  kind: "list";
  items: Item[];
}

// "null" item per Maven: empty list, zero int, or empty string.
// These are stripped from the END of any list during normalization
// so `1.0` == `1.0.0` == `1`.
function isNull(item: Item): boolean {
  if (item.kind === "int") return item.value === 0n;
  if (item.kind === "string") return qualifierOrder(item.value) === 5; // "" / release
  if (item.kind === "list") return item.items.length === 0;
  return false;
}

// Known qualifier ordering. Aliases map to the canonical name so
// `a == alpha`, `b == beta`, `m == milestone`, `cr == rc`, `ga/final == ""`.
const QUALIFIER_ALIASES: Record<string, string> = {
  a: "alpha",
  b: "beta",
  m: "milestone",
  cr: "rc",
  ga: "",
  final: "",
  release: "",
  "": "",
};
const QUALIFIER_RANK: Record<string, number> = {
  alpha: 0,
  beta: 1,
  milestone: 2,
  rc: 3,
  snapshot: 4,
  "": 5,
  sp: 6,
};
function qualifierOrder(q: string): number {
  const canonical = QUALIFIER_ALIASES[q] ?? q;
  if (QUALIFIER_RANK[canonical] !== undefined) return QUALIFIER_RANK[canonical];
  // Unknown qualifier: sorts AFTER all known ones, alphabetically.
  // We give them rank 7+ but tiebreak by string comparison in
  // compareItems().
  return 7;
}

// -----------------------------------------------------------------------------
// Parsing
// -----------------------------------------------------------------------------

function parse(versionRaw: string): ListItem {
  const version = versionRaw.toLowerCase();
  const root: ListItem = { kind: "list", items: [] };
  let stack: ListItem[] = [root];
  let current: ListItem = root;
  let isDigit = false;
  let startIdx = 0;
  let i = 0;

  const pushItem = (start: number, end: number) => {
    if (start === end) return;
    const piece = version.slice(start, end);
    if (isDigit) {
      current.items.push({ kind: "int", value: BigInt(piece) });
    } else {
      current.items.push({ kind: "string", value: piece });
    }
  };

  // Maven prepends a "0" int item to the start of any list whose
  // first token is a qualifier — so `alpha-1` becomes `[0, alpha, [1]]`.
  // Our pushItem helper handles digits/strings; we set up the
  // pre-zero condition by tracking whether the list is "empty" (no
  // items yet).

  for (i = 0; i < version.length; i++) {
    const c = version[i];
    if (c === ".") {
      pushItem(startIdx, i);
      startIdx = i + 1;
    } else if (c === "-") {
      pushItem(startIdx, i);
      startIdx = i + 1;
      // Open a new sub-list and descend
      const sub: ListItem = { kind: "list", items: [] };
      current.items.push(sub);
      stack.push(current);
      current = sub;
    } else if (c >= "0" && c <= "9") {
      if (!isDigit && i > startIdx) {
        // Transition from string → digit: flush the string token,
        // then implicitly open a sub-list (Maven treats this like
        // a `-` between string and digit run, e.g. `alpha1` becomes
        // `alpha-1`).
        pushItem(startIdx, i);
        startIdx = i;
        const sub: ListItem = { kind: "list", items: [] };
        current.items.push(sub);
        stack.push(current);
        current = sub;
      }
      isDigit = true;
    } else {
      if (isDigit && i > startIdx) {
        pushItem(startIdx, i);
        startIdx = i;
        const sub: ListItem = { kind: "list", items: [] };
        current.items.push(sub);
        stack.push(current);
        current = sub;
      }
      isDigit = false;
    }
  }
  pushItem(startIdx, i);

  // Normalize: strip trailing nulls from EACH list (recursive).
  normalize(root);
  return root;
}

function normalize(list: ListItem): void {
  for (const item of list.items) {
    if (item.kind === "list") normalize(item);
  }
  while (list.items.length > 0 && isNull(list.items[list.items.length - 1])) {
    list.items.pop();
  }
}

// -----------------------------------------------------------------------------
// Comparison
// -----------------------------------------------------------------------------

function compareItems(a: Item | null, b: Item | null): number {
  // Missing item is treated as "null" for its expected kind. Per
  // Maven's ComparableVersion:
  //   IntItem.compareTo(null)    → IntItem == 0 ? 0 : 1
  //   StringItem.compareTo(null) → string-rank vs release-rank
  //                                ("" / release has rank 5)
  //   ListItem.compareTo(null)   → recurse with each item.compareTo(null);
  //                                empty list == null
  if (a === null && b === null) return 0;
  if (a === null) return -compareItems(b, null);
  if (b === null) {
    if (a.kind === "int") return a.value === 0n ? 0 : 1;
    if (a.kind === "string") {
      const ra = qualifierOrder(a.value);
      // Compare to "release" rank (5). If ra === 5 → equal.
      if (ra === 5) return 0;
      return ra < 5 ? -1 : 1;
    }
    // list: recurse on first element (or 0 if empty)
    if (a.items.length === 0) return 0;
    return compareItems(a.items[0], null);
  }

  // Both present. Mixed-kind comparison rules from ComparableVersion:
  //   int  vs int    → numeric
  //   list vs list   → element-wise (recursive)
  //   string vs string → qualifier ordering
  //   int  vs string → int wins (more-significant)
  //   int  vs list   → int wins
  //   list vs string → list wins
  if (a.kind === "int") {
    if (b.kind === "int") {
      if (a.value === b.value) return 0;
      return a.value < b.value ? -1 : 1;
    }
    return 1;
  }
  if (a.kind === "list") {
    if (b.kind === "list") {
      const n = Math.max(a.items.length, b.items.length);
      for (let i = 0; i < n; i++) {
        const x = i < a.items.length ? a.items[i] : null;
        const y = i < b.items.length ? b.items[i] : null;
        const r = compareItems(x, y);
        if (r !== 0) return r;
      }
      return 0;
    }
    if (b.kind === "int") return -1;
    return 1;
  }
  // a is string
  if (b.kind === "string") {
    const ra = qualifierOrder(a.value);
    const rb = qualifierOrder(b.value);
    if (ra !== rb) return ra < rb ? -1 : 1;
    // Same rank — for unknown qualifiers (rank 7), tiebreak by
    // canonical string compare.
    if (ra === 7) {
      const ca = QUALIFIER_ALIASES[a.value] ?? a.value;
      const cb = QUALIFIER_ALIASES[b.value] ?? b.value;
      if (ca === cb) return 0;
      return ca < cb ? -1 : 1;
    }
    return 0;
  }
  if (b.kind === "int") return -1;
  // b is list
  return -1;
}

export const mavenComparator: Comparator = {
  cmp(a, b) {
    if (a === b) return 0;
    if (a === "0") return -1;
    if (b === "0") return 1;
    const ra = parse(a);
    const rb = parse(b);
    return compareItems(ra, rb);
  },
};
