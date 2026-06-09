import type { OsvRange, OsvEvent } from "./osv";
import { comparatorFor } from "./version";
import { lexicographic } from "./version/types";

/**
 * Ecosystem name as it appears on OSV records / our `affected.ecosystem`
 * column. We accept any string and dispatch via comparatorFor(); unknown
 * ecosystems fall through to lexicographic order.
 */
export type Ecosystem = string;

export interface MatchResult {
  affected: boolean;
  fixedIn: string | null; // smallest "fixed" event boundary above queried version
}

const ZERO_PLACEHOLDER = "0";

function cmp(a: string, b: string, eco: Ecosystem): number {
  if (a === b) return 0;
  if (a === ZERO_PLACEHOLDER) return -1;
  if (b === ZERO_PLACEHOLDER) return 1;
  const c = comparatorFor(eco);
  if (!c) return lexicographic(a, b);
  return c.cmp(a, b);
}

interface SortableEvent {
  kind: "introduced" | "fixed" | "last_affected" | "limit";
  value: string;
}

function toSortable(events: OsvEvent[]): SortableEvent[] {
  const out: SortableEvent[] = [];
  for (const e of events) {
    if (e.introduced !== undefined) out.push({ kind: "introduced", value: e.introduced });
    else if (e.fixed !== undefined) out.push({ kind: "fixed", value: e.fixed });
    else if (e.last_affected !== undefined) out.push({ kind: "last_affected", value: e.last_affected });
    else if (e.limit !== undefined) out.push({ kind: "limit", value: e.limit });
  }
  return out;
}

/**
 * Evaluate whether a queried version is affected by a single OSV range.
 *
 * OSV `events[]` semantics (from osv-schema spec):
 *   - introduced: vulnerable from this version onward (inclusive).
 *   - fixed:      no longer vulnerable starting at this version (exclusive — fixed
 *                 itself is clean).
 *   - last_affected: highest version still vulnerable (inclusive — strictly
 *                    greater is clean).
 *   - limit:      hard upper bound; treat like `fixed`.
 *
 * Algorithm: sort events by version, then walk in order. Maintain a running
 * boolean `inRange`. Whether the queried version is affected is the value of
 * `inRange` after processing all events whose value <= queried (and the
 * `last_affected` case is checked separately because it's inclusive).
 */
function isAffectedByRange(
  queried: string,
  range: OsvRange,
  eco: Ecosystem,
): { affected: boolean; fixedIn: string | null } {
  if (range.type === "GIT") return { affected: false, fixedIn: null };
  const events = toSortable(range.events);
  if (events.length === 0) return { affected: false, fixedIn: null };

  // Sort by value, with "0" treated as lowest. Stable ordering matters when
  // two events share the same value: introduced should come before fixed.
  events.sort((a, b) => {
    const c = cmp(a.value, b.value, eco);
    if (c !== 0) return c;
    // tiebreak: introduced before fixed before last_affected before limit
    const order = { introduced: 0, fixed: 1, last_affected: 2, limit: 3 } as const;
    return order[a.kind] - order[b.kind];
  });

  let inRange = false;
  let fixedIn: string | null = null;

  for (const e of events) {
    const c = cmp(queried, e.value, eco);
    if (e.kind === "introduced") {
      // queried >= introduced → vulnerable from this point if no fix has happened later
      if (c >= 0) inRange = true;
    } else if (e.kind === "fixed") {
      // queried >= fixed → clean
      if (c >= 0) inRange = false;
      // remember smallest fixed > queried as the recommended upgrade target
      if (c < 0 && fixedIn === null) fixedIn = e.value;
    } else if (e.kind === "last_affected") {
      // queried > last_affected → clean
      if (c > 0) inRange = false;
    } else if (e.kind === "limit") {
      // limit is inclusive of "stop considering" — same as fixed for our purposes
      if (c >= 0) inRange = false;
    }
  }

  return { affected: inRange, fixedIn };
}

/**
 * Determine whether a queried version is affected by any of the given OSV
 * ranges (OR across ranges), with explicit `versions[]` taking precedence
 * when present.
 */
export function isAffected(
  version: string,
  ranges: OsvRange[] | null | undefined,
  explicitVersions: string[] | null | undefined,
  ecosystem: Ecosystem,
): MatchResult {
  // Prefer ranges when present. OSV's `versions` field is in practice a
  // convenience enumeration computed from the ranges by the publisher and
  // suffers from string-vs-canonical mismatch (e.g. "3.2" vs "3.2.0").
  // Only fall back to explicit version matching when ranges are absent.
  if (!ranges || ranges.length === 0) {
    if (!explicitVersions || explicitVersions.length === 0) {
      return { affected: false, fixedIn: null };
    }
    // Compare with ecosystem-aware equality (semver/pep440 treat "3.2" == "3.2.0").
    for (const v of explicitVersions) {
      if (cmp(version, v, ecosystem) === 0) {
        return { affected: true, fixedIn: null };
      }
    }
    return { affected: false, fixedIn: null };
  }

  let affected = false;
  let fixedIn: string | null = null;
  for (const r of ranges) {
    const res = isAffectedByRange(version, r, ecosystem);
    if (res.affected) affected = true;
    if (res.fixedIn) {
      if (fixedIn === null || cmp(res.fixedIn, fixedIn, ecosystem) < 0) {
        fixedIn = res.fixedIn;
      }
    }
  }
  return { affected, fixedIn };
}

// Render an OSV range as a human-readable string like ">= 1.0.0, < 4.17.21".
export function describeRange(range: OsvRange): string {
  const parts: string[] = [];
  for (const e of range.events) {
    if (e.introduced && e.introduced !== "0") parts.push(`>= ${e.introduced}`);
    else if (e.introduced === "0") parts.push("from 0");
    if (e.fixed) parts.push(`< ${e.fixed}`);
    if (e.last_affected) parts.push(`<= ${e.last_affected}`);
    if (e.limit) parts.push(`< ${e.limit}`);
  }
  return parts.join(", ");
}
