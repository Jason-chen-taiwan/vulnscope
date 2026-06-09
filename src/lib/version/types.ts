/**
 * Shared types + helpers for per-ecosystem version comparators.
 *
 * Each comparator file exports a `cmp(a, b)` returning -1/0/1, plus
 * any ecosystem-specific normalization. The dispatch table in
 * `./index.ts` maps an OSV ecosystem name to a comparator.
 *
 * Comparators throw on completely unparseable input — the caller
 * (version-match.ts) catches and falls back to lexicographic order
 * for malformed OSV data, preserving the existing behavior.
 */
export interface Comparator {
  /**
   * Three-way comparison. Returns:
   *   <0 if a < b
   *   0  if a === b (semantically; not necessarily string-equal)
   *   >0 if a > b
   *
   * Implementations should be **total** — every input pair yields a
   * defined answer. For unparseable input, fall back to lexicographic
   * compare rather than throwing.
   */
  cmp: (a: string, b: string) => number;
}

/**
 * Lexicographic fallback. Used inside comparators when both sides
 * are unparseable so they still return a deterministic order
 * (matters because event sorting must be stable).
 */
export function lexicographic(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
