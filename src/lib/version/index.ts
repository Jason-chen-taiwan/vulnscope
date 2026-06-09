/**
 * Per-ecosystem version comparator dispatch.
 *
 * Maps an OSV ecosystem name (the string we store on `affected.ecosystem`)
 * to the `Comparator` that knows how to sort that ecosystem's version
 * strings. The 13 ecosystems we ingest are listed in the OSV crawler:
 * npm, PyPI, Maven, Go, RubyGems, Packagist, crates.io, NuGet, Hex,
 * Hackage, Debian, Alpine, Bitnami.
 *
 * Adding a new ecosystem:
 *   1. Drop a `<name>.ts` exporting a `Comparator` (returns -1/0/1)
 *   2. Register here under the exact ecosystem string OSV uses
 *   3. Add a corresponding `__tests__/<name>.test.ts`
 *
 * Unknown ecosystems return `null` so callers (version-match.ts) can
 * fall back to lexicographic — better than blowing up the page for
 * a CVE whose OSV record lists an ecosystem we don't ship yet.
 */
import type { Comparator } from "./types";
import { npmComparator } from "./npm";
import { pypiComparator } from "./pypi";
import { nugetComparator } from "./nuget";
import { debianComparator } from "./debian";
import { mavenComparator } from "./maven";

// crates.io shares the SemVer comparator — Rust's spec defers to
// SemVer 2.0 with only cosmetic restrictions (no leading zeros) that
// don't change ordering.
const COMPARATORS: Record<string, Comparator> = {
  npm: npmComparator,
  "crates.io": npmComparator,
  PyPI: pypiComparator,
  NuGet: nugetComparator,
  Debian: debianComparator,
  Maven: mavenComparator,
};

export function comparatorFor(ecosystem: string): Comparator | null {
  return COMPARATORS[ecosystem] ?? null;
}

/** All ecosystems with a real (non-lexicographic) comparator wired up.
 *  Used by the API + UI to gate the version checker. */
export function supportedEcosystems(): string[] {
  return Object.keys(COMPARATORS);
}

export type { Comparator };
