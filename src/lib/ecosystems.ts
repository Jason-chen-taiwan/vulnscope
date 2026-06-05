/**
 * Canonical list of ecosystem labels we ingest from OSV (+ "Linux"
 * which OSV's kernel feed emits). Use this everywhere that needs an
 * allowlist — the API watchlist endpoint, ecosystem dropdowns, etc.
 *
 * Order matches package.json's `ingest:all` script and the homepage
 * featured strip.
 */
export const ECOSYSTEMS = [
  "npm",
  "PyPI",
  "Maven",
  "Go",
  "RubyGems",
  "Packagist",
  "crates.io",
  "NuGet",
  "Hex",
  "Hackage",
  "Debian",
  "Alpine",
  "Bitnami",
  "Linux",
] as const;

export type Ecosystem = (typeof ECOSYSTEMS)[number];

export function isEcosystem(value: unknown): value is Ecosystem {
  return typeof value === "string" && (ECOSYSTEMS as readonly string[]).includes(value);
}
