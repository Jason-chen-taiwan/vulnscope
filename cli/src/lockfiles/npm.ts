import type { Pkg } from "./types.js";

/**
 * Parse a package-lock.json (npm) into a flat list of {name, version}.
 *
 * Handles lockfileVersion 2 and 3 (the modern formats). v1 stores deps
 * differently; we explicitly reject it so users get a clear error
 * rather than silently scanning the wrong shape.
 *
 * The `packages` map keys look like:
 *   ""                              (root project; skipped)
 *   "node_modules/lodash"           → name "lodash"
 *   "node_modules/foo/node_modules/bar"  → nested copy; name "bar"
 *   "node_modules/@scope/name"      → name "@scope/name"
 *
 * Each entry has a `version` field. We dedupe on (name, version) so a
 * package that appears at multiple nesting depths counts once.
 *
 * Entries with `"link": true` are workspace symlinks — not real installs,
 * skipped. Entries with `"inBundle": true` ride along inside another
 * package's tarball; still real installs, kept.
 */
export function parseNpmLockfile(text: string): Pkg[] {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (e) {
    throw new Error(`package-lock.json is not valid JSON: ${(e as Error).message}`);
  }
  if (!json || typeof json !== "object") {
    throw new Error("package-lock.json root is not an object");
  }
  const root = json as Record<string, unknown>;
  const version = root.lockfileVersion;
  if (typeof version !== "number" || version < 2) {
    throw new Error(
      `unsupported lockfileVersion ${version ?? "?"}; vulnscope needs v2 or v3 (run \`npm install\` with npm 7+)`,
    );
  }
  const packages = root.packages;
  if (!packages || typeof packages !== "object") {
    throw new Error("package-lock.json missing `packages` map");
  }

  const seen = new Set<string>();
  const out: Pkg[] = [];
  for (const [key, raw] of Object.entries(packages as Record<string, unknown>)) {
    if (key === "") continue; // root project entry, not a dep
    if (!raw || typeof raw !== "object") continue;
    const entry = raw as Record<string, unknown>;
    if (entry.link === true) continue; // workspace symlink
    const v = entry.version;
    if (typeof v !== "string" || !v) continue;

    const name = nameFromPackagesKey(key);
    if (!name) continue;
    const dedupeKey = `${name}@${v}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push({ ecosystem: "npm", name, version: v });
  }
  return out;
}

/**
 * Extract the package name from a `packages` map key by taking the
 * substring after the LAST `node_modules/` segment. This naturally
 * handles both scoped (`@scope/name`) and nested copies.
 */
function nameFromPackagesKey(key: string): string | null {
  const marker = "node_modules/";
  const idx = key.lastIndexOf(marker);
  if (idx < 0) return null;
  const tail = key.slice(idx + marker.length);
  return tail.length > 0 ? tail : null;
}
