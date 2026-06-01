import { parse as parseYaml } from "yaml";
import type { Pkg } from "./types.js";

/**
 * Parse a pnpm-lock.yaml (v9 format) into a flat list of {name, version}.
 *
 * pnpm-lock.yaml's `packages` map is keyed by a string like:
 *   /lodash@4.17.21
 *   /@types/node@22.10.0
 *   /react-dom@19.0.0(react@19.0.0)            ← peer-deps suffix
 *   /@scope/name@1.2.3(some@x.y)(another@1.0)
 *
 * In pnpm v9 the leading slash was dropped, so we accept both forms.
 *
 * Strategy: peel off the optional peer-deps suffix (everything from the
 * first `(` to the end), then split on the LAST `@` to separate
 * `name` and `version`. The last-`@` rule is important so scoped names
 * like `@scope/foo` stay intact.
 *
 * Dedupes on (name, version) since the same package can appear under
 * multiple peer-dep keys.
 */
export function parsePnpmLockfile(text: string): Pkg[] {
  let doc: unknown;
  try {
    doc = parseYaml(text);
  } catch (e) {
    throw new Error(`pnpm-lock.yaml is not valid YAML: ${(e as Error).message}`);
  }
  if (!doc || typeof doc !== "object") {
    throw new Error("pnpm-lock.yaml root is not an object");
  }
  const root = doc as Record<string, unknown>;
  const lockfileVersion = root.lockfileVersion;
  // pnpm 9 uses string "9.0", earlier uses number. We accept both as long as
  // the `packages` map is present — that's the actual shape we care about.
  const packages = root.packages;
  if (!packages || typeof packages !== "object") {
    throw new Error(
      `pnpm-lock.yaml missing \`packages\` map (lockfileVersion=${String(lockfileVersion)})`,
    );
  }

  const seen = new Set<string>();
  const out: Pkg[] = [];
  for (const rawKey of Object.keys(packages as Record<string, unknown>)) {
    const parsed = parsePackagesKey(rawKey);
    if (!parsed) continue;
    const dedupeKey = `${parsed.name}@${parsed.version}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push({ ecosystem: "npm", name: parsed.name, version: parsed.version });
  }
  return out;
}

/** Exported for tests; covers the gnarly cases. */
export function parsePackagesKey(key: string): { name: string; version: string } | null {
  // Strip optional leading slash (pre-v9 form).
  let s = key.startsWith("/") ? key.slice(1) : key;
  // Strip peer-deps suffix starting at the first '('.
  const paren = s.indexOf("(");
  if (paren >= 0) s = s.slice(0, paren);
  // Split on the LAST `@` so '@scope/name@1.0.0' yields name '@scope/name'.
  const at = s.lastIndexOf("@");
  if (at <= 0) return null; // either no @ or @ at position 0 (scope only)
  const name = s.slice(0, at);
  const version = s.slice(at + 1);
  if (!name || !version) return null;
  // Reject obviously bad versions (e.g. git refs, file paths) — those
  // can't be checked against OSV anyway.
  if (version.includes("/") || version.startsWith("file:") || version.startsWith("link:")) {
    return null;
  }
  return { name, version };
}
