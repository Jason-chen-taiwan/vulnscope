import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import type { LockfileKind, Pkg } from "./types.js";
import { parseNpmLockfile } from "./npm.js";
import { parsePnpmLockfile } from "./pnpm.js";

/**
 * Resolve which lockfile to scan.
 *
 * If the user passed an explicit path, honour it (and infer kind from
 * the filename). Otherwise look in `cwd` with pnpm preferred over npm —
 * in mixed repos `pnpm-lock.yaml` is the source of truth and
 * package-lock.json is usually a stale artefact.
 */
export function detectLockfile(cwd: string): { kind: LockfileKind; path: string } | null {
  const pnpm = join(cwd, "pnpm-lock.yaml");
  if (existsSync(pnpm)) return { kind: "pnpm", path: pnpm };
  const npm = join(cwd, "package-lock.json");
  if (existsSync(npm)) return { kind: "npm", path: npm };
  return null;
}

export function kindFromPath(path: string): LockfileKind | null {
  const base = basename(path).toLowerCase();
  if (base === "pnpm-lock.yaml" || base.endsWith(".pnpm-lock.yaml")) return "pnpm";
  if (base === "package-lock.json" || base.endsWith(".package-lock.json")) return "npm";
  if (base === "npm-shrinkwrap.json") return "npm";
  return null;
}

/**
 * Load + parse a lockfile in one step. Accepts either a file path or
 * a directory (in which case it auto-detects). Throws clear errors so
 * the CLI can map them to exit code 2 with a helpful message.
 */
export function loadLockfile(input: string): { kind: LockfileKind; path: string; packages: Pkg[] } {
  const abs = resolve(input);
  if (!existsSync(abs)) {
    throw new Error(`path not found: ${input}`);
  }
  let target: { kind: LockfileKind; path: string } | null;
  if (statSync(abs).isDirectory()) {
    target = detectLockfile(abs);
    if (!target) {
      throw new Error(
        `no lockfile found in ${input} (looked for pnpm-lock.yaml, package-lock.json)`,
      );
    }
  } else {
    const kind = kindFromPath(abs);
    if (!kind) {
      throw new Error(
        `cannot infer lockfile type from filename ${basename(abs)}; supported: pnpm-lock.yaml, package-lock.json`,
      );
    }
    target = { kind, path: abs };
  }
  const text = readFileSync(target.path, "utf8");
  const packages = target.kind === "pnpm" ? parsePnpmLockfile(text) : parseNpmLockfile(text);
  return { kind: target.kind, path: target.path, packages };
}
