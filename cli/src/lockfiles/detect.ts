import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import type { LockfileKind, Pkg } from "./types.js";
import { parseNpmLockfile } from "./npm.js";
import { parsePnpmLockfile } from "./pnpm.js";
import {
  parseYarnV1Lockfile,
  parseYarnBerryLockfile,
  detectYarnVariant,
} from "./yarn.js";
import { parseRequirementsTxt, parsePoetryLockfile } from "./python.js";

/**
 * Resolve which lockfile to scan.
 *
 * Priority — when multiple lockfiles coexist in the same directory the
 * one we pick should match what would actually get installed. The
 * order roughly tracks "newest tooling wins":
 *
 *   poetry.lock > requirements.txt > pnpm > yarn > npm
 *
 * (yarn.lock alongside package-lock.json is the messiest case — yarn
 * wins because if someone runs `yarn install` the package-lock is just
 * stale.)
 */
export function detectLockfile(cwd: string): { kind: LockfileKind; path: string } | null {
  const poetry = join(cwd, "poetry.lock");
  if (existsSync(poetry)) return { kind: "poetry", path: poetry };
  const requirements = join(cwd, "requirements.txt");
  if (existsSync(requirements)) return { kind: "requirements", path: requirements };
  const pnpm = join(cwd, "pnpm-lock.yaml");
  if (existsSync(pnpm)) return { kind: "pnpm", path: pnpm };
  const yarn = join(cwd, "yarn.lock");
  if (existsSync(yarn)) {
    const head = readFileSync(yarn, "utf8").slice(0, 2048);
    return { kind: detectYarnVariant(head), path: yarn };
  }
  const npm = join(cwd, "package-lock.json");
  if (existsSync(npm)) return { kind: "npm", path: npm };
  return null;
}

export function kindFromPath(path: string): LockfileKind | null {
  const base = basename(path).toLowerCase();
  if (base === "pnpm-lock.yaml" || base.endsWith(".pnpm-lock.yaml")) return "pnpm";
  if (base === "package-lock.json" || base.endsWith(".package-lock.json")) return "npm";
  if (base === "npm-shrinkwrap.json") return "npm";
  // yarn variant is resolved from file content in loadLockfile.
  if (base === "yarn.lock") return "yarn";
  if (base === "requirements.txt" || base.endsWith(".requirements.txt")) return "requirements";
  if (base === "poetry.lock") return "poetry";
  return null;
}

export interface LoadResult {
  kind: LockfileKind;
  path: string;
  packages: Pkg[];
  /** Non-fatal warning the CLI should surface (e.g. how many
   *  requirements.txt lines were unpinned). */
  warning?: string;
}

/**
 * Load + parse a lockfile in one step. Accepts either a file path or
 * a directory (in which case it auto-detects). Throws clear errors so
 * the CLI can map them to exit code 2 with a helpful message.
 */
export function loadLockfile(input: string): LoadResult {
  const abs = resolve(input);
  if (!existsSync(abs)) {
    throw new Error(`path not found: ${input}`);
  }
  let target: { kind: LockfileKind; path: string } | null;
  if (statSync(abs).isDirectory()) {
    target = detectLockfile(abs);
    if (!target) {
      throw new Error(
        `no lockfile found in ${input} (looked for poetry.lock, requirements.txt, pnpm-lock.yaml, yarn.lock, package-lock.json)`,
      );
    }
  } else {
    const kind = kindFromPath(abs);
    if (!kind) {
      throw new Error(
        `cannot infer lockfile type from filename ${basename(abs)}; supported: pnpm-lock.yaml, package-lock.json, yarn.lock, requirements.txt, poetry.lock`,
      );
    }
    target = { kind, path: abs };
  }
  const text = readFileSync(target.path, "utf8");

  // yarn.lock from kindFromPath was returned as "yarn" — verify variant
  // from contents before parsing.
  let kind: LockfileKind = target.kind;
  if (kind === "yarn") kind = detectYarnVariant(text);

  let packages: Pkg[] = [];
  let warning: string | undefined;
  switch (kind) {
    case "pnpm":
      packages = parsePnpmLockfile(text);
      break;
    case "npm":
      packages = parseNpmLockfile(text);
      break;
    case "yarn":
      packages = parseYarnV1Lockfile(text);
      break;
    case "yarn-berry":
      packages = parseYarnBerryLockfile(text);
      break;
    case "requirements": {
      const r = parseRequirementsTxt(text);
      packages = r.packages;
      if (r.skipped > 0) {
        warning = `${r.skipped} unpinned or non-PyPI line(s) skipped — only ==pinned versions are checked`;
      }
      break;
    }
    case "poetry":
      packages = parsePoetryLockfile(text);
      break;
  }

  return { kind, path: target.path, packages, warning };
}
