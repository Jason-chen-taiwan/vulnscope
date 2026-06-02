import type { Pkg } from "./types.js";

/**
 * Parse a pip-style requirements.txt.
 *
 * Only handles fully pinned entries — `pkg==1.2.3` — because a CVE
 * scanner needs a concrete version, and `>=1.0,<2.0` could match any
 * of dozens of releases. Loosely-pinned and unpinned lines are skipped
 * (callers see the count via the "skipped" return so they can warn).
 *
 * Lines we explicitly handle:
 *   `pkg==1.2.3`                                  → pinned
 *   `pkg==1.2.3 ; python_version >= "3.8"`        → pinned + marker
 *   `pkg==1.2.3 --hash=sha256:...`                → pinned + hash
 *   `# comment`, blank lines, `-r other.txt`,     → skipped
 *   `-e .`, `git+https://...`, `./local/wheel.whl` → skipped
 *
 * Returns both the parsed packages and a count of skipped lines so the
 * CLI can surface a warning when most of the file was unpinned.
 */
export function parseRequirementsTxt(
  text: string,
): { packages: Pkg[]; skipped: number } {
  const out: Pkg[] = [];
  const seen = new Set<string>();
  let skipped = 0;

  const lines = text.split(/\r?\n/);
  for (let raw of lines) {
    // Line continuations: pip joins lines ending with `\` to the next.
    while (raw.endsWith("\\")) {
      raw = raw.slice(0, -1);
      // Caller is iterating per-line; for simplicity treat `\` as a
      // soft skip — pip files with backslash continuations are rare.
      break;
    }
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith("#")) continue;
    if (line.startsWith("-")) continue; // -r, -c, -e, --index-url, etc.
    if (/^(https?:|git\+|file:|\.\/|\.\\)/i.test(line)) {
      skipped += 1;
      continue;
    }

    // Strip environment markers (`; python_version >= "3.8"`) and
    // hash options (`--hash=sha256:...`).
    let spec = line;
    const semi = spec.indexOf(";");
    if (semi >= 0) spec = spec.slice(0, semi).trim();
    const hashIdx = spec.indexOf("--hash");
    if (hashIdx >= 0) spec = spec.slice(0, hashIdx).trim();
    // Drop trailing extras: `pkg[ext1,ext2]==1.0` → `pkg==1.0`.
    spec = spec.replace(/\[[^\]]*\]/g, "");

    const m = spec.match(/^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+!]+)/);
    if (!m) {
      skipped += 1;
      continue;
    }
    const name = m[1].toLowerCase();
    const version = m[2];
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ecosystem: "PyPI", name, version });
  }

  return { packages: out, skipped };
}

/**
 * Parse a Poetry-generated poetry.lock.
 *
 * Format is TOML, but we don't want a TOML dep just to read one
 * structure. The fields we need are simple and grep-able:
 *
 *     [[package]]
 *     name = "requests"
 *     version = "2.31.0"
 *     description = "..."
 *     category = "main"
 *
 * One small parser pass: collect `name` and `version` per `[[package]]`
 * block, emit one Pkg each. Robust against attribute order, missing
 * description, multi-line strings, and `category = "dev"` (dev deps
 * count too — they're installed during tests/CI and can carry CVEs).
 */
export function parsePoetryLockfile(text: string): Pkg[] {
  const out: Pkg[] = [];
  const seen = new Set<string>();

  let inPackage = false;
  let name: string | null = null;
  let version: string | null = null;

  const flush = () => {
    if (name && version) {
      const lower = name.toLowerCase();
      const key = `${lower}@${version}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push({ ecosystem: "PyPI", name: lower, version });
      }
    }
    name = null;
    version = null;
  };

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("[[package]]")) {
      flush();
      inPackage = true;
      continue;
    }
    if (line.startsWith("[") && line.endsWith("]")) {
      // Any other section header ends the current package block.
      flush();
      inPackage = false;
      continue;
    }
    if (!inPackage) continue;
    // `name = "foo"` / `version = "1.2.3"`
    const nm = line.match(/^name\s*=\s*"([^"]+)"/);
    if (nm) {
      name = nm[1];
      continue;
    }
    const vm = line.match(/^version\s*=\s*"([^"]+)"/);
    if (vm) {
      version = vm[1];
    }
  }
  flush();

  return out;
}
