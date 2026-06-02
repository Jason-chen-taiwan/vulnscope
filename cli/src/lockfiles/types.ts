/**
 * Canonical shape the rest of the CLI expects from any lockfile parser.
 * `ecosystem` is fixed to "npm" / "PyPI" because that's what the
 * VulnScope API accepts today; future parsers (yarn / requirements.txt)
 * will reuse the same envelope.
 */
export interface Pkg {
  ecosystem: "npm" | "PyPI";
  name: string;
  version: string;
}

export type LockfileKind = "npm" | "pnpm" | "yarn" | "yarn-berry" | "requirements" | "poetry";
