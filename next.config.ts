import { existsSync } from "node:fs";
import path from "node:path";
import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

const withNextIntl = createNextIntlPlugin("./src/i18n/request.ts");

/**
 * Open Core via webpack alias.
 *
 * Pro tier code lives in a private repo cloned into ./pro at Docker
 * build time. OSS / self-host builds don't have ./pro on disk — they
 * fall through to ./pro-stub, which exports the same surface as
 * no-ops (null user, 404 handlers, etc.). This way:
 *   - one codebase builds in both modes
 *   - webpack bundles Pro normally (no dynamic import, no runtime
 *     module-resolution dance, no extra node_modules splicing in the
 *     standalone Docker output)
 *   - the OSS image silently 404s Pro routes
 *
 * The alias is computed once at config load. Don't try to flip it per-
 * request — webpack only resolves modules at build time.
 */
const PRO_DIR = path.resolve(__dirname, "pro");
const PRO_STUB_DIR = path.resolve(__dirname, "pro-stub");
const PRO_ROOT = existsSync(path.join(PRO_DIR, "auth", "config.ts"))
  ? PRO_DIR
  : PRO_STUB_DIR;

// Surfaced in build logs so a misconfigured hosted deploy (no /pro
// after the build secret was supposed to clone it) is obvious.
// eslint-disable-next-line no-console
console.log(
  `[next.config] Pro alias → ${path.relative(__dirname, PRO_ROOT)}/` +
    (PRO_ROOT === PRO_STUB_DIR ? " (OSS / stub mode)" : " (hosted Pro)"),
);

const nextConfig: NextConfig = {
  // Standalone output produces a minimal node_modules + server.js bundle —
  // required for the Docker production image to stay under ~250 MB.
  output: "standalone",
  outputFileTracingRoot: __dirname,
  serverExternalPackages: [
    "@renovatebot/pep440",
    "xregexp",
    "pg",
    "undici",
    // Pro tier deps. Externalized so webpack doesn't try to trace
    // into Better Auth's kysely-adapter (which references kysely
    // exports that don't actually exist — guarded by runtime checks
    // we never hit because we only use the drizzle adapter). With
    // these listed here, Next.js standalone copies the packages into
    // node_modules and we let Node resolve them at runtime.
    "better-auth",
    "@polar-sh/sdk",
    // yauzl is the active zip reader (pull-based, lazyEntries mode)
    // for OSV ingest. Externalizing keeps Next's webpack tracer from
    // over-resolving its CJS internals at build time.
    "yauzl",
    // unzipper stays listed even though we no longer use it directly:
    // it's a transitive dep of other tooling and its Open/index.js
    // lazy-requires @aws-sdk/client-s3, which would otherwise fail
    // the build with "Module not found: Can't resolve '@aws-sdk/client-s3'".
    "unzipper",
  ],
  experimental: {
    serverActions: { bodySizeLimit: "2mb" },
  },
  // pg's native binding is optional; webpack tries to resolve it eagerly
  // and warns even when we never use it. Externalize it explicitly so the
  // server bundle skips the attempted resolution. The webpack type isn't
  // a direct dependency of this project so we use `any` rather than
  // pulling @types/webpack in just for one parameter.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  webpack: (config: any, { isServer }: { isServer: boolean }) => {
    if (isServer) {
      const existing = Array.isArray(config.externals) ? config.externals : [];
      config.externals = [...existing, "pg-native"];
    }

    // Resolve `@pro/...` imports to either the real /pro directory
    // (hosted build) or the OSS stub (self-host / when the private
    // repo wasn't cloned at build time).
    config.resolve = config.resolve ?? {};
    config.resolve.alias = {
      ...(config.resolve.alias ?? {}),
      "@pro": PRO_ROOT,
    };

    return config;
  },
};

export default withNextIntl(nextConfig);
