import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

const withNextIntl = createNextIntlPlugin("./src/i18n/request.ts");

const nextConfig: NextConfig = {
  serverExternalPackages: [
    "@renovatebot/pep440",
    "xregexp",
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

    return config;
  },
};

export default withNextIntl(nextConfig);

// Populate `getCloudflareContext().env` (the D1 `DB` binding, etc.) during
// `next dev` so server code that reads bindings works in local development.
// No-op in production builds.
import { initOpenNextCloudflareForDev } from "@opennextjs/cloudflare";
void initOpenNextCloudflareForDev();
