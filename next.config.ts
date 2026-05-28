import type { NextConfig } from "next";
import type { Configuration } from "webpack";

const nextConfig: NextConfig = {
  outputFileTracingRoot: __dirname,
  serverExternalPackages: ["@renovatebot/pep440", "xregexp", "pg", "undici"],
  experimental: {
    serverActions: { bodySizeLimit: "2mb" },
  },
  webpack: (config: Configuration, { isServer }) => {
    // pg's native binding is optional; webpack tries to resolve it eagerly
    // and warns even when we never use it. Externalize on the server,
    // ignore on the (impossible) client edge case.
    if (isServer) {
      const existing = Array.isArray(config.externals) ? config.externals : [];
      config.externals = [...existing, "pg-native"];
    }
    return config;
  },
};

export default nextConfig;
