import type { MetadataRoute } from "next";

const SITE = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        // /search is a faceted-URL crawler trap: severity × ecosystem × page
        // combinations are unbounded, and each filtered request runs a
        // relatively expensive D1 count. Crawlers hammering these combos
        // drove D1 into CPU-limit resets (2026-07-08 incident). Search
        // results shouldn't be indexed anyway.
        disallow: ["/admin/", "/api/", "/en/search", "/zh/search", "/*/search"],
      },
    ],
    sitemap: `${SITE}/sitemap.xml`,
  };
}
