import { defineRouting } from "next-intl/routing";

export const routing = defineRouting({
  locales: ["en", "zh"] as const,
  defaultLocale: "en",
  // Always include the locale in the URL — keeps server/client/SEO behaviour
  // consistent and makes shared links unambiguous.
  localePrefix: "always",
});

export type Locale = (typeof routing.locales)[number];
