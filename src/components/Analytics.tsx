/**
 * Privacy-friendly analytics (Plausible by default). Renders nothing
 * unless NEXT_PUBLIC_PLAUSIBLE_DOMAIN is set, so the OSS repo and any
 * self-host stay tracker-free.
 */
import Script from "next/script";

export function Analytics() {
  const domain = process.env.NEXT_PUBLIC_PLAUSIBLE_DOMAIN;
  const src = process.env.NEXT_PUBLIC_PLAUSIBLE_SRC ?? "https://plausible.io/js/script.js";
  if (!domain) return null;
  return <Script defer src={src} data-domain={domain} strategy="afterInteractive" />;
}
