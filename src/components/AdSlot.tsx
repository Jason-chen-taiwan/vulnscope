/**
 * Sidebar ad slot. Designed for Carbon Ads or EthicalAds — dev-focused
 * networks that respect the audience (one static image + a line of text).
 *
 * Renders nothing unless NEXT_PUBLIC_ADS_ENABLED=true, so self-hosters
 * never see ads and the OSS repo stays clean. The operator of the hosted
 * demo can also set NEXT_PUBLIC_CARBON_SRC once their application is
 * approved — until then we show a neutral "Sponsor placeholder" so we
 * can verify layout without inviting third-party tracking.
 */
"use client";

import Script from "next/script";

export function AdSlot({ placement = "sidebar" }: { placement?: "sidebar" | "footer" }) {
  if (process.env.NEXT_PUBLIC_ADS_ENABLED !== "true") return null;
  const carbonSrc = process.env.NEXT_PUBLIC_CARBON_SRC;
  if (carbonSrc) {
    return (
      <aside className={`vs-ad vs-ad-${placement}`}>
        <Script src={carbonSrc} async id="_carbonads_js" strategy="afterInteractive" />
      </aside>
    );
  }
  // Placeholder: layout slot is reserved but no third-party script runs.
  return (
    <aside
      className={`vs-ad vs-ad-${placement} rounded border border-dashed border-[hsl(var(--border))] p-3 text-xs text-[hsl(var(--muted-foreground))]`}
      aria-label="Sponsor placeholder"
    >
      Sponsor slot. Reach out for partnership.
    </aside>
  );
}
