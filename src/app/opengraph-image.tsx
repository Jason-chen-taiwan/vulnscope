import { ImageResponse } from "next/og";

// No `runtime = "edge"`: OpenNext requires edge-runtime routes to be a
// separate function, and on Cloudflare Workers everything already runs on
// workerd. next/og's ImageResponse works in the default server bundle.
export const alt = "VulnScope — package-centric CVE lookup";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpenGraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          background: "#0a0a0a",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          padding: "80px",
          fontFamily: "ui-sans-serif, system-ui",
          color: "#fafafa",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 20, marginBottom: 40 }}>
          <div
            style={{
              width: 100,
              height: 100,
              borderRadius: 20,
              background: "#171717",
              border: "2px solid #262626",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              position: "relative",
              fontSize: 64,
              fontWeight: 700,
              fontFamily: "ui-monospace, monospace",
            }}
          >
            V
            <div
              style={{
                position: "absolute",
                right: 12,
                bottom: 18,
                width: 16,
                height: 16,
                borderRadius: 999,
                background: "#dc2626",
              }}
            />
          </div>
          <div style={{ fontSize: 96, fontWeight: 700, letterSpacing: -2, display: "flex" }}>
            Vuln
            <span style={{ color: "#dc2626", margin: "0 6px" }}>·</span>
            Scope
          </div>
        </div>
        <div style={{ fontSize: 36, color: "#a3a3a3", maxWidth: 1000, lineHeight: 1.3 }}>
          Package-centric CVE lookup. 74k+ vulnerabilities across 14 ecosystems.
        </div>
        <div style={{ marginTop: 50, display: "flex", gap: 14, fontSize: 22, color: "#737373" }}>
          <span>OSV.dev</span>
          <span>·</span>
          <span>CISA KEV</span>
          <span>·</span>
          <span>EPSS</span>
          <span>·</span>
          <span style={{ color: "#dc2626" }}>self-hosted, MIT</span>
        </div>
      </div>
    ),
    { ...size },
  );
}
