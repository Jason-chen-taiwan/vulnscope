import { ImageResponse } from "next/og";

// No `runtime = "edge"`: OpenNext requires edge-runtime routes to be a
// separate function, and on Cloudflare Workers everything already runs on
// workerd. next/og's ImageResponse works in the default server bundle.
export const size = { width: 180, height: 180 };
export const contentType = "image/png";

export default function AppleIcon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          background: "#0a0a0a",
          borderRadius: 34,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          position: "relative",
          color: "#fafafa",
          fontSize: 108,
          fontWeight: 700,
          fontFamily: "ui-monospace, monospace",
          letterSpacing: -6,
        }}
      >
        V
        <div
          style={{
            position: "absolute",
            right: 32,
            bottom: 42,
            width: 28,
            height: 28,
            borderRadius: 999,
            background: "#dc2626",
          }}
        />
      </div>
    ),
    { ...size },
  );
}
