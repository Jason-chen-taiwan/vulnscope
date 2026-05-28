import { ImageResponse } from "next/og";

export const runtime = "edge";
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
        C
        <div
          style={{
            position: "absolute",
            right: 38,
            bottom: 50,
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
