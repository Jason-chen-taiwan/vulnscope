import type { Metadata } from "next";
import Link from "next/link";
import { HeaderSearch } from "@/components/HeaderSearch";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "VulnScope — package-centric CVE lookup",
    template: "%s · VulnScope",
  },
  description:
    "Self-hosted CVE search across 14 ecosystems. Package-centric: paste a version, see what's exploitable. Powered by OSV.dev, CISA KEV, and EPSS.",
  applicationName: "VulnScope",
  openGraph: {
    type: "website",
    siteName: "VulnScope",
    title: "VulnScope — package-centric CVE lookup",
    description:
      "Self-hosted CVE search across 14 ecosystems. Package-centric: paste a version, see what's exploitable.",
  },
  twitter: {
    card: "summary_large_image",
    title: "VulnScope",
    description: "Package-centric CVE lookup across 14 ecosystems",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b border-[hsl(var(--border))]">
          <nav className="mx-auto max-w-6xl px-4 py-3 flex items-center gap-6">
            <Link href="/" className="font-semibold text-lg no-underline" title="Home">
              Vuln<span className="text-red-600">·</span>Scope
            </Link>
            <HeaderSearch />
            <Link href="/" className="text-sm text-[hsl(var(--muted-foreground))] no-underline">Home</Link>
            <Link href="/packages" className="text-sm text-[hsl(var(--muted-foreground))] no-underline">Packages</Link>
            <Link href="/search?kev=true" className="text-sm text-[hsl(var(--muted-foreground))] no-underline">KEV</Link>
            <Link href="/search?severity=CRITICAL" className="text-sm text-[hsl(var(--muted-foreground))] no-underline">Critical</Link>
            <Link href="/admin/jobs" className="text-sm text-[hsl(var(--muted-foreground))] no-underline" title="Data refresh status">Jobs</Link>
          </nav>
        </header>
        <main className="mx-auto max-w-6xl px-4 py-6">{children}</main>
        <footer className="mx-auto max-w-6xl px-4 py-10 text-xs text-[hsl(var(--muted-foreground))] flex flex-wrap gap-x-4 gap-y-1">
          <span>
            Data from{" "}
            <a href="https://osv.dev" className="underline" target="_blank" rel="noreferrer">OSV.dev</a>,{" "}
            <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" className="underline" target="_blank" rel="noreferrer">CISA KEV</a>, and{" "}
            <a href="https://www.first.org/epss/" className="underline" target="_blank" rel="noreferrer">FIRST EPSS</a>.
          </span>
          <span className="ml-auto flex gap-3">
            <Link href="/admin/jobs" className="underline">Sync status</Link>
            <a href="https://github.com/Jason-chen-taiwan/vulnscope" className="underline" target="_blank" rel="noreferrer">GitHub</a>
          </span>
        </footer>
      </body>
    </html>
  );
}
