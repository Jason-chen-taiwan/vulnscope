import type { Metadata } from "next";
import Link from "next/link";
import { HeaderSearch } from "@/components/HeaderSearch";
import "./globals.css";

export const metadata: Metadata = {
  title: "CVE Hub — package-centric vulnerability lookup",
  description:
    "Search CVEs by package and version across npm and PyPI. Sources: OSV.dev + CISA KEV.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b border-[hsl(var(--border))]">
          <nav className="mx-auto max-w-6xl px-4 py-3 flex items-center gap-6">
            <Link href="/" className="font-semibold text-lg no-underline">
              CVE<span className="text-red-600">·</span>Hub
            </Link>
            <HeaderSearch />
            <Link href="/packages" className="text-sm text-[hsl(var(--muted-foreground))] no-underline">Packages</Link>
            <Link href="/search?kev=true" className="text-sm text-[hsl(var(--muted-foreground))] no-underline">KEV</Link>
            <Link href="/search?severity=CRITICAL" className="text-sm text-[hsl(var(--muted-foreground))] no-underline">Critical</Link>
          </nav>
        </header>
        <main className="mx-auto max-w-6xl px-4 py-6">{children}</main>
        <footer className="mx-auto max-w-6xl px-4 py-10 text-xs text-[hsl(var(--muted-foreground))]">
          Data from <a href="https://osv.dev" className="underline">OSV.dev</a> and{" "}
          <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" className="underline">CISA KEV</a>.
          This is a Phase 0 MVP — npm + PyPI only.
        </footer>
      </body>
    </html>
  );
}
