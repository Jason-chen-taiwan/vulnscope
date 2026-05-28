// This file exists only because Next.js requires a root layout. The real
// layout (html + body + nav + i18n providers) lives in app/[locale]/layout.tsx
// so it can access the active locale via route params.
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return children;
}
