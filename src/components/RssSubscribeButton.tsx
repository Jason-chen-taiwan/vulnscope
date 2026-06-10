/**
 * Subscribe-to-RSS pill. Caller owns the link rel="alternate" tag in
 * <head> via Metadata.other (Next.js doesn't have a first-class hreflang-style
 * API for feeds), so this component is just the visible UI.
 */
export function RssSubscribeButton({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      className="inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-2.5 py-1 text-xs font-medium text-[hsl(var(--muted-foreground))] no-underline hover:bg-[hsl(var(--muted))] hover:text-[hsl(var(--foreground))]"
      title={label}
    >
      <svg
        width="12"
        height="12"
        viewBox="0 0 24 24"
        fill="currentColor"
        aria-hidden="true"
      >
        <path d="M6.18 15.64a2.18 2.18 0 1 1 0 4.36 2.18 2.18 0 0 1 0-4.36zM4 4.44A19.56 19.56 0 0 1 23.56 24h-2.83A16.74 16.74 0 0 0 4 7.27V4.44zm0 5.66A13.91 13.91 0 0 1 17.9 24h-2.84A11.07 11.07 0 0 0 4 12.94V10.1z" />
      </svg>
      <span>{label}</span>
    </a>
  );
}
