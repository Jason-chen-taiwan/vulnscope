/**
 * Shared loading skeleton for all force-dynamic SSR pages. Rendered
 * via Next.js's `loading.tsx` convention as the Suspense fallback
 * while the server is rendering the real page.
 *
 * One component, several variants — keeps the look consistent across
 * the site and means a layout change to (e.g.) the CVE detail page
 * skeleton only happens here, not in five separate files.
 *
 * Variants mirror the actual page layouts so the swap from skeleton
 * → real content doesn't jump the viewport.
 */
type Variant = "default" | "cve" | "search" | "packages";

const SHIMMER =
  "bg-[hsl(var(--muted))] animate-pulse rounded";

function Bar({ className = "" }: { className?: string }) {
  return <div className={`${SHIMMER} ${className}`} aria-hidden />;
}

function Card({ children, className = "" }: { children?: React.ReactNode; className?: string }) {
  return (
    <div
      className={`rounded-lg border border-[hsl(var(--border))] p-5 ${className}`}
    >
      {children}
    </div>
  );
}

function DefaultSkeleton() {
  return (
    <div className="space-y-8">
      <div className="space-y-3">
        <Bar className="h-8 w-48" />
        <Bar className="h-4 w-96 max-w-full" />
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i}>
            <Bar className="h-3 w-20 mb-3" />
            <Bar className="h-7 w-24" />
          </Card>
        ))}
      </div>
      <div className="grid lg:grid-cols-2 gap-6">
        {Array.from({ length: 2 }).map((_, i) => (
          <Card key={i}>
            <Bar className="h-5 w-40 mb-4" />
            <div className="space-y-2">
              {Array.from({ length: 6 }).map((_, j) => (
                <Bar key={j} className="h-4 w-full" />
              ))}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

function CveSkeleton() {
  return (
    <div className="space-y-6">
      {/* Severity hero */}
      <Card className="border-l-4 border-l-[hsl(var(--muted))]">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0 flex-1 space-y-3">
            <Bar className="h-7 w-48" />
            <Bar className="h-5 w-3/4" />
            <Bar className="h-5 w-1/2" />
          </div>
          <div className="shrink-0 space-y-2 sm:text-right">
            <Bar className="h-12 w-20 ml-auto" />
            <Bar className="h-3 w-16 ml-auto" />
            <Bar className="h-2.5 w-14 ml-auto" />
          </div>
        </div>
        <div className="mt-4 flex gap-2">
          <Bar className="h-5 w-16" />
          <Bar className="h-5 w-20" />
        </div>
      </Card>
      <div className="grid gap-6 lg:grid-cols-[1fr_280px]">
        <div className="min-w-0 space-y-6">
          {Array.from({ length: 3 }).map((_, i) => (
            <Card key={i}>
              <Bar className="h-5 w-32 mb-4" />
              <div className="space-y-2">
                <Bar className="h-3.5 w-full" />
                <Bar className="h-3.5 w-full" />
                <Bar className="h-3.5 w-3/4" />
              </div>
            </Card>
          ))}
        </div>
        <aside className="space-y-6">
          <Card>
            <Bar className="h-3 w-16 mb-4" />
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="flex justify-between gap-3">
                  <Bar className="h-3 w-16" />
                  <Bar className="h-3 w-20" />
                </div>
              ))}
            </div>
          </Card>
        </aside>
      </div>
    </div>
  );
}

function SearchSkeleton() {
  return (
    <div className="space-y-6">
      <Bar className="h-7 w-40" />
      <div className="flex flex-wrap gap-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <Bar key={i} className="h-8 w-24" />
        ))}
      </div>
      <ul className="divide-y divide-[hsl(var(--border))] rounded-lg border border-[hsl(var(--border))]">
        {Array.from({ length: 10 }).map((_, i) => (
          <li key={i} className="px-4 py-3 flex items-baseline gap-3">
            <Bar className="h-5 w-16 shrink-0" />
            <Bar className="h-4 w-32 shrink-0" />
            <Bar className="h-4 flex-1" />
            <Bar className="h-3 w-16 shrink-0" />
          </li>
        ))}
      </ul>
    </div>
  );
}

function PackagesSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex items-baseline justify-between">
        <Bar className="h-7 w-32" />
        <Bar className="h-4 w-48" />
      </div>
      <div className="flex flex-wrap gap-2">
        <Bar className="h-9 w-64" />
        <Bar className="h-9 w-36" />
        <Bar className="h-9 w-24" />
      </div>
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {Array.from({ length: 12 }).map((_, i) => (
          <Card key={i}>
            <div className="flex items-baseline gap-2">
              <Bar className="h-3 w-12 shrink-0" />
              <Bar className="h-4 flex-1" />
              <Bar className="h-3 w-8 shrink-0" />
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

export function PageSkeleton({ variant = "default" }: { variant?: Variant }) {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-label="Loading page"
      className="motion-reduce:animate-none"
    >
      <span className="sr-only">Loading…</span>
      {variant === "cve" && <CveSkeleton />}
      {variant === "search" && <SearchSkeleton />}
      {variant === "packages" && <PackagesSkeleton />}
      {variant === "default" && <DefaultSkeleton />}
    </div>
  );
}
