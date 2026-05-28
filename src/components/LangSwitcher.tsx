"use client";

import { useLocale } from "next-intl";
import { usePathname, useRouter } from "@/i18n/navigation";
import type { Locale } from "@/i18n/routing";

const OPTIONS: { code: Locale; label: string }[] = [
  { code: "en", label: "EN" },
  { code: "zh", label: "中" },
];

export function LangSwitcher() {
  const router = useRouter();
  const pathname = usePathname();
  const active = useLocale() as Locale;

  return (
    <div
      className="flex items-center gap-0.5 rounded border border-[hsl(var(--border))] p-0.5 text-xs"
      role="group"
      aria-label="Language"
    >
      {OPTIONS.map((o) => {
        const isActive = o.code === active;
        return (
          <button
            key={o.code}
            type="button"
            onClick={() => router.replace(pathname, { locale: o.code })}
            className={`px-2 py-0.5 rounded ${
              isActive
                ? "bg-zinc-900 text-white dark:bg-white dark:text-zinc-900"
                : "text-[hsl(var(--muted-foreground))]"
            }`}
            aria-pressed={isActive}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
