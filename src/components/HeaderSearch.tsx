"use client";

import { useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { useRouter } from "@/i18n/navigation";

interface Suggestion {
  ecosystem: string;
  name: string;
  cve_count: number;
}

export function HeaderSearch() {
  const t = useTranslations("Nav");
  const [q, setQ] = useState("");
  const [items, setItems] = useState<Suggestion[]>([]);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);

  // Debounced fetch
  useEffect(() => {
    const term = q.trim();
    if (term.length < 2) {
      setItems([]);
      setOpen(false);
      return;
    }
    const t = setTimeout(async () => {
      try {
        const r = await fetch(`/api/v1/packages/autocomplete?q=${encodeURIComponent(term)}&limit=8`);
        const j = await r.json();
        setItems(j.data ?? []);
        setOpen(true);
        setActive(-1);
      } catch {
        /* ignore */
      }
    }, 120);
    return () => clearTimeout(t);
  }, [q]);

  // Click-outside closes
  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (formRef.current && !formRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  function go(s: Suggestion) {
    router.push(`/package/${encodeURIComponent(s.ecosystem)}/${encodeURIComponent(s.name)}`);
    setOpen(false);
    setQ("");
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (!open || items.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(items.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter" && active >= 0) {
      e.preventDefault();
      go(items[active]);
    } else if (e.key === "Escape") {
      setOpen(false);
    }
  }

  return (
    <form ref={formRef} action="/search" className="flex-1 max-w-xl relative">
      <input
        type="search"
        name="q"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onKeyDown={onKeyDown}
        autoComplete="off"
        placeholder={t("searchPlaceholder")}
        className="w-full rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-red-500"
      />
      {open && items.length > 0 && (
        <ul className="absolute left-0 right-0 top-full mt-1 z-50 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] shadow-lg max-h-80 overflow-y-auto">
          {items.map((s, i) => (
            <li
              key={`${s.ecosystem}/${s.name}`}
              onMouseDown={(e) => {
                e.preventDefault();
                go(s);
              }}
              onMouseEnter={() => setActive(i)}
              className={`flex items-baseline gap-2 px-3 py-1.5 text-sm cursor-pointer ${
                i === active ? "bg-[hsl(var(--muted))]" : ""
              }`}
            >
              <span className="text-xs font-mono uppercase text-[hsl(var(--muted-foreground))] w-16 shrink-0">
                {s.ecosystem}
              </span>
              <span className="font-mono flex-1 min-w-0 truncate">{s.name}</span>
              <span className="text-xs text-[hsl(var(--muted-foreground))] shrink-0">{s.cve_count}</span>
            </li>
          ))}
        </ul>
      )}
    </form>
  );
}
