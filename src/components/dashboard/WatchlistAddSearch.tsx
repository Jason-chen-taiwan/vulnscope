"use client";

import { useEffect, useRef, useState, useTransition } from "react";
import { useTranslations } from "next-intl";

import { SeverityBadge, KevBadge } from "@/components/SeverityBadge";
import { EpssBadge } from "@/components/EpssBadge";

import type { ClientWatchlistRow } from "./types";

interface Suggestion {
  ecosystem: string;
  name: string;
  cve_count: number;
}

interface VersionCheck {
  is_vulnerable: boolean;
  affected_by: Array<{
    cve_id: string;
    severity: string | null;
    base_score: number | null;
    kev: boolean;
    epss_score: number | null;
    fixed_in: string | null;
  }>;
  recommended_version: string | null;
}

interface Props {
  onAdded: (row: ClientWatchlistRow) => void;
  onLimitReached: () => void;
  disabled?: boolean;
}

/**
 * Three-stage add flow:
 *
 *   1. Autocomplete a package by name (reuses
 *      /api/v1/packages/autocomplete + the keyboard/click-outside
 *      patterns from HeaderSearch).
 *   2. Pick a version from the OSV-known version dropdown. "Any
 *      version" stays as the first option for users who don't want
 *      to pin a specific release.
 *   3. Preview "currently affected by N CVEs" (via the existing
 *      /api/v1/packages/{eco}/{name}/check endpoint), then commit.
 *
 * This is the differentiator: Snyk/Dependabot only know about
 * dependencies from a manifest. We let the user pin any version
 * they actually run in production and surface its exact CVE state
 * before they even sign up for alerts.
 */
export function WatchlistAddSearch({ onAdded, onLimitReached, disabled }: Props) {
  const t = useTranslations("Dashboard");

  // Stage 1: search input
  const [q, setQ] = useState("");
  const [items, setItems] = useState<Suggestion[]>([]);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const wrapRef = useRef<HTMLDivElement>(null);

  // Stage 2/3: picked package + version selection
  const [picked, setPicked] = useState<Suggestion | null>(null);
  const [versions, setVersions] = useState<string[]>([]);
  const [versionsLoading, setVersionsLoading] = useState(false);
  const [selectedVersion, setSelectedVersion] = useState<string>("");
  const [customVersion, setCustomVersion] = useState<string>("");
  const [check, setCheck] = useState<VersionCheck | null>(null);
  const [checking, setChecking] = useState(false);

  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  // ----- Stage 1: debounced autocomplete -----
  useEffect(() => {
    if (picked) return;
    const term = q.trim();
    if (term.length < 2) {
      setItems([]);
      setOpen(false);
      return;
    }
    const id = setTimeout(async () => {
      try {
        const r = await fetch(
          `/api/v1/packages/autocomplete?q=${encodeURIComponent(term)}&limit=8`,
        );
        const j = await r.json();
        setItems(j.data ?? []);
        setOpen(true);
        setActive(-1);
      } catch {
        /* ignore */
      }
    }, 120);
    return () => clearTimeout(id);
  }, [q, picked]);

  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  // Allow the empty-state "popular packages" buttons to drive us
  // straight to the version-pick UI without retyping.
  useEffect(() => {
    function onPick(e: Event) {
      const detail = (e as CustomEvent<{ ecosystem: string; name: string }>)
        .detail;
      if (!detail) return;
      pickSuggestion({ ecosystem: detail.ecosystem, name: detail.name, cve_count: 0 });
    }
    window.addEventListener("vulnscope:watchlist:pick", onPick);
    return () => window.removeEventListener("vulnscope:watchlist:pick", onPick);
    // pickSuggestion is stable enough here; we deliberately omit it
    // from deps to keep one global listener and avoid double-pick on
    // re-renders.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ----- Stage 2: load versions when a package is picked -----
  useEffect(() => {
    if (!picked) return;
    setVersionsLoading(true);
    setVersions([]);
    // Default to "any version" so the Add button is immediately
    // enabled — the select renders __any__ as the visible first
    // option regardless, so this just brings state into line with
    // what the user already sees on screen.
    setSelectedVersion("__any__");
    setCustomVersion("");
    setCheck(null);
    (async () => {
      try {
        const r = await fetch(
          `/api/v1/packages/${encodeURIComponent(picked.ecosystem)}/${encodeURIComponent(picked.name)}/versions`,
        );
        const j = await r.json();
        setVersions(j.data ?? []);
      } catch {
        setVersions([]);
      } finally {
        setVersionsLoading(false);
      }
    })();
  }, [picked]);

  // ----- Stage 3: check selected version against CVEs -----
  const versionToCheck = customVersion.trim() || selectedVersion;
  useEffect(() => {
    if (!picked || !versionToCheck || versionToCheck === "__any__") {
      setCheck(null);
      return;
    }
    setChecking(true);
    const id = setTimeout(async () => {
      try {
        const r = await fetch(
          `/api/v1/packages/${encodeURIComponent(picked.ecosystem)}/${encodeURIComponent(picked.name)}/check?version=${encodeURIComponent(versionToCheck)}`,
        );
        const j = await r.json();
        setCheck(j.data ?? null);
      } catch {
        setCheck(null);
      } finally {
        setChecking(false);
      }
    }, 200);
    return () => clearTimeout(id);
  }, [picked, versionToCheck]);

  function pickSuggestion(s: Suggestion) {
    setPicked(s);
    setOpen(false);
    setQ(`${s.ecosystem} / ${s.name}`);
    setError(null);
  }

  function reset() {
    setPicked(null);
    setQ("");
    setItems([]);
    setVersions([]);
    setSelectedVersion("");
    setCustomVersion("");
    setCheck(null);
    setError(null);
  }

  function add() {
    if (!picked) return;
    setError(null);
    const versionToSend =
      versionToCheck && versionToCheck !== "__any__" ? versionToCheck : null;
    startTransition(async () => {
      try {
        const r = await fetch("/api/v1/watchlist", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            ecosystem: picked.ecosystem,
            packageName: picked.name,
            version: versionToSend,
          }),
        });
        if (r.status === 402) {
          onLimitReached();
          return;
        }
        if (!r.ok) {
          setError(t("addError"));
          return;
        }
        const listR = await fetch("/api/v1/watchlist");
        const listJson = await listR.json();
        const fresh = (listJson.data as ClientWatchlistRow[]).find(
          (row) =>
            row.ecosystem === picked.ecosystem &&
            row.packageName === picked.name &&
            (row.version ?? "") === (versionToSend ?? ""),
        );
        if (fresh) onAdded(fresh);
        reset();
      } catch {
        setError(t("addError"));
      }
    });
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
      pickSuggestion(items[active]);
    } else if (e.key === "Escape") {
      setOpen(false);
    }
  }

  // ----- Render -----
  return (
    <div className="space-y-2">
      <div ref={wrapRef} className="relative">
        <div className="flex gap-2">
          <input
            type="search"
            value={q}
            onChange={(e) => {
              if (picked) reset();
              setQ(e.target.value);
            }}
            onKeyDown={onKeyDown}
            disabled={disabled || pending}
            autoComplete="off"
            placeholder={t("addPlaceholder")}
            className="flex-1 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-red-500 disabled:opacity-50"
          />
          {picked && (
            <button
              type="button"
              onClick={reset}
              className="rounded-md border border-[hsl(var(--border))] px-3 py-2 text-xs text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))]"
            >
              ✕
            </button>
          )}
        </div>
        {!picked && open && items.length > 0 && (
          <ul className="absolute left-0 right-0 top-full mt-1 z-50 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] shadow-lg max-h-80 overflow-y-auto">
            {items.map((s, i) => (
              <li
                key={`${s.ecosystem}/${s.name}`}
                onMouseDown={(e) => {
                  e.preventDefault();
                  pickSuggestion(s);
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
                <span className="text-xs text-[hsl(var(--muted-foreground))] shrink-0">
                  {s.cve_count}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Stage 2/3: version + preview */}
      {picked && (
        <div className="rounded-md border border-[hsl(var(--border))] p-3 space-y-3 text-sm">
          <div className="flex items-center gap-2 flex-wrap">
            <label className="text-xs text-[hsl(var(--muted-foreground))]">
              {t("versionLabel")}
            </label>
            <select
              value={selectedVersion}
              onChange={(e) => {
                setSelectedVersion(e.target.value);
                setCustomVersion("");
              }}
              disabled={versionsLoading}
              className="rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-2 py-1 text-sm"
            >
              <option value="__any__">{t("versionAny")}</option>
              {versionsLoading && <option>…</option>}
              {!versionsLoading &&
                versions.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
            </select>
            <span className="text-xs text-[hsl(var(--muted-foreground))]">
              {t("versionOr")}
            </span>
            <input
              type="text"
              value={customVersion}
              onChange={(e) => {
                setCustomVersion(e.target.value);
                setSelectedVersion("");
              }}
              placeholder={t("versionCustomPlaceholder")}
              className="rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-2 py-1 text-sm font-mono w-32"
            />
          </div>

          {/* CVE preview */}
          {versionToCheck && versionToCheck !== "__any__" && (
            <div className="rounded-md bg-[hsl(var(--muted))] p-2 text-xs space-y-1">
              {checking ? (
                <p className="text-[hsl(var(--muted-foreground))]">
                  {t("checking")}
                </p>
              ) : check === null ? (
                <p className="text-[hsl(var(--muted-foreground))]">
                  {t("checkUnknown")}
                </p>
              ) : check.is_vulnerable ? (
                <>
                  <p className="font-medium">
                    {t("checkAffected", {
                      n: check.affected_by.length,
                      kev: check.affected_by.filter((a) => a.kev).length,
                    })}
                  </p>
                  <ul className="space-y-1">
                    {check.affected_by.slice(0, 3).map((a) => (
                      <li key={a.cve_id} className="flex items-baseline gap-1.5">
                        <span className="font-mono">{a.cve_id}</span>
                        <SeverityBadge severity={a.severity} score={a.base_score} />
                        <KevBadge kev={a.kev} />
                        <EpssBadge score={a.epss_score} />
                        {a.fixed_in && (
                          <span className="text-[hsl(var(--muted-foreground))] ml-auto">
                            {t("fixedIn", { v: a.fixed_in })}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                  {check.recommended_version && (
                    <p className="text-[hsl(var(--muted-foreground))]">
                      {t("recommendVersion", { v: check.recommended_version })}
                    </p>
                  )}
                </>
              ) : (
                <p className="text-green-600 dark:text-green-400 font-medium">
                  {t("checkClean")}
                </p>
              )}
            </div>
          )}

          {versionToCheck === "__any__" && (
            <p className="text-xs text-[hsl(var(--muted-foreground))]">
              {t("anyVersionHint")}
            </p>
          )}

          <button
            type="button"
            onClick={add}
            disabled={pending || (!selectedVersion && !customVersion.trim())}
            className="w-full rounded-md bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] py-2 text-sm font-medium hover:opacity-90 disabled:opacity-50"
          >
            {pending ? "…" : t("addCta")}
          </button>
        </div>
      )}

      {error && <p className="text-xs text-red-500">{error}</p>}
    </div>
  );
}
