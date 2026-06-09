"use client";

import { useState, useTransition } from "react";
import { useTranslations } from "next-intl";

interface CheckResponse {
  data: {
    package: { ecosystem: string; name: string };
    version: string;
    is_vulnerable: boolean;
    affected_by: Array<{
      cve_id: string;
      severity: string | null;
      base_score: number | null;
      kev: boolean;
      fixed_in: string | null;
      summary: string | null;
    }>;
    recommended_version: string | null;
  } | null;
  errors?: Array<{ code: string; message: string }>;
}

// All ecosystems with a dedicated comparator wired up in
// src/lib/version/index.ts. Kept as a literal here so this
// "use client" component doesn't have to import server-only code.
// Add new ecosystems to both places.
const SUPPORTED_ECOSYSTEMS = new Set([
  "npm",
  "PyPI",
  "Maven",
  "Go",
  "RubyGems",
  "Packagist",
  "crates.io",
  "NuGet",
  "Hex",
  "Hackage",
  "Debian",
  "Alpine",
  "Bitnami",
]);

export function VersionChecker({
  ecosystem,
  name,
}: {
  ecosystem: string;
  name: string;
}) {
  const t = useTranslations("Package.checker");
  const [v, setV] = useState("");
  const [result, setResult] = useState<CheckResponse["data"] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!v.trim()) return;
    setError(null);
    setResult(null);
    start(async () => {
      try {
        const r = await fetch(
          `/api/v1/packages/${encodeURIComponent(ecosystem)}/${encodeURIComponent(name)}/check?version=${encodeURIComponent(v.trim())}`,
        );
        const json = (await r.json()) as CheckResponse;
        if (!r.ok || !json.data) {
          // Surface the API error envelope so the user gets feedback
          // instead of a silent no-op (e.g. 400 UNSUPPORTED_ECOSYSTEM
          // on Debian/Maven/Go, 404 NOT_FOUND for unknown packages).
          const msg = json.errors?.[0]?.message ?? `HTTP ${r.status}`;
          setError(msg);
          return;
        }
        setResult(json.data);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
    });
  }

  // Hide entirely for ecosystems we can't compare versions in.
  // The package detail page still shows the CVE list — the
  // checker just isn't useful for, say, "is openssl 1.1.1 affected"
  // when we don't have a Debian version comparator wired up.
  if (!SUPPORTED_ECOSYSTEMS.has(ecosystem)) {
    return null;
  }

  const placeholder =
    ecosystem === "npm" ? t("placeholderNpm") :
    ecosystem === "PyPI" ? t("placeholderPypi") :
    t("placeholderGeneric");

  return (
    <div className="rounded-lg border border-[hsl(var(--border))] p-4 space-y-3">
      <h2 className="font-semibold">{t("title")}</h2>
      <form onSubmit={submit} className="flex gap-2">
        <input
          value={v}
          onChange={(e) => setV(e.target.value)}
          placeholder={placeholder}
          className="flex-1 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-3 py-1.5 text-sm font-mono outline-none focus:ring-2 focus:ring-red-500"
        />
        <button
          type="submit"
          disabled={pending}
          className="rounded-md bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 px-4 py-1.5 text-sm font-medium disabled:opacity-50"
        >
          {pending ? t("checking") : t("check")}
        </button>
      </form>

      {error && <p className="text-sm text-red-600">{error}</p>}

      {result && (
        <div className="space-y-2 text-sm">
          {result.is_vulnerable ? (
            <div className="rounded bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 p-3">
              <p className="font-medium text-red-700 dark:text-red-300">
                {t("vulnerable", { version: result.version, n: result.affected_by.length })}
              </p>
              {result.recommended_version && (
                <p className="text-xs mt-1">
                  {t("recommended", { version: result.recommended_version })}
                </p>
              )}
              <ul className="mt-2 space-y-1 text-xs">
                {result.affected_by.map((m) => (
                  <li key={m.cve_id} className="font-mono">
                    <a href={`/cve/${m.cve_id}`}>{m.cve_id}</a>
                    {m.severity && <span className="ml-2 opacity-70">[{m.severity}]</span>}
                    {m.kev && <span className="ml-2 text-[hsl(15,82%,30%)] font-bold">KEV</span>}
                    {m.fixed_in && (
                      <span className="ml-2 opacity-70">{t("fixedIn", { version: m.fixed_in })}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="rounded bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-900 p-3">
              <p className="font-medium text-green-700 dark:text-green-300">
                {t("clean", { version: result.version })}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
