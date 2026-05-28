"use client";

import { useState, useTransition } from "react";

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
  };
}

export function VersionChecker({
  ecosystem,
  name,
}: {
  ecosystem: string;
  name: string;
}) {
  const [v, setV] = useState("");
  const [result, setResult] = useState<CheckResponse["data"] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!v.trim()) return;
    setError(null);
    start(async () => {
      try {
        const r = await fetch(
          `/api/v1/packages/${encodeURIComponent(ecosystem)}/${encodeURIComponent(name)}/check?version=${encodeURIComponent(v.trim())}`,
        );
        const json = (await r.json()) as CheckResponse;
        setResult(json.data);
      } catch (err) {
        setError(String(err));
      }
    });
  }

  return (
    <div className="rounded-lg border border-[hsl(var(--border))] p-4 space-y-3">
      <h2 className="font-semibold">✅ Check your installed version</h2>
      <form onSubmit={submit} className="flex gap-2">
        <input
          value={v}
          onChange={(e) => setV(e.target.value)}
          placeholder={ecosystem === "npm" ? "e.g. 4.17.20" : "e.g. 3.2.0"}
          className="flex-1 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-3 py-1.5 text-sm font-mono outline-none focus:ring-2 focus:ring-red-500"
        />
        <button
          type="submit"
          disabled={pending}
          className="rounded-md bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 px-4 py-1.5 text-sm font-medium disabled:opacity-50"
        >
          {pending ? "Checking…" : "Check"}
        </button>
      </form>

      {error && <p className="text-sm text-red-600">{error}</p>}

      {result && (
        <div className="space-y-2 text-sm">
          {result.is_vulnerable ? (
            <div className="rounded bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 p-3">
              <p className="font-medium text-red-700 dark:text-red-300">
                ⚠ {result.version} is affected by {result.affected_by.length} CVE
                {result.affected_by.length === 1 ? "" : "s"}.
              </p>
              {result.recommended_version && (
                <p className="text-xs mt-1">
                  Recommended upgrade target:{" "}
                  <code className="font-mono font-bold">{result.recommended_version}</code>
                </p>
              )}
              <ul className="mt-2 space-y-1 text-xs">
                {result.affected_by.map((m) => (
                  <li key={m.cve_id} className="font-mono">
                    <a href={`/cve/${m.cve_id}`}>{m.cve_id}</a>
                    {m.severity && <span className="ml-2 opacity-70">[{m.severity}]</span>}
                    {m.kev && <span className="ml-2 text-[hsl(15,82%,30%)] font-bold">KEV</span>}
                    {m.fixed_in && (
                      <span className="ml-2 opacity-70">fixed in {m.fixed_in}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="rounded bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-900 p-3">
              <p className="font-medium text-green-700 dark:text-green-300">
                ✓ {result.version} is not affected by any known CVE in this DB.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
