import { getTranslations, setRequestLocale } from "next-intl/server";
import { getRecentSyncJobs } from "@/lib/sync-jobs";
import { JobsAutoReload } from "./auto-reload";

function TriggerHint({ t }: { t: (key: string, values?: Record<string, string>) => string }) {
  const txt = t("triggerHint", { token: "__TOKEN__" });
  const [before, after] = txt.split("__TOKEN__");
  return (
    <span className="ml-3 text-xs text-[hsl(var(--muted-foreground))]">
      {before}
      <code className="font-mono">ADMIN_TOKEN</code>
      {after}
    </span>
  );
}

export const dynamic = "force-dynamic";

interface SyncJobRow {
  id: number;
  source: string;
  started_at: Date;
  finished_at: Date | null;
  status: string;
  records_seen: number | null;
  records_changed: number | null;
  error_message: string | null;
}

export default async function JobsPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "Jobs" });
  const dateLocale = locale === "zh" ? "zh-TW" : "en";
  const jobs = (await getRecentSyncJobs(100)) as SyncJobRow[];
  const anyRunning = jobs.some((j) => j.status === "running");
  return (
    <div className="space-y-4">
      {/* Live updates while anything is running. We can't use
          <meta http-equiv="refresh"> because Next.js client navigation
          carries the tag across route changes — users get yanked back to
          this page when they try to navigate elsewhere. Use a tiny inline
          script that only reloads while we're still on /admin/jobs, and
          stops the moment the user navigates away (pagehide / SPA route
          change both clear the timer). */}
      {anyRunning && <JobsAutoReload />}
      <header>
        <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">{t("subtitle")}</p>
      </header>
      <table className="w-full text-sm">
        <thead className="text-xs uppercase text-[hsl(var(--muted-foreground))]">
          <tr>
            <th className="text-left py-1 pr-3">{t("colSource")}</th>
            <th className="text-left py-1 pr-3">{t("colStarted")}</th>
            <th className="text-left py-1 pr-3">{t("colDuration")}</th>
            <th className="text-left py-1 pr-3">{t("colStatus")}</th>
            <th className="text-right py-1 pr-3">{t("colSeen")}</th>
            <th className="text-right py-1 pr-3">{t("colChanged")}</th>
            <th className="text-left py-1">{t("colError")}</th>
          </tr>
        </thead>
        <tbody className="font-mono text-xs">
          {jobs.map((j) => {
            const startMs = new Date(j.started_at).getTime();
            const endMs = j.finished_at ? new Date(j.finished_at).getTime() : Date.now();
            const elapsedSec = ((endMs - startMs) / 1000).toFixed(1);
            // 'running' shows live elapsed seconds with a small ⏱ prefix so
            // operators can tell at a glance it's still moving.
            const duration =
              j.status === "running" ? `⏱ ${elapsedSec}s` :
              j.finished_at ? `${elapsedSec}s` : "—";
            const cls =
              j.status === "success" ? "text-green-600" :
              j.status === "failed" ? "text-red-600" :
              "text-yellow-600";
            return (
              <tr key={j.id} className="border-t border-[hsl(var(--border))]">
                <td className="py-1 pr-3">{j.source}</td>
                <td className="py-1 pr-3">{new Date(j.started_at).toLocaleString(dateLocale)}</td>
                <td className="py-1 pr-3">{duration}</td>
                <td className={`py-1 pr-3 font-bold ${cls}`}>{j.status}</td>
                <td className="py-1 pr-3 text-right">{j.records_seen ?? "—"}</td>
                <td className="py-1 pr-3 text-right">{j.records_changed ?? "—"}</td>
                <td className="py-1 text-red-600">{j.error_message ?? ""}</td>
              </tr>
            );
          })}
          {jobs.length === 0 && (
            <tr>
              <td colSpan={7} className="py-4 text-center text-[hsl(var(--muted-foreground))]">
                {t("empty")}
              </td>
            </tr>
          )}
        </tbody>
      </table>
      {/* Manual trigger is only useful when an operator can actually call it.
          Without ADMIN_TOKEN the endpoint is loopback-only, so on a hosted
          demo the button would just 401 every random visitor — hide it. */}
      {process.env.ADMIN_TOKEN ? (
        <form action="/api/v1/admin/refresh" method="post">
          <button
            type="submit"
            className="rounded-md bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 px-4 py-1.5 text-sm font-medium"
          >
            {t("trigger")}
          </button>
          <TriggerHint t={t} />
        </form>
      ) : (
        <p className="text-xs text-[hsl(var(--muted-foreground))]">
          <TriggerHint t={t} />
        </p>
      )}
    </div>
  );
}
