export function EpssBadge({ score, percentile }: { score: number | null; percentile?: number | null }) {
  if (score === null || score === undefined) return null;
  const pct = score * 100;
  const color =
    score >= 0.5 ? "bg-red-600 text-white"
    : score >= 0.1 ? "bg-orange-500 text-white"
    : score >= 0.01 ? "bg-yellow-400 text-black"
    : "bg-zinc-200 text-zinc-700 dark:bg-zinc-700 dark:text-zinc-200";
  const label = pct >= 1 ? `EPSS ${pct.toFixed(1)}%` : `EPSS ${pct.toFixed(2)}%`;
  const title = percentile != null
    ? `${pct.toFixed(2)}% probability of exploitation in 30 days · top ${(100 - percentile * 100).toFixed(1)}%`
    : `${pct.toFixed(2)}% probability of exploitation in 30 days`;
  return (
    <span title={title} className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide font-mono ${color}`}>
      {label}
    </span>
  );
}
