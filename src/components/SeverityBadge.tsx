const STYLES: Record<string, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-600 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-green-600 text-white",
  NONE: "bg-zinc-300 text-zinc-700",
};

export function SeverityBadge({
  severity,
  score,
}: {
  severity: string | null;
  score?: number | null;
}) {
  const label = severity ?? "—";
  const cls = STYLES[severity ?? ""] ?? "bg-zinc-200 text-zinc-800";
  return (
    <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide ${cls}`}>
      {label}
      {typeof score === "number" && <span className="font-mono opacity-90">{score.toFixed(1)}</span>}
    </span>
  );
}

export function KevBadge({ kev }: { kev: boolean }) {
  if (!kev) return null;
  return (
    <span className="inline-flex items-center gap-1 rounded bg-[hsl(15,82%,30%)] px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-white">
      ⚠ KEV
    </span>
  );
}
