import pc from "picocolors";
import type { VersionCheckResult, AffectedCve } from "../api.js";

export interface TableOptions {
  color: boolean;
  severities?: Set<string>;
  ignore?: Set<string>;
}

interface Row {
  severity: string;
  cve: string;
  pkg: string;
  installed: string;
  fixed: string;
  kev: string;
  epss: string;
  summary: string;
}

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 };

export function renderTable(results: VersionCheckResult[], opts: TableOptions): string {
  const rows = collectRows(results, opts);
  if (rows.length === 0) return "";
  rows.sort((a, b) => {
    const sr = (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99);
    if (sr !== 0) return sr;
    return a.pkg.localeCompare(b.pkg);
  });
  return renderAscii(rows, opts.color);
}

function collectRows(results: VersionCheckResult[], opts: TableOptions): Row[] {
  const out: Row[] = [];
  for (const r of results) {
    if (!r.is_vulnerable) continue;
    for (const c of r.affected_by) {
      if (opts.ignore?.has(c.cve_id)) continue;
      const sev = c.severity ?? "NONE";
      if (opts.severities && !opts.severities.has(sev)) continue;
      out.push({
        severity: sev,
        cve: c.cve_id,
        pkg: `${r.package.ecosystem}/${r.package.name}`,
        installed: r.version,
        fixed: c.fixed_in ?? "—",
        kev: c.kev ? "⚠ KEV" : "",
        epss: formatEpss(c.epss_score),
        summary: truncate(c.summary, 60),
      });
    }
  }
  return out;
}

function formatEpss(score: number | null): string {
  if (score === null || score === undefined) return "";
  const pct = score * 100;
  if (pct >= 1) return `${pct.toFixed(1)}%`;
  if (pct > 0) return `${pct.toFixed(2)}%`;
  return "0%";
}

function truncate(s: string | null, max: number): string {
  if (!s) return "";
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + "…";
}

function renderAscii(rows: Row[], color: boolean): string {
  const headers = ["Severity", "CVE", "Package", "Installed", "Fixed", "KEV", "EPSS", "Summary"];
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => Object.values(r)[i]?.length ?? 0)),
  );
  const sep = "  ";
  const fmt = (cells: string[], color?: (s: string) => string) =>
    cells.map((c, i) => (color ?? identity)(c.padEnd(widths[i]))).join(sep);

  const lines: string[] = [];
  lines.push(fmt(headers, color ? pc.dim : undefined));
  lines.push(widths.map((w) => "─".repeat(w)).join(sep));
  for (const r of rows) {
    const cells = [r.severity, r.cve, r.pkg, r.installed, r.fixed, r.kev, r.epss, r.summary];
    if (!color) {
      lines.push(fmt(cells));
      continue;
    }
    const painter = severityColor(r.severity);
    lines.push(
      cells
        .map((c, i) => {
          const padded = c.padEnd(widths[i]);
          if (i === 0) return painter(padded);
          if (i === 5 && c) return pc.red(padded);
          return padded;
        })
        .join(sep),
    );
  }
  return lines.join("\n");
}

const identity = (s: string) => s;

function severityColor(sev: string): (s: string) => string {
  switch (sev) {
    case "CRITICAL":
      return (s) => pc.bgRed(pc.white(pc.bold(s)));
    case "HIGH":
      return pc.red;
    case "MEDIUM":
      return pc.yellow;
    case "LOW":
      return pc.green;
    default:
      return pc.dim;
  }
}
