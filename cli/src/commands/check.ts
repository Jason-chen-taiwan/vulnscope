import pc from "picocolors";
import { loadLockfile } from "../lockfiles/detect.js";
import { postCheckBatch, ApiError, type VersionCheckResult } from "../api.js";
import { resolveApiUrl, isOfficialHost } from "../config.js";
import { buildSummary, renderSummary } from "../format/summary.js";
import { renderTable } from "../format/table.js";
import { renderJson } from "../format/json.js";
import { shouldShowPromo, markPromoShown } from "../upsell.js";

export interface CheckArgs {
  path?: string;
  api?: string;
  json?: boolean;
  exitZero?: boolean;
  severity?: string;
  ignore?: string[];
  quiet?: boolean;
  noColor?: boolean;
}

export type ExitCode = 0 | 1 | 2;

interface IO {
  out: (line: string) => void;
  err: (line: string) => void;
}

const defaultIO: IO = {
  out: (line) => process.stdout.write(line + "\n"),
  err: (line) => process.stderr.write(line + "\n"),
};

/**
 * Main check command. Returns the exit code instead of calling
 * process.exit so it's trivially testable.
 */
export async function runCheck(args: CheckArgs, io: IO = defaultIO): Promise<ExitCode> {
  const apiUrl = resolveApiUrl(args.api);
  const color = !args.noColor && !args.json && process.stdout.isTTY === true;

  // 1. Load lockfile.
  let loaded: ReturnType<typeof loadLockfile>;
  try {
    loaded = loadLockfile(args.path ?? process.cwd());
  } catch (e) {
    io.err(red(color, `vulnscope: ${(e as Error).message}`));
    return 2;
  }
  if (loaded.packages.length === 0) {
    if (!args.quiet) io.out(`No packages found in ${loaded.path}. Nothing to check.`);
    return 0;
  }

  if (!args.json && !args.quiet) {
    io.out(
      dim(color, `Scanning ${loaded.packages.length} packages from ${loaded.path}...`),
    );
    if (loaded.warning) {
      io.out(dim(color, `  note: ${loaded.warning}`));
    }
  }

  // 2. POST batch(es).
  let results: VersionCheckResult[];
  try {
    results = await postCheckBatch(loaded.packages, {
      apiUrl,
      onProgress: (done, total) => {
        if (args.json || args.quiet || total < 2) return;
        io.out(dim(color, `  [${done}/${total}] chunks sent`));
      },
    });
  } catch (e) {
    if (e instanceof ApiError) {
      io.err(red(color, `vulnscope: ${e.message}`));
      io.err(dim(color, `(API: ${apiUrl}; pass --api to override)`));
      return 2;
    }
    throw e;
  }

  // 3. Apply filters → render.
  const severitySet = args.severity
    ? new Set(args.severity.split(",").map((s) => s.trim().toUpperCase()).filter(Boolean))
    : undefined;
  const ignoreSet = args.ignore && args.ignore.length > 0 ? new Set(args.ignore) : undefined;

  // For exit-code purposes we count CVEs after applying filters.
  const filtered = filterResults(results, severitySet, ignoreSet);
  const summary = buildSummary(filtered);

  if (args.json) {
    io.out(renderJson(filtered, summary));
  } else {
    const table = renderTable(filtered, {
      color,
      severities: severitySet,
      ignore: ignoreSet,
    });
    if (table) io.out(table);
    if (!args.quiet || summary.total_cves > 0) {
      io.out("");
      io.out(severityTag(color, summary.total_cves > 0) + " " + renderSummary(summary));
      if (summary.recommended_upgrades.length > 0 && !args.quiet) {
        io.out(
          dim(
            color,
            `Top recommendation: upgrade ${summary.recommended_upgrades[0].name} from ` +
              `${summary.recommended_upgrades[0].current} to ${summary.recommended_upgrades[0].recommended}.`,
          ),
        );
      }
      // Attribution links to the canonical CVE detail page on the
      // hosted instance. ?ref=cli lets us attribute traffic in
      // Plausible without dropping a cookie. Suppressed when the user
      // pointed --api at their own self-hosted instance (the link
      // wouldn't help them) or when --quiet.
      if (!args.quiet && isOfficialHost(apiUrl) && summary.total_cves > 0) {
        const uniqueCves = collectUniqueCves(filtered);
        if (uniqueCves.length > 0) {
          io.out("");
          io.out(dim(color, "Read more:"));
          for (const id of uniqueCves.slice(0, 5)) {
            io.out(
              dim(color, `  • ${id} → ${apiUrl}/cve/${id}?ref=cli`),
            );
          }
          if (uniqueCves.length > 5) {
            io.out(dim(color, `  • ... ${uniqueCves.length - 5} more`));
          }
        }
        // Pro upsell footer: shown at most once per 7 days per
        // machine. The premise is "you already ran vulnscope and
        // found stuff — would you like to be told *before* the next
        // one lands?". Soft sell with the free tier mentioned so it
        // doesn't read as paywall pressure.
        if (shouldShowPromo()) {
          io.out("");
          io.out(
            dim(
              color,
              `Get daily email alerts when new CVEs land — ${apiUrl}/pricing?ref=cli-footer`,
            ),
          );
          io.out(
            dim(color, "(Free for your first 5 packages. VULNSCOPE_NO_PROMO=1 silences this.)"),
          );
          markPromoShown();
        }
      }
    }
  }

  if (summary.total_cves === 0) return 0;
  return args.exitZero ? 0 : 1;
}

function collectUniqueCves(results: VersionCheckResult[]): string[] {
  const seen = new Set<string>();
  const ordered: string[] = [];
  // Preserve table order (already severity-sorted by the time we
  // arrive here), which is also the order most useful to the user.
  for (const r of results) {
    if (!r.is_vulnerable) continue;
    for (const c of r.affected_by) {
      if (seen.has(c.cve_id)) continue;
      seen.add(c.cve_id);
      ordered.push(c.cve_id);
    }
  }
  return ordered;
}

function filterResults(
  results: VersionCheckResult[],
  severities: Set<string> | undefined,
  ignore: Set<string> | undefined,
): VersionCheckResult[] {
  if (!severities && !ignore) return results;
  return results.map((r) => ({
    ...r,
    affected_by: r.affected_by.filter((c) => {
      if (ignore?.has(c.cve_id)) return false;
      if (severities) {
        const sev = c.severity ?? "NONE";
        if (!severities.has(sev)) return false;
      }
      return true;
    }),
  })).map((r) => ({
    ...r,
    is_vulnerable: r.affected_by.length > 0,
  }));
}

function red(color: boolean, s: string): string {
  return color ? pc.red(s) : s;
}
function dim(color: boolean, s: string): string {
  return color ? pc.dim(s) : s;
}
function severityTag(color: boolean, hasFindings: boolean): string {
  if (!hasFindings) return color ? pc.green("✓") : "✓";
  return color ? pc.red("✗") : "✗";
}
