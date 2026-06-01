import pc from "picocolors";
import { loadLockfile } from "../lockfiles/detect.js";
import { postCheckBatch, ApiError, type VersionCheckResult } from "../api.js";
import { resolveApiUrl } from "../config.js";
import { buildSummary, renderSummary } from "../format/summary.js";
import { renderTable } from "../format/table.js";
import { renderJson } from "../format/json.js";

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
    }
  }

  if (summary.total_cves === 0) return 0;
  return args.exitZero ? 0 : 1;
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
