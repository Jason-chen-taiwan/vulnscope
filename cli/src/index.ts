#!/usr/bin/env node
import { Command } from "commander";
import { runCheck, type CheckArgs } from "./commands/check.js";

const program = new Command();

program
  .name("vulnscope")
  .description("Scan lockfiles for known CVEs (OSV + CISA KEV + EPSS)")
  .version("0.1.0");

program
  .command("check", { isDefault: true })
  .description("Scan a lockfile for known vulnerabilities")
  .argument("[path]", "Path to a lockfile or project directory (defaults to cwd)")
  .option("--api <url>", "Backend URL (env VULNSCOPE_API)")
  .option("--json", "Machine-readable JSON output")
  .option("--exit-zero", "Exit 0 even when vulnerabilities are found")
  .option("--severity <levels>", "Only report given severities (e.g. CRITICAL,HIGH)")
  .option(
    "--ignore <cve...>",
    "Suppress specific CVE IDs (repeatable: --ignore CVE-1 --ignore CVE-2)",
  )
  .option("--quiet", "Suppress informational output; show CVEs and summary only")
  .option("--no-color", "Disable ANSI colors")
  .action(async (path: string | undefined, opts: Record<string, unknown>) => {
    const args: CheckArgs = {
      path,
      api: opts.api as string | undefined,
      json: opts.json === true,
      exitZero: opts.exitZero === true,
      severity: opts.severity as string | undefined,
      ignore: opts.ignore as string[] | undefined,
      quiet: opts.quiet === true,
      // Commander turns --no-color into opts.color = false
      noColor: opts.color === false,
    };
    const code = await runCheck(args);
    process.exit(code);
  });

program.parseAsync(process.argv).catch((e) => {
  process.stderr.write(`vulnscope: unexpected error: ${(e as Error).message}\n`);
  process.exit(2);
});
