import type { VersionCheckResult } from "../api.js";
import type { Summary } from "./summary.js";

/**
 * Machine-readable output. Stable shape — anything documented here is
 * part of the CLI's contract for CI consumers and shouldn't change
 * without a minor version bump.
 */
export function renderJson(results: VersionCheckResult[], summary: Summary): string {
  return JSON.stringify(
    {
      schema_version: 1,
      summary,
      results,
    },
    null,
    2,
  );
}
