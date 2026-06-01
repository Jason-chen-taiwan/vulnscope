import type { VersionCheckResult } from "../api.js";

export interface Summary {
  total_packages: number;
  unknown_packages: number;
  vulnerable_packages: number;
  total_cves: number;
  by_severity: Record<string, number>;
  kev_count: number;
  /** First fixed_in suggestion the user could apply, if obvious. */
  recommended_upgrades: Array<{ name: string; current: string; recommended: string }>;
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const;

export function buildSummary(results: VersionCheckResult[]): Summary {
  const by_severity: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
  let total_cves = 0;
  let kev_count = 0;
  let unknown_packages = 0;
  let vulnerable_packages = 0;
  const recommended: Summary["recommended_upgrades"] = [];
  for (const r of results) {
    if (r.unknown) unknown_packages++;
    if (r.is_vulnerable) vulnerable_packages++;
    for (const c of r.affected_by) {
      total_cves++;
      const key = c.severity ?? "NONE";
      by_severity[key] = (by_severity[key] ?? 0) + 1;
      if (c.kev) kev_count++;
    }
    if (r.recommended_version) {
      recommended.push({
        name: r.package.name,
        current: r.version,
        recommended: r.recommended_version,
      });
    }
  }
  return {
    total_packages: results.length,
    unknown_packages,
    vulnerable_packages,
    total_cves,
    by_severity,
    kev_count,
    recommended_upgrades: recommended,
  };
}

export function renderSummary(s: Summary): string {
  if (s.total_cves === 0) {
    const note = s.unknown_packages > 0
      ? ` (${s.unknown_packages} packages not in database)`
      : "";
    return `✓ No known vulnerabilities in ${s.total_packages} packages${note}.`;
  }
  const parts = SEVERITY_ORDER.filter((sev) => (s.by_severity[sev] ?? 0) > 0).map(
    (sev) => `${s.by_severity[sev]} ${sev}`,
  );
  const kev = s.kev_count > 0 ? `, ${s.kev_count} in CISA KEV` : "";
  const unknown = s.unknown_packages > 0
    ? ` · ${s.unknown_packages} packages not in database`
    : "";
  return `Found ${s.total_cves} vulnerabilities (${parts.join(", ")}${kev}) in ${s.vulnerable_packages} packages${unknown}.`;
}
