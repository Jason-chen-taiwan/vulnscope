import { z } from "zod";

// OSV schema (subset we use). See https://ossf.github.io/osv-schema/
export const osvEventSchema = z
  .object({
    introduced: z.string().optional(),
    fixed: z.string().optional(),
    last_affected: z.string().optional(),
    limit: z.string().optional(),
  })
  .passthrough();

export const osvRangeSchema = z
  .object({
    type: z.enum(["SEMVER", "ECOSYSTEM", "GIT"]),
    repo: z.string().optional(),
    events: z.array(osvEventSchema),
  })
  .passthrough();

export const osvSeveritySchema = z
  .object({
    type: z.string(), // CVSS_V3 / CVSS_V4 / CVSS_V2
    score: z.string(), // vector string
  })
  .passthrough();

export const osvAffectedSchema = z
  .object({
    package: z
      .object({
        name: z.string(),
        ecosystem: z.string(),
        purl: z.string().optional(),
      })
      .passthrough(),
    ranges: z.array(osvRangeSchema).optional(),
    versions: z.array(z.string()).optional(),
    severity: z.array(osvSeveritySchema).optional(),
    database_specific: z.unknown().optional(),
    ecosystem_specific: z.unknown().optional(),
  })
  .passthrough();

export const osvReferenceSchema = z
  .object({
    type: z.string(), // ADVISORY / FIX / WEB / REPORT / PACKAGE / EVIDENCE
    url: z.string(),
  })
  .passthrough();

export const osvRecordSchema = z
  .object({
    id: z.string(),
    aliases: z.array(z.string()).optional(),
    related: z.array(z.string()).optional(),
    upstream: z.array(z.string()).optional(), // distro feeds use this
    summary: z.string().optional(),
    details: z.string().optional(),
    published: z.string().optional(),
    modified: z.string().optional(),
    withdrawn: z.string().optional(),
    affected: z.array(osvAffectedSchema).optional(),
    references: z.array(osvReferenceSchema).optional(),
    severity: z.array(osvSeveritySchema).optional(),
  })
  .passthrough();

export type OsvRecord = z.infer<typeof osvRecordSchema>;
export type OsvAffected = z.infer<typeof osvAffectedSchema>;
export type OsvRange = z.infer<typeof osvRangeSchema>;
export type OsvEvent = z.infer<typeof osvEventSchema>;

// Severity label derived from a CVSS base score.
export function severityFromScore(score: number | null): string | null {
  if (score === null || Number.isNaN(score)) return null;
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0.0) return "LOW";
  return "NONE";
}

// Parse `base_score` out of a CVSS vector string. Returns null if not present.
// CVSS v3/v4 vectors don't embed a numeric base score, so callers should
// compute via a CVSS library when we need precision; this is a best-effort
// helper for OSV records that occasionally include `CVSS:3.1/...` with no
// explicit score field — in practice OSV's `severity[].score` is the vector
// only, and the score itself must be derived. For the MVP we accept that
// `base_score` may be null when the vector is all we have.
export function tryExtractBaseScore(_vector: string): number | null {
  return null;
}

// Extract the CVE identifier from an OSV record. Sources vary:
//   - NVD-style:   id="CVE-2021-44228"                        → use id
//   - GHSA:        id="GHSA-...", aliases=["CVE-..."]         → use alias
//   - Alpine:      id="ALPINE-CVE-...", upstream=["CVE-..."]  → use upstream
//   - Debian:      id="DSA-1234-1", upstream/aliases=["CVE-..."]
//   - Distro embed: id="ALPINE-CVE-2021-44228"                → substring match
export function pickCveAlias(rec: OsvRecord): string | null {
  const CVE_RE = /\b(CVE-\d{4}-\d{4,})\b/i;
  if (/^CVE-\d{4}-\d+$/i.test(rec.id)) return rec.id.toUpperCase();
  for (const a of rec.aliases ?? []) {
    if (/^CVE-\d{4}-\d+$/i.test(a)) return a.toUpperCase();
  }
  for (const u of rec.upstream ?? []) {
    if (/^CVE-\d{4}-\d+$/i.test(u)) return u.toUpperCase();
  }
  for (const r of rec.related ?? []) {
    if (/^CVE-\d{4}-\d+$/i.test(r)) return r.toUpperCase();
  }
  // Fallback: distro-prefixed IDs like ALPINE-CVE-2021-44228
  const m = rec.id.match(CVE_RE);
  if (m) return m[1].toUpperCase();
  return null;
}

// PEP 503 package name normalization for PyPI.
export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

export function refTypeFromOsv(type: string): string {
  // Map OSV reference types to a simpler vocabulary used in UI.
  switch (type) {
    case "ADVISORY":
    case "ARTICLE":
      return "ADVISORY";
    case "FIX":
    case "PACKAGE":
      return "PATCH";
    case "EVIDENCE":
      return "EXPLOIT";
    case "REPORT":
      return "REPORT";
    case "WEB":
    default:
      return "WEB";
  }
}
