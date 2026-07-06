/**
 * OSV modified_id.csv changelog parser (DB-agnostic, pure).
 *
 * OSV publishes a per-ecosystem changelog at
 *   <base>/<eco>/modified_id.csv
 * sorted reverse-chronologically as `<iso-modified>,<primary-id>`. Consumers
 * stream from the top and stop at the first timestamp they have already seen.
 *
 * We collect the PRIMARY ids (the csv id column) verbatim — we do NOT filter
 * to CVE- here, because npm/PyPI records are keyed by GHSA-* with the CVE in
 * their aliases; filtering the csv id would drop them. CVE-only scope is
 * enforced later by bufferRecord (returns null for no-CVE-alias records).
 */

const OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com";

export function MODIFIED_CSV_URL(eco: string): string {
  return `${OSV_BASE}/${encodeURIComponent(eco)}/modified_id.csv`;
}

export function parseModifiedCsv(
  text: string,
  watermark: string | null,
): { changedIds: Set<string>; newWatermark: string | null } {
  const changedIds = new Set<string>();
  let newWatermark: string | null = null;

  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const comma = line.indexOf(",");
    if (comma === -1) continue;
    const modified = line.slice(0, comma);
    const id = line.slice(comma + 1).trim();
    if (!id) continue;

    // First (newest) line sets the new watermark.
    if (newWatermark === null) newWatermark = modified;

    // Reverse-chronological: once we reach a row at/older than the
    // watermark, everything below is already seen — stop.
    if (watermark !== null && modified <= watermark) break;

    changedIds.add(id);
  }

  return { changedIds, newWatermark };
}
