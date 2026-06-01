/**
 * Best-effort one-line summary for a CVE.
 *
 * OSV records sometimes ship `summary` (short) and sometimes only ship
 * `details` (multi-line, can be paragraphs of context). About half of
 * what we ingest has no `summary` but does have `description`. Rather
 * than showing "(no summary)" in 50% of list rows, prefer the first
 * sentence of the description, truncated to one line.
 */
export function summarize(
  summary: string | null | undefined,
  description: string | null | undefined,
  maxLen = 140,
): string | null {
  if (summary && summary.trim()) return summary.trim();
  if (!description) return null;
  const cleaned = description.replace(/\s+/g, " ").trim();
  if (!cleaned) return null;
  // Cut at first sentence boundary if it's close enough; otherwise hard
  // truncate. ". " and ". \n" are the common boundaries.
  const period = cleaned.search(/\.\s/);
  if (period > 20 && period < maxLen) return cleaned.slice(0, period + 1);
  if (cleaned.length <= maxLen) return cleaned;
  return cleaned.slice(0, maxLen - 1).trimEnd() + "…";
}
