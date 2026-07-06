/**
 * CISA KEV feed READ + TRANSFORM core (DB-agnostic).
 *
 * Shared by the Postgres ingest (src/lib/ingest/kev.ts) and the SQLite
 * build (scripts/build-sqlite.ts). No `server-only` / pg imports so it's
 * safe under tsx. The WRITE path is injected via `upsertEntry`.
 */
import { fetch } from "undici";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export interface KevEntry {
  cveID: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
}
export interface KevPayload {
  catalogVersion: string;
  count: number;
  vulnerabilities: KevEntry[];
}

export function parseKevDate(s: string | undefined | null): Date | null {
  if (!s) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Fetch + JSON-parse the CISA KEV catalog. */
export async function fetchKev(signal?: AbortSignal): Promise<KevPayload> {
  const res = await fetch(KEV_URL, { signal });
  if (!res.ok) throw new Error(`KEV fetch failed: ${res.status}`);
  return (await res.json()) as KevPayload;
}
