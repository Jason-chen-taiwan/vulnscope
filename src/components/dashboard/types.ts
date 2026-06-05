/**
 * Shared types for the dashboard watchlist UI. Mirrors the wire
 * shape of /api/v1/watchlist (which itself comes from pro/lib's
 * WatchlistDisplayRow) without forcing the client to import Drizzle
 * types — keeps the client bundle small and the Pro internals private.
 */
export interface ClientWatchlistCve {
  cve_id: string;
  summary: string | null;
  published_at: string | null; // ISO string after JSON round-trip
  kev: boolean;
  epss_score: number | null;
  severity: string | null;
  base_score: number | null;
}

export interface PopularPackage {
  ecosystem: string;
  name: string;
  cve_count: number;
  kev_count: number;
}

export interface ClientWatchlistRow {
  id: string;
  ecosystem: string;
  packageName: string;
  version: string | null;
  createdAt: string;
  lastAlertedAt: string;
  latestCves: ClientWatchlistCve[];
}
