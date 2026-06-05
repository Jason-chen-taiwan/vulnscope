/**
 * OSS-mode stub for the watchlist Pro feature. All operations are
 * silent no-ops: list returns empty, count returns 0, add/remove
 * throw. The bridge layer treats Pro-disabled as 503 before reaching
 * these functions.
 */
import "server-only";

import type { VulnListItem } from "@/lib/queries";

export type WatchlistRow = {
  id: string;
  userId: string;
  ecosystem: string;
  packageName: string;
  lastAlertedAt: Date;
  createdAt: Date;
};

export type WatchlistDisplayRow = WatchlistRow & {
  latestCves: VulnListItem[];
};

export const FREE_WATCHLIST_LIMIT = 3;

export async function getWatchlistWithSummary(
  _userId: string,
): Promise<WatchlistDisplayRow[]> {
  return [];
}

export async function countWatches(_userId: string): Promise<number> {
  return 0;
}

export async function addWatch(
  _userId: string,
  _ecosystem: string,
  _packageName: string,
): Promise<{ row: WatchlistRow; created: boolean }> {
  throw new Error("Watchlist is not available on this build");
}

export async function removeWatch(
  _userId: string,
  _id: string,
): Promise<{ removed: boolean }> {
  return { removed: false };
}
