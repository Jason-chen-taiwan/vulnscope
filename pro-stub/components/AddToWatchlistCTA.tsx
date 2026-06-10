/**
 * OSS-mode stub: watchlist is hosted-only, so the CTA is invisible
 * on self-host builds. next.config.ts aliases @pro/* to ./pro/ when
 * the private Pro repo is present at build time; otherwise resolution
 * falls through to this file.
 */
export function AddToWatchlistCTA(_props: { ecosystem: string; name: string; variant?: "inline" | "card" }) {
  return null;
}
