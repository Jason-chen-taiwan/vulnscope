/**
 * OSS-mode stub for the digest cron. No-op so self-host builds
 * don't depend on Resend or the users/watchlists tables. The bridge
 * gates this behind PRO_ENABLED before calling.
 */
import "server-only";

export async function runDigest(_args?: {
  onlyEmail?: string;
  dryRun?: boolean;
  sentDate?: string;
}): Promise<{
  candidates: number;
  digestsSent: number;
  skippedNoHits: number;
  skippedAlreadySent: number;
  errors: { userId: string; message: string }[];
}> {
  return {
    candidates: 0,
    digestsSent: 0,
    skippedNoHits: 0,
    skippedAlreadySent: 0,
    errors: [],
  };
}
