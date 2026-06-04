/**
 * OSS-mode stub for the Polar billing wrapper. Calls throw so
 * accidental invocation in OSS surfaces immediately instead of
 * silently appearing to charge a card.
 */
import "server-only";

export async function createCheckoutSession(_args: {
  userId: string;
  email: string;
  siteUrl: string;
}): Promise<{ url: string; id: string }> {
  throw new Error("Polar checkout is not available on this build");
}

export async function customerPortalUrl(
  _polarCustomerId: string,
): Promise<string> {
  throw new Error("Polar portal is not available on this build");
}
