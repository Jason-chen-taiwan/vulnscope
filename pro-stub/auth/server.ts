/**
 * OSS-mode stub for server-side auth helpers. Hosted Pro replaces
 * this. Every call returns the unauthenticated answer so OSS routes
 * gated on Pro return 404 cleanly.
 */
import "server-only";

export class ProAccessError extends Error {
  constructor(
    public readonly reason: "unauthenticated" | "not_subscribed",
    message: string,
  ) {
    super(message);
    this.name = "ProAccessError";
  }
}

/**
 * Shape of the user row we'd return from the Pro database. Kept here
 * (and structurally identical to the real one) so pro-bridge can
 * `typeof` it without dragging the real Drizzle schema in.
 */
export type ProUser = {
  id: string;
  email: string;
  name: string;
  emailVerified: boolean;
  image: string | null;
  polarCustomerId: string | null;
  polarSubscriptionId: string | null;
  subscriptionStatus: string | null;
  subscriptionTier: string | null;
  currentPeriodEnd: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

export async function getCurrentUser(): Promise<ProUser | null> {
  return null;
}

export async function requirePro(): Promise<ProUser> {
  throw new ProAccessError(
    "unauthenticated",
    "Pro tier is not enabled on this build",
  );
}
