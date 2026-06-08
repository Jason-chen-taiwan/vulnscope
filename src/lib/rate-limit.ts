/**
 * Per-route rate limiting for the public API.
 *
 * Why this exists: Cloudflare blocks volumetric attacks at the edge,
 * but attackers can bypass to `vulnscope-tw.fly.dev` directly. Without
 * an app-layer limiter, one curl loop on /api/v1/packages/autocomplete
 * saturates the 512 MB Postgres machine.
 *
 * Design choices:
 *   - **In-memory** Map<string, Bucket>. One web machine today; if we
 *     scale to ≥2, replace `BucketStore` with a Postgres- or Redis-
 *     backed implementation without touching the call sites.
 *   - **Token bucket** with lazy refill. Each entry is two numbers
 *     (tokens, lastRefillMs). Capacity = burst allowance, refillPerMin
 *     = sustained allowance.
 *   - **Hard cap at MAX_ENTRIES** entries on the Map so a botnet rotating
 *     source IPs can't OOM us. On overflow, fail-closed (429) for new
 *     identities until the next probabilistic sweep.
 *   - **Identity precedence**: signed-in user > Cloudflare CF-Connecting-IP
 *     > Fly-Client-IP > X-Forwarded-For first value > "unknown".
 *   - **Signed-in users get 3× capacity** on every bucket. OAuth identity
 *     is harder to forge than IP, and this also nudges towards sign-in.
 *
 * Per-route usage:
 *
 *   export const GET = withRateLimit("autocomplete", async (req) => {
 *     // ...existing handler
 *   }, { identityHint: "ip-only" });
 *
 * `identityHint: "ip-only"` skips the auth lookup. Use it for routes
 * that don't have a "signed-in" experience anyway (anonymous search,
 * autocomplete) so per-keystroke latency stays sub-millisecond.
 */
// Note: no `import "server-only"` here so vitest can import this
// module under the Node environment without the client-guard
// throwing. Every caller path (API route handlers) is already a
// server-only context.
import type { NextRequest } from "next/server";
import { fail } from "./envelope";

// ─── Bucket catalog ──────────────────────────────────────────────────────────

/**
 * Bucket policy. capacity = max tokens (burst); refillPerMin = sustained
 * tokens/min. Anonymous users get this; signed-in get 3× (except `admin`,
 * which is already token-gated).
 *
 * Conservative starting point. Bump up if we see false positives in logs;
 * bump down if abuse incidents demand it.
 */
export const RATE_LIMIT_BUCKETS = {
  global:          { capacity: 300, refillPerMin: 300 },
  autocomplete:    { capacity:  60, refillPerMin:  60 },
  search:          { capacity: 120, refillPerMin: 120 },
  vuln_detail:     { capacity: 120, refillPerMin: 120 },
  package_detail:  { capacity: 120, refillPerMin: 120 },
  check_batch:     { capacity:  10, refillPerMin:  10 },
  mutation:        { capacity:  30, refillPerMin:  30 },
  auth:            { capacity:  10, refillPerMin:  10 },
  admin:           { capacity:   5, refillPerMin:   5 },
} as const satisfies Record<string, { capacity: number; refillPerMin: number }>;

export type BucketName = keyof typeof RATE_LIMIT_BUCKETS;

const SIGNED_IN_MULTIPLIER = 3;

// ─── Store ───────────────────────────────────────────────────────────────────

interface Bucket {
  tokens: number;
  lastRefillMs: number;
  lastTouchedMs: number;
}

// Hard cap on Map size so a botnet rotating source IPs can't OOM us.
// 50k entries × ~120 bytes/entry ≈ 6 MB worst-case.
const MAX_ENTRIES = 50_000;
// Inactive entries are eligible for eviction after this much idle time.
const IDLE_EVICTION_MS = 10 * 60 * 1000;
// Probabilistically sweep on insert so attacker traffic causes its own
// cleanup, no separate timer needed.
const SWEEP_PROBABILITY = 1 / 1000;

declare global {
  // Per-process global. Process boundary = web machine for us.
  // eslint-disable-next-line no-var
  var __vulnscope_rate_limit_store: Map<string, Bucket> | undefined;
}

function store(): Map<string, Bucket> {
  if (!globalThis.__vulnscope_rate_limit_store) {
    globalThis.__vulnscope_rate_limit_store = new Map();
  }
  return globalThis.__vulnscope_rate_limit_store;
}

function maybeSweep(now: number) {
  if (Math.random() >= SWEEP_PROBABILITY) return;
  const m = store();
  const cutoff = now - IDLE_EVICTION_MS;
  for (const [k, v] of m) {
    if (v.lastTouchedMs < cutoff) m.delete(k);
  }
}

// ─── Identity extraction ─────────────────────────────────────────────────────

/**
 * Look up the requester's identity. `user:<id>` if signed in (and the
 * route opted into auth lookup); otherwise `ip:<ip>` from one of the
 * proxy headers Cloudflare and Fly add.
 */
async function deriveIdentity(
  req: NextRequest,
  opts: { identityHint?: "ip-only" } | undefined,
): Promise<{ key: string; signedIn: boolean }> {
  // Auth path — lazy import keeps the rate-limiter usable from any route
  // including OSS / PRO_ENABLED=0 builds where the Pro module 404s.
  if (opts?.identityHint !== "ip-only") {
    try {
      const { proAuth } = await import("@/lib/pro-bridge");
      const pro = await proAuth();
      const user = await pro?.getCurrentUser();
      if (user?.id) return { key: `user:${user.id}`, signedIn: true };
    } catch {
      // Auth subsystem unavailable — fall through to IP identity.
    }
  }
  const h = req.headers;
  const cf = h.get("cf-connecting-ip");
  if (cf) return { key: `ip:${cf}`, signedIn: false };
  const fly = h.get("fly-client-ip");
  if (fly) return { key: `ip:${fly}`, signedIn: false };
  const xff = h.get("x-forwarded-for");
  if (xff) return { key: `ip:${xff.split(",")[0]!.trim()}`, signedIn: false };
  return { key: "unknown", signedIn: false };
}

// ─── Token bucket math ───────────────────────────────────────────────────────

export interface RateLimitResult {
  allow: boolean;
  /** Tokens remaining after this request (floor); for X-RateLimit-Remaining */
  remaining: number;
  /** Capacity in effect for this identity (anon vs signed-in × multiplier) */
  limit: number;
  /** Unix seconds when bucket next reaches full capacity */
  resetEpochSec: number;
  /** Seconds to wait before next allowed request; 0 if allow=true */
  retryAfterSec: number;
}

/** Pure, testable. Mutates `state` in place. */
export function consume(
  state: Bucket,
  capacity: number,
  refillPerMs: number,
  now: number,
): RateLimitResult {
  // Lazy refill: catch up tokens from last visit to now.
  const elapsed = Math.max(0, now - state.lastRefillMs);
  state.tokens = Math.min(capacity, state.tokens + elapsed * refillPerMs);
  state.lastRefillMs = now;
  state.lastTouchedMs = now;

  const allow = state.tokens >= 1;
  if (allow) state.tokens -= 1;

  const remaining = Math.max(0, Math.floor(state.tokens));
  const tokensNeededToFull = capacity - state.tokens;
  const msToFull = refillPerMs > 0 ? tokensNeededToFull / refillPerMs : 0;
  const resetEpochSec = Math.ceil((now + msToFull) / 1000);
  // (1 - state.tokens) / refillPerMs is milliseconds to next whole
  // token. Convert to seconds and round up; minimum 1s so clients see
  // a sane Retry-After value even when the refill is sub-second.
  const retryAfterSec = allow
    ? 0
    : Math.max(1, Math.ceil((1 - state.tokens) / refillPerMs / 1000));

  return { allow, remaining, limit: capacity, resetEpochSec, retryAfterSec };
}

// ─── Public check ────────────────────────────────────────────────────────────

/**
 * Take one token from the bucket for `(identity, bucketName)`. Returns
 * shape-stable result + the headers that should be applied to either
 * the allowed response or the 429 response.
 */
export async function checkLimit(
  req: NextRequest,
  bucketName: BucketName,
  opts?: { identityHint?: "ip-only" },
): Promise<{
  allow: boolean;
  headers: Record<string, string>;
  retryAfterSec: number;
}> {
  const policy = RATE_LIMIT_BUCKETS[bucketName];
  const { key, signedIn } = await deriveIdentity(req, opts);
  const multiplier = signedIn && bucketName !== "admin" ? SIGNED_IN_MULTIPLIER : 1;
  const capacity = policy.capacity * multiplier;
  const refillPerMs = (policy.refillPerMin * multiplier) / 60_000;

  const compositeKey = `${bucketName}|${key}`;
  const now = Date.now();
  const m = store();

  let state = m.get(compositeKey);
  if (!state) {
    // New identity — fail-closed if the Map is at capacity.
    if (m.size >= MAX_ENTRIES) {
      return {
        allow: false,
        headers: {
          "X-RateLimit-Limit": String(capacity),
          "X-RateLimit-Remaining": "0",
          "X-RateLimit-Reset": String(Math.ceil(now / 1000) + 60),
          "Retry-After": "60",
        },
        retryAfterSec: 60,
      };
    }
    state = { tokens: capacity, lastRefillMs: now, lastTouchedMs: now };
    m.set(compositeKey, state);
    maybeSweep(now);
  }

  const r = consume(state, capacity, refillPerMs, now);
  const headers: Record<string, string> = {
    "X-RateLimit-Limit": String(capacity),
    "X-RateLimit-Remaining": String(r.remaining),
    "X-RateLimit-Reset": String(r.resetEpochSec),
  };
  if (!r.allow) headers["Retry-After"] = String(r.retryAfterSec);
  return { allow: r.allow, headers, retryAfterSec: r.retryAfterSec };
}

// ─── Wrapper HOF ─────────────────────────────────────────────────────────────

type RouteHandler<Ctx = unknown> = (req: NextRequest, ctx: Ctx) => Promise<Response>;

/**
 * Wrap a route handler so it runs `checkLimit` first and on success
 * appends rate-limit headers to the response. On 429 the handler is
 * not invoked.
 *
 * OPTIONS preflights bypass the limiter entirely. CORS is browser-
 * controlled and any abuse-resistance gain would be marginal.
 */
export function withRateLimit<Ctx = unknown>(
  bucketName: BucketName,
  handler: RouteHandler<Ctx>,
  opts?: { identityHint?: "ip-only" },
): RouteHandler<Ctx> {
  return async (req, ctx) => {
    if (req.method === "OPTIONS") return handler(req, ctx);
    const r = await checkLimit(req, bucketName, opts);
    if (!r.allow) {
      return fail(
        429,
        "RATE_LIMITED",
        `Rate limit exceeded. Try again in ${r.retryAfterSec}s.`,
        undefined,
        r.headers,
      );
    }
    const resp = await handler(req, ctx);
    for (const [k, v] of Object.entries(r.headers)) resp.headers.set(k, v);
    return resp;
  };
}

// ─── Test-only ───────────────────────────────────────────────────────────────

/** Visible for tests. Don't call from app code. */
export function __resetStoreForTests() {
  globalThis.__vulnscope_rate_limit_store = new Map();
}
