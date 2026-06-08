import { describe, it, expect, beforeEach } from "vitest";
import { NextRequest } from "next/server";
import {
  consume,
  checkLimit,
  withRateLimit,
  RATE_LIMIT_BUCKETS,
  __resetStoreForTests,
} from "./rate-limit";

// ─── Pure algorithm tests (no Map, no Request) ───────────────────────────────

describe("consume() token bucket math", () => {
  it("allows when bucket has tokens, decrements by 1", () => {
    const state = { tokens: 5, lastRefillMs: 1000, lastTouchedMs: 1000 };
    const r = consume(state, 10, 10 / 60_000, 1000);
    expect(r.allow).toBe(true);
    expect(state.tokens).toBeCloseTo(4, 5);
    expect(r.remaining).toBe(4);
  });

  it("rejects when bucket is empty", () => {
    const state = { tokens: 0, lastRefillMs: 1000, lastTouchedMs: 1000 };
    const r = consume(state, 10, 10 / 60_000, 1000);
    expect(r.allow).toBe(false);
    expect(r.retryAfterSec).toBeGreaterThan(0);
  });

  it("refills lazily based on elapsed time, caps at capacity", () => {
    const state = { tokens: 0, lastRefillMs: 0, lastTouchedMs: 0 };
    // 60 tokens/min = 1 token/sec → 30s elapsed = 30 tokens, capped at 10.
    const r = consume(state, 10, 60 / 60_000, 30_000);
    expect(r.allow).toBe(true);
    // We refilled to 10 (cap), then consumed 1 → 9 remaining.
    expect(state.tokens).toBeCloseTo(9, 5);
  });

  it("Retry-After grows as tokens go further negative", () => {
    const state = { tokens: 0, lastRefillMs: 1000, lastTouchedMs: 1000 };
    const r = consume(state, 10, 60 / 60_000, 1000); // 1 token/sec
    // Need 1 - 0 = 1 token's worth of wait at 1/sec → 1s
    expect(r.retryAfterSec).toBe(1);
  });

  it("partial refill: 30s at 1 token/sec adds ~30 tokens", () => {
    const state = { tokens: 0, lastRefillMs: 0, lastTouchedMs: 0 };
    consume(state, 100, 60 / 60_000, 30_000);
    // refilled 30, consumed 1 → 29
    expect(state.tokens).toBeCloseTo(29, 5);
  });
});

// ─── Integration via checkLimit + Map ────────────────────────────────────────

function mockRequest(method: string, headers: Record<string, string> = {}): NextRequest {
  return new NextRequest("http://localhost/api/test", {
    method,
    headers,
  });
}

describe("checkLimit() integration", () => {
  beforeEach(() => __resetStoreForTests());

  it("allows first N requests up to capacity, then 429", async () => {
    const cap = RATE_LIMIT_BUCKETS.autocomplete.capacity; // 60
    const req = mockRequest("GET", { "cf-connecting-ip": "1.2.3.4" });
    let allowedCount = 0;
    for (let i = 0; i < cap + 5; i++) {
      const r = await checkLimit(req, "autocomplete", { identityHint: "ip-only" });
      if (r.allow) allowedCount++;
    }
    expect(allowedCount).toBe(cap);
  });

  it("distinct CF-Connecting-IP values get distinct buckets", async () => {
    const cap = RATE_LIMIT_BUCKETS.autocomplete.capacity;
    const a = mockRequest("GET", { "cf-connecting-ip": "1.1.1.1" });
    const b = mockRequest("GET", { "cf-connecting-ip": "2.2.2.2" });
    for (let i = 0; i < cap; i++) {
      await checkLimit(a, "autocomplete", { identityHint: "ip-only" });
    }
    const r = await checkLimit(b, "autocomplete", { identityHint: "ip-only" });
    expect(r.allow).toBe(true); // b's bucket is untouched
  });

  it("emits X-RateLimit-* headers on allow", async () => {
    const req = mockRequest("GET", { "cf-connecting-ip": "3.3.3.3" });
    const r = await checkLimit(req, "search", { identityHint: "ip-only" });
    expect(r.allow).toBe(true);
    expect(r.headers["X-RateLimit-Limit"]).toBe("120");
    expect(r.headers["X-RateLimit-Remaining"]).toBe("119");
    expect(r.headers["X-RateLimit-Reset"]).toMatch(/^\d+$/);
    expect(r.headers["Retry-After"]).toBeUndefined();
  });

  it("emits Retry-After on 429", async () => {
    const cap = RATE_LIMIT_BUCKETS.check_batch.capacity;
    const req = mockRequest("POST", { "cf-connecting-ip": "4.4.4.4" });
    for (let i = 0; i < cap; i++) {
      await checkLimit(req, "check_batch", { identityHint: "ip-only" });
    }
    const denied = await checkLimit(req, "check_batch", { identityHint: "ip-only" });
    expect(denied.allow).toBe(false);
    expect(denied.headers["Retry-After"]).toMatch(/^\d+$/);
  });

  it("identity precedence: CF-Connecting-IP wins over Fly-Client-IP", async () => {
    const a = mockRequest("GET", {
      "cf-connecting-ip": "9.9.9.9",
      "fly-client-ip": "8.8.8.8",
    });
    const b = mockRequest("GET", { "fly-client-ip": "9.9.9.9" });
    // First request exhausts a's CF-keyed bucket.
    const cap = RATE_LIMIT_BUCKETS.autocomplete.capacity;
    for (let i = 0; i < cap; i++) {
      await checkLimit(a, "autocomplete", { identityHint: "ip-only" });
    }
    // b uses Fly-Client-IP only — but key is the SAME ip 9.9.9.9. That
    // means it should ALSO be exhausted (we strip the source-header
    // distinction and key on the IP value alone).
    const r = await checkLimit(b, "autocomplete", { identityHint: "ip-only" });
    expect(r.allow).toBe(false);
  });

  it("falls back to x-forwarded-for first value", async () => {
    const req = mockRequest("GET", {
      "x-forwarded-for": "5.5.5.5, 10.0.0.1, 10.0.0.2",
    });
    const r = await checkLimit(req, "autocomplete", { identityHint: "ip-only" });
    expect(r.allow).toBe(true);
    // We can't directly inspect the key, but a second IP from a different
    // first-hop is its own bucket:
    const req2 = mockRequest("GET", {
      "x-forwarded-for": "6.6.6.6, 10.0.0.1",
    });
    const cap = RATE_LIMIT_BUCKETS.autocomplete.capacity;
    for (let i = 0; i < cap; i++) {
      await checkLimit(req, "autocomplete", { identityHint: "ip-only" });
    }
    const onB = await checkLimit(req2, "autocomplete", { identityHint: "ip-only" });
    expect(onB.allow).toBe(true);
  });
});

// ─── Wrapper ─────────────────────────────────────────────────────────────────

describe("withRateLimit() HOF", () => {
  beforeEach(() => __resetStoreForTests());

  it("invokes handler on first request and appends headers to response", async () => {
    const handler = async () =>
      new Response(JSON.stringify({ data: "hello" }), { status: 200 });
    const wrapped = withRateLimit("search", handler, { identityHint: "ip-only" });
    const resp = await wrapped(
      mockRequest("GET", { "cf-connecting-ip": "7.7.7.7" }),
      undefined,
    );
    expect(resp.status).toBe(200);
    expect(resp.headers.get("X-RateLimit-Limit")).toBe("120");
    expect(resp.headers.get("X-RateLimit-Remaining")).toBe("119");
  });

  it("returns 429 without calling handler when bucket is empty", async () => {
    let handlerCalls = 0;
    const handler = async () => {
      handlerCalls++;
      return new Response("ok");
    };
    const wrapped = withRateLimit("check_batch", handler, { identityHint: "ip-only" });
    const cap = RATE_LIMIT_BUCKETS.check_batch.capacity;
    const req = mockRequest("POST", { "cf-connecting-ip": "8.8.8.8" });
    // Use up the allowance.
    for (let i = 0; i < cap; i++) await wrapped(req, undefined);
    expect(handlerCalls).toBe(cap);
    // Next request: 429 without handler invocation.
    const denied = await wrapped(req, undefined);
    expect(denied.status).toBe(429);
    expect(handlerCalls).toBe(cap); // unchanged
    expect(denied.headers.get("Retry-After")).toBeTruthy();
  });

  it("exempts OPTIONS preflight from the limiter entirely", async () => {
    let handlerCalls = 0;
    const handler = async () => {
      handlerCalls++;
      return new Response(null, { status: 204 });
    };
    const wrapped = withRateLimit("check_batch", handler, { identityHint: "ip-only" });
    const req = mockRequest("OPTIONS", { "cf-connecting-ip": "9.9.9.9" });
    // Way more than capacity — should ALL pass through, no 429.
    const cap = RATE_LIMIT_BUCKETS.check_batch.capacity;
    for (let i = 0; i < cap + 20; i++) await wrapped(req, undefined);
    expect(handlerCalls).toBe(cap + 20);
  });
});
