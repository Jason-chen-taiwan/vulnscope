// Shared API response envelope helpers.
import { NextResponse } from "next/server";

export interface ApiError {
  code: string;
  message: string;
  field?: string;
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400",
} as const;

/** Add CORS headers in-place to any NextResponse. The CLI and any
 *  third-party client browser tools both need this; the cost is nil. */
export function withCors(res: NextResponse): NextResponse {
  for (const [k, v] of Object.entries(CORS_HEADERS)) res.headers.set(k, v);
  return res;
}

export function ok<T>(data: T, meta?: Record<string, unknown>) {
  return withCors(NextResponse.json({ data, meta, errors: null }));
}

export function fail(
  status: number,
  code: string,
  message: string,
  field?: string,
  extraHeaders?: Record<string, string>,
) {
  const err: ApiError = { code, message };
  if (field) err.field = field;
  const res = withCors(
    NextResponse.json({ data: null, meta: null, errors: [err] }, { status }),
  );
  if (extraHeaders) {
    for (const [k, v] of Object.entries(extraHeaders)) res.headers.set(k, v);
  }
  return res;
}

/** Preflight handler for CORS. Routes that accept POST should re-export
 *  this as their `OPTIONS` so browsers can negotiate. */
export function corsPreflight() {
  return withCors(new NextResponse(null, { status: 204 }));
}
