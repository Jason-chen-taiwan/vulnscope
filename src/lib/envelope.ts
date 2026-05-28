// Shared API response envelope helpers.
import { NextResponse } from "next/server";

export interface ApiError {
  code: string;
  message: string;
  field?: string;
}

export function ok<T>(data: T, meta?: Record<string, unknown>) {
  return NextResponse.json({ data, meta, errors: null });
}

export function fail(status: number, code: string, message: string, field?: string) {
  const err: ApiError = { code, message };
  if (field) err.field = field;
  return NextResponse.json({ data: null, meta: null, errors: [err] }, { status });
}
