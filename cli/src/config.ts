/**
 * Default backend. The hosted demo run by the author. Users can
 * override per-invocation with `--api <url>` or persistently with
 * the VULNSCOPE_API environment variable.
 */
export const DEFAULT_API_URL = "https://vulnscope.dev";

export function resolveApiUrl(flag: string | undefined): string {
  if (flag) return flag.replace(/\/+$/, "");
  const env = process.env.VULNSCOPE_API;
  if (env) return env.replace(/\/+$/, "");
  return DEFAULT_API_URL;
}

/**
 * Whether the resolved API URL is the public hosted vulnscope.dev.
 * When true, output can carry `?ref=cli` attribution links + a Pro
 * upsell footer. Self-hosters pointed at their own instance get
 * neither — they're not the people we're marketing to.
 */
export function isOfficialHost(apiUrl: string): boolean {
  return apiUrl.replace(/\/+$/, "") === DEFAULT_API_URL;
}

/** Max packages per POST per the server's zod schema in check-batch/route.ts. */
export const BATCH_SIZE = 500;

/** Stop waiting after this many ms per HTTP request. */
export const REQUEST_TIMEOUT_MS = 60_000;
