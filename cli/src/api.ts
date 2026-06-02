import type { Pkg } from "./lockfiles/types.js";
import { BATCH_SIZE, REQUEST_TIMEOUT_MS } from "./config.js";

/**
 * Mirror of the server's VersionCheckResult shape (in src/lib/queries.ts).
 * Intentionally duplicated here to keep the CLI a zero-coupling consumer.
 * If the server adds new fields, declare them optional here.
 */
export interface AffectedCve {
  cve_id: string;
  severity: string | null;
  base_score: number | null;
  kev: boolean;
  epss_score: number | null;
  fixed_in: string | null;
  summary: string | null;
  /** Server 0.3+ : count of public exploits/PoCs (Metasploit, Exploit-DB,
   *  Nuclei, GitHub). Optional because older servers don't return it. */
  exploits_count?: number;
}

export interface VersionCheckResult {
  package: { ecosystem: string; name: string };
  version: string;
  is_vulnerable: boolean;
  affected_by: AffectedCve[];
  recommended_version: string | null;
  /** Server sets this when the package isn't in our DB. */
  unknown?: boolean;
}

/** Envelope shape used by every /api/v1 route. */
interface Envelope<T> {
  data: T | null;
  meta: Record<string, unknown> | null;
  errors: Array<{ code: string; message: string; field?: string }> | null;
}

export class ApiError extends Error {
  constructor(message: string, public status?: number) {
    super(message);
    this.name = "ApiError";
  }
}

export interface BatchOptions {
  apiUrl: string;
  /** Optional progress callback fired after each chunk. */
  onProgress?: (done: number, total: number) => void;
}

/**
 * Send `packages` to the batch endpoint, transparently chunking into
 * BATCH_SIZE-sized requests when the input is larger than the server's
 * per-request limit.
 *
 * Throws ApiError on any network failure, 4xx/5xx response, or
 * envelope-level error. The caller (commands/check.ts) maps ApiError
 * to exit code 2.
 */
export async function postCheckBatch(
  packages: Pkg[],
  opts: BatchOptions,
): Promise<VersionCheckResult[]> {
  if (packages.length === 0) return [];
  const url = `${opts.apiUrl}/api/v1/packages/check-batch`;
  const out: VersionCheckResult[] = [];
  const totalChunks = Math.ceil(packages.length / BATCH_SIZE);
  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    const chunk = packages.slice(i, i + BATCH_SIZE);
    const body = JSON.stringify({ packages: chunk });
    let res: Response;
    try {
      res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": "vulnscope-cli" },
        body,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (e) {
      const msg = (e as Error).message;
      throw new ApiError(`network error contacting ${url}: ${msg}`);
    }
    let envelope: Envelope<VersionCheckResult[]>;
    try {
      envelope = (await res.json()) as Envelope<VersionCheckResult[]>;
    } catch {
      throw new ApiError(`API returned non-JSON (status ${res.status})`, res.status);
    }
    if (!res.ok || envelope.errors) {
      const msg = envelope.errors?.[0]?.message ?? `HTTP ${res.status}`;
      throw new ApiError(`API error: ${msg}`, res.status);
    }
    if (!envelope.data) {
      throw new ApiError("API returned empty data", res.status);
    }
    out.push(...envelope.data);
    if (opts.onProgress) opts.onProgress(Math.ceil((i + chunk.length) / BATCH_SIZE), totalChunks);
  }
  return out;
}
