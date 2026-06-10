import { pool } from "@/db/client";

/**
 * IndexNow notify: pings Bing (and shared with Yandex, Naver, Seznam,
 * Yep) when CVE records change, so new pages get indexed in hours
 * instead of weeks. Spec: https://www.indexnow.org/
 *
 * Gated by INDEXNOW_KEY — self-hosters who don't set this env var
 * get a no-op. The key must also exist as a public file at
 * `${SITE}/${INDEXNOW_KEY}.txt` containing the key itself, otherwise
 * IndexNow rejects submissions with 403.
 */

const ENDPOINT = "https://api.indexnow.org/IndexNow";
const MAX_URLS_PER_BATCH = 10_000;
// Only ping URLs whose modified_at moved in the recent past — typical
// refresh window is daily, so 36h gives us a safety margin on the slow
// edge without re-pinging the entire DB.
const RECENT_WINDOW = "36 hours";

export async function notifyIndexNowRecent(): Promise<{ ok: boolean; submitted: number; reason?: string }> {
  const key = process.env.INDEXNOW_KEY;
  const site = process.env.NEXT_PUBLIC_SITE_URL;
  if (!key) return { ok: false, submitted: 0, reason: "INDEXNOW_KEY not set" };
  if (!site) return { ok: false, submitted: 0, reason: "NEXT_PUBLIC_SITE_URL not set" };

  // Pull CVE IDs whose modified_at advanced in the recent window AND
  // the CVE meets the same "high signal" bar as sitemap.ts — we only
  // want IndexNow attention on URLs we'd actually want indexed. Pinging
  // 75k low-signal CVEs every day would waste our daily quota.
  const { rows } = await pool.query<{ cve_id: string }>(
    `SELECT cve_id
       FROM vulnerabilities
      WHERE modified_at >= now() - interval '${RECENT_WINDOW}'
        AND (kev = true OR epss_score >= 0.05)
      ORDER BY modified_at DESC
      LIMIT $1`,
    [MAX_URLS_PER_BATCH / 2], // /2 because each CVE generates 2 URLs (en + zh)
  );

  if (rows.length === 0) {
    return { ok: true, submitted: 0, reason: "no recently-modified high-signal CVEs" };
  }

  const urlList: string[] = [];
  for (const r of rows) {
    urlList.push(`${site}/en/cve/${r.cve_id}`);
    urlList.push(`${site}/zh/cve/${r.cve_id}`);
  }

  const host = new URL(site).host;
  const body = {
    host,
    key,
    keyLocation: `${site}/${key}.txt`,
    urlList,
  };

  try {
    const res = await fetch(ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify(body),
    });
    // IndexNow returns 200 for success, 202 for accepted-with-pending-validation.
    // 422 = invalid URL list, 403 = key mismatch (verification file wrong),
    // 429 = quota exceeded.
    if (res.status === 200 || res.status === 202) {
      return { ok: true, submitted: urlList.length };
    }
    return {
      ok: false,
      submitted: 0,
      reason: `IndexNow returned ${res.status}: ${await res.text().catch(() => "(no body)")}`,
    };
  } catch (e) {
    return { ok: false, submitted: 0, reason: `IndexNow fetch failed: ${(e as Error).message}` };
  }
}
