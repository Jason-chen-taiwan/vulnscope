/**
 * Minimal CVSS v3.x base-score calculator.
 *
 * Implements the formula in §7.1 of the CVSS v3.1 spec:
 *   https://www.first.org/cvss/specification-document
 *
 * Returns null for malformed or unsupported vectors. We don't handle
 * temporal or environmental metrics — base score only, which is what UIs
 * and OSV records use 99% of the time.
 */

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 }, // Unchanged scope
  PR_C: { N: 0.85, L: 0.68, H: 0.5 }, // Changed scope
  UI: { N: 0.85, R: 0.62 },
  C: { N: 0, L: 0.22, H: 0.56 },
  I: { N: 0, L: 0.22, H: 0.56 },
  A: { N: 0, L: 0.22, H: 0.56 },
} as const;

function roundUp(n: number): number {
  // CVSS-specified rounding: round to nearest 0.1, always up.
  const x = Math.round(n * 100000);
  if (x % 10000 === 0) return x / 100000;
  return (Math.floor(x / 10000) + 1) / 10;
}

export function cvss3BaseScore(vector: string): number | null {
  // Expected like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  const m = vector.match(/^CVSS:3\.[01]\/(.+)$/);
  if (!m) return null;
  const parts = m[1].split("/");
  const metrics: Record<string, string> = {};
  for (const p of parts) {
    const [k, v] = p.split(":");
    if (k && v) metrics[k] = v;
  }
  const av = (W.AV as Record<string, number>)[metrics.AV];
  const ac = (W.AC as Record<string, number>)[metrics.AC];
  const ui = (W.UI as Record<string, number>)[metrics.UI];
  const c = (W.C as Record<string, number>)[metrics.C];
  const i = (W.I as Record<string, number>)[metrics.I];
  const a = (W.A as Record<string, number>)[metrics.A];
  const s = metrics.S;
  if (!s || (s !== "U" && s !== "C")) return null;
  const prTbl = s === "C" ? W.PR_C : W.PR_U;
  const pr = (prTbl as Record<string, number>)[metrics.PR];
  if ([av, ac, ui, c, i, a, pr].some((x) => x === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = s === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  const base = s === "U"
    ? roundUp(Math.min(impact + exploitability, 10))
    : roundUp(Math.min(1.08 * (impact + exploitability), 10));
  return base;
}

/**
 * Stub for CVSS v4 — the v4 calculator is large; for the MVP we return null.
 * If the OSV record provides only a v4 vector we fall back to severity=null
 * which the UI handles gracefully.
 */
export function cvss4BaseScore(_vector: string): number | null {
  return null;
}

export function baseScoreFromVector(vector: string): number | null {
  if (vector.startsWith("CVSS:3")) return cvss3BaseScore(vector);
  if (vector.startsWith("CVSS:4")) return cvss4BaseScore(vector);
  return null;
}
