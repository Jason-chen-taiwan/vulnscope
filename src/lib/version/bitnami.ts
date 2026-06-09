/**
 * Bitnami version comparator.
 *
 * Bitnami images use SemVer-with-distro-suffix: `8.0.30-debian-11-r12`.
 * The structure is `<upstream-version>-<distro>-<distro-version>-r<revision>`.
 *
 * Strategy: strip the distro suffix when present and compare upstream
 * via semver; tiebreak on the `-rN` revision number. If the distro
 * portion differs (Debian 10 vs Debian 11), we treat that as part of
 * the package identity — different builds of the same upstream version,
 * sorted lex on the distro string after upstream comparison succeeds.
 */
import semver from "semver";
import { lexicographic, type Comparator } from "./types";

interface BitnamiVersion {
  upstream: string;
  distro: string; // "debian-11" or ""
  revision: number; // -rN, default 0 when absent
}

function parseBitnami(v: string): BitnamiVersion | null {
  if (!v) return null;
  // Capture `-rN` at the end if present
  let core = v;
  let revision = 0;
  const revMatch = /-r(\d+)$/.exec(core);
  if (revMatch) {
    revision = Number(revMatch[1]);
    core = core.slice(0, revMatch.index);
  }
  // Look for a -distro suffix like -debian-11 or -ubuntu-22
  const distroMatch = /-(debian|ubuntu|centos|rhel|alpine|fedora)-\d+$/.exec(
    core,
  );
  let distro = "";
  let upstream = core;
  if (distroMatch) {
    distro = distroMatch[0].slice(1); // drop leading -
    upstream = core.slice(0, distroMatch.index);
  }
  return { upstream, distro, revision };
}

export const bitnamiComparator: Comparator = {
  cmp(a, b) {
    if (a === b) return 0;
    if (a === "0") return -1;
    if (b === "0") return 1;
    const pa = parseBitnami(a);
    const pb = parseBitnami(b);
    if (!pa || !pb) return lexicographic(a, b);

    // Upstream via semver (coerce — Bitnami sometimes has 4-part)
    const ua = semver.coerce(pa.upstream);
    const ub = semver.coerce(pb.upstream);
    if (ua && ub) {
      const c = semver.compare(ua.version, ub.version);
      if (c !== 0) return c;
    } else if (pa.upstream !== pb.upstream) {
      return lexicographic(pa.upstream, pb.upstream);
    }

    // Same upstream — compare distro then revision
    if (pa.distro !== pb.distro) return lexicographic(pa.distro, pb.distro);
    if (pa.revision !== pb.revision)
      return pa.revision < pb.revision ? -1 : 1;
    return 0;
  },
};
