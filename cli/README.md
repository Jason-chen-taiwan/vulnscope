# vulnscope

Scan your lockfile for known CVEs, with **CISA KEV** and **FIRST EPSS**
overlays baked in. Powered by the [VulnScope](https://github.com/Jason-chen-taiwan/vulnscope)
project; uses its hosted API by default so there's nothing to install
or sync.

## Install

No install needed:

```bash
npx vulnscope check
```

Or install globally:

```bash
npm i -g vulnscope
vulnscope check
```

Requires Node 18+.

## Usage

```bash
# Auto-detect lockfile in current directory
vulnscope check

# Explicit path to a lockfile or project directory
vulnscope check ./path/to/pnpm-lock.yaml
vulnscope check ../some-project

# Machine-readable JSON (for CI / scripting)
vulnscope check --json

# Only fail on CRITICAL or HIGH
vulnscope check --severity CRITICAL,HIGH

# Ignore specific CVEs you've accepted as risk
vulnscope check --ignore CVE-2021-23337 --ignore CVE-2024-12345

# CI-friendly: report findings but never fail
vulnscope check --exit-zero
```

### Flags

| Flag | What it does |
|---|---|
| `--api <url>` | Override the backend (default `https://vulnscope-tw.fly.dev`; env `VULNSCOPE_API` also works) |
| `--json` | Output stable JSON, suppress banners |
| `--exit-zero` | Always exit 0, even when CVEs found |
| `--severity <list>` | Comma list: `CRITICAL,HIGH,MEDIUM,LOW` |
| `--ignore <cve>` | Suppress a specific CVE ID (repeatable) |
| `--quiet` | Print only when findings exist |
| `--no-color` | Disable ANSI colors |

### Exit codes

- `0` — clean (or filtered to clean, or `--exit-zero`)
- `1` — found one or more vulnerabilities
- `2` — operational error (parse failure, network error, missing file)

The split between **1** and **2** lets CI tell "the tool ran but found
real CVEs" apart from "the tool itself broke."

## Supported lockfiles (v0.1)

- `package-lock.json` (npm, lockfileVersion 2 or 3)
- `pnpm-lock.yaml` (v9)

Yarn, Bun, Python, Go, Rust etc. are on the roadmap — open an issue
or PR for what you need next.

## Example output

```
Scanning 684 packages from ./pnpm-lock.yaml...
  [1/2] chunks sent
  [2/2] chunks sent

Severity  CVE             Package          Installed  Fixed    KEV  EPSS   Summary
────────  ──────────────  ───────────────  ─────────  ───────  ───  ─────  ───────────────────────────
HIGH      CVE-2026-39356  npm/drizzle-orm  0.36.4     0.45.2        0.02%  Drizzle ORM has SQL injec…
MEDIUM    CVE-2026-41305  npm/postcss      8.4.31     8.5.10        0.01%  PostCSS has XSS via Unesc…

✗ Found 2 vulnerabilities (1 HIGH, 1 MEDIUM) in 2 packages · 629 packages not in database.
Top recommendation: upgrade drizzle-orm from 0.36.4 to 0.45.2.
```

## CI example

GitHub Actions:

```yaml
- run: npx vulnscope check --severity CRITICAL,HIGH
```

GitLab:

```yaml
audit:
  script: npx vulnscope check --severity CRITICAL,HIGH
```

To capture results without failing the build:

```yaml
- run: npx vulnscope check --json --exit-zero > vulns.json
```

## Backend / self-host

By default the CLI talks to `https://vulnscope-tw.fly.dev` (free, no
auth, "best effort, no SLA"). To point at your own deployment:

```bash
vulnscope check --api https://vulns.your-company.com
# or
VULNSCOPE_API=https://vulns.your-company.com vulnscope check
```

Self-hosting docs:
https://github.com/Jason-chen-taiwan/vulnscope#deploy-your-own

## What we are / aren't

- ✅ **Are**: a fast, opinionated lockfile→CVE checker with KEV/EPSS
  context, designed to slot into CI and into `npx` for one-off audits.
- ❌ **Aren't**: an SBOM scanner ([Trivy](https://github.com/aquasecurity/trivy),
  [Grype](https://github.com/anchore/grype) do that better),
  an auto-patcher (Dependabot/Renovate), or an interactive UI
  (use [the web app](https://vulnscope-tw.fly.dev) for that).

## License

MIT
