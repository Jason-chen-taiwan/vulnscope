import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/**
 * Single-line Pro upsell shown at most once every PROMO_INTERVAL_MS.
 * Off when:
 *   - VULNSCOPE_NO_PROMO=1 (user opt-out)
 *   - --json output (machine-readable)
 *   - the resolved API URL isn't the official hosted instance
 *   - we showed it within the last 7 days
 *
 * State is a single timestamp in ~/.config/vulnscope/state.json.
 * Honors XDG_STATE_HOME / XDG_CONFIG_HOME when set so we don't
 * scatter dotfiles in $HOME.
 */
const PROMO_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;

interface State {
  lastPromoAt?: number;
}

function statePath(): string {
  const base =
    process.env.XDG_STATE_HOME ||
    process.env.XDG_CONFIG_HOME ||
    join(homedir(), ".config");
  return join(base, "vulnscope", "state.json");
}

function readState(): State {
  try {
    const raw = readFileSync(statePath(), "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") return parsed as State;
  } catch {
    /* missing or corrupt — start fresh */
  }
  return {};
}

function writeState(s: State): void {
  try {
    const path = statePath();
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(s), "utf8");
  } catch {
    /* read-only home directory etc. — silent. We never want a promo
       state write to break the actual check command. */
  }
}

export function shouldShowPromo(): boolean {
  if (process.env.VULNSCOPE_NO_PROMO === "1") return false;
  // Never write to user state from tests / CI. Suppresses promo
  // output so snapshot assertions stay stable, and prevents the
  // CLI's own test suite from polluting the dev's real ~/.config.
  if (process.env.NODE_ENV === "test" || process.env.VITEST) return false;
  const state = readState();
  if (!state.lastPromoAt) return true;
  return Date.now() - state.lastPromoAt >= PROMO_INTERVAL_MS;
}

export function markPromoShown(): void {
  if (process.env.NODE_ENV === "test" || process.env.VITEST) return;
  writeState({ lastPromoAt: Date.now() });
}
