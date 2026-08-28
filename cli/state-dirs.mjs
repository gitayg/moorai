import os from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";

// The agent's per-user state, kept across THREE deliberately-different user-scope directories plus a
// root-owned leg. This is a tamper-evidence design, not redundancy for its own sake: each critical
// fact (the policy-key pin, the last-known-good verified policy, the offline posture) is written to
// more than one directory so that erasing one — `rm -rf ~/.moorai`, or a single-file `rm` — cannot
// take the device's anti-rollback memory with it, and a PARTIAL erasure stays detectable (an erased
// pin must not read as a fresh install). hook-core.mjs combines the legs by a ratchet (strongest
// value wins) and flags evidenceMissing when they disagree.
//
// Rebrand: these were ~/.curaiq (primary) and ~/.moorai (latch). The CuraIQ name is retired WITHOUT
// collapsing the legs. The new primary is ~/.moorai (which already held the old latch, so its state
// is continuous), and a fresh, distinct latch and breadcrumb are introduced. Migration is handled by
// the ratchet itself, not by a copy step: ~/.curaiq (and ~/.raiseme) stay READ-ONLY legacy legs, so
// the strongest value across old and new legs still wins and no anti-rollback mark can be downgraded.
// Nothing is ever WRITTEN to a legacy directory again.

const home = os.homedir();
const win = process.platform === "win32";

// Three distinct user-scope WRITE directories. Windows: USERPROFILE / APPDATA(roaming) /
// LOCALAPPDATA(local). POSIX: home dotdir / XDG config / XDG state.
export const STATE_DIR = join(home, ".moorai");
export const LATCH_DIR = win
  ? join(process.env.APPDATA || join(home, "AppData", "Roaming"), "MoorAI")
  : join(process.env.XDG_CONFIG_HOME || join(home, ".config"), "moorai");
export const BREADCRUMB_DIR = win
  ? join(process.env.LOCALAPPDATA || join(home, "AppData", "Local"), "MoorAI")
  : join(process.env.XDG_STATE_HOME || join(home, ".local", "state"), "moorai");

// READ-ONLY legacy user-scope legs, oldest brand last. Never written. Present so the ratchet keeps
// honouring state from an install that predates the rebrand until the new legs have been written.
export const LEGACY_DIRS = [join(home, ".curaiq"), join(home, ".raiseme")];

// A single-copy state/config file (NOT a tamper-evidence latch): write to STATE_DIR, but read with a
// legacy fallback so an install that predates the rebrand keeps its config/provider-key until the app
// next writes the new location. Returns "" when the file is in none of the directories.
export function readState(name) {
  for (const dir of [STATE_DIR, ...LEGACY_DIRS]) {
    try { return readFileSync(join(dir, name), "utf8"); } catch { /* try next */ }
  }
  return "";
}

export function statePath(...p) { return join(STATE_DIR, ...p); }
export function latchPath(...p) { return join(LATCH_DIR, ...p); }
export function breadcrumbPath(...p) { return join(BREADCRUMB_DIR, ...p); }

// Every directory a given state file may be READ from, most-authoritative new legs first, then the
// read-only legacy legs. Callers ratchet across the values; they WRITE only to statePath/latchPath.
export function readLegs(name) {
  return [
    join(STATE_DIR, name),
    join(LATCH_DIR, name),
    ...LEGACY_DIRS.map((d) => join(d, name))
  ];
}
