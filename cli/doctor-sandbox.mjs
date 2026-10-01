// A throwaway HOME that mirrors the parts of this device's MoorAI state the hook's policy path READS,
// so `moorai-doctor` and `moorai-explain` can run the real loader and the real hook without either one
// being able to write to the user's own state. Everything the hook would write (the policy cache, pin,
// last-known-good copy, posture, stamps) lands in the copy, which is deleted afterwards.
//
// What is NOT copied, on purpose:
//   * config.json — it holds the install token. The self-test writes a config with a placeholder token
//     (enrolled) or none (unenrolled) and a serverUrl on a closed loopback port, so nothing the hook
//     does in the sandbox can reach, or post to, the console.
//   * keys and caches (intent.key, instruction-fp.key, agency-ed25519.key, ...). The hook creates fresh
//     ones inside the sandbox; the device's own are never read into it.
// Operation-evidence files are copied as a one-byte stub: loadVerifiedPolicy only asks whether they are
// non-empty (presentArtifacts), and their contents are the device's activity log.
import { mkdtempSync, mkdirSync, copyFileSync, statSync, utimesSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";
import { STATE_DIR, LATCH_DIR, BREADCRUMB_DIR, LEGACY_DIRS } from "./state-dirs.mjs";

// Files the policy/posture/break-glass path reads, per directory leg.
const COPY = ["hook-policy.json", "policy-pin.json", "policy-lkg.json", "posture", "offline-posture", "pinned", "break-glass"];
const STUB = ["action-audit.jsonl", "exposure-ledger.jsonl", "agent-events.jsonl"];
// The hook's detached index/agent scanners are interval-gated by these stamps; a fresh stamp keeps the
// self-test from spawning a background worker that would outlive the sandbox.
const STAMPS = ["index-scan.stamp", "agent-scan.stamp"];

export const DEAD_SERVER = "http://127.0.0.1:9";

function copyLeg(from, to, names) {
  for (const n of names) {
    let st;
    try { st = statSync(join(from, n)); } catch { continue; }
    if (!st.isFile()) continue;
    mkdirSync(to, { recursive: true });
    copyFileSync(join(from, n), join(to, n));
    // The 60s policy-cache window is decided by mtime, so the copy keeps it.
    try { utimesSync(join(to, n), st.atime, st.mtime); } catch { /* best effort */ }
  }
}
function stubLeg(from, to, names) {
  for (const n of names) {
    try { if (statSync(join(from, n)).size > 0) { mkdirSync(to, { recursive: true }); writeFileSync(join(to, n), "\n"); } } catch { /* absent */ }
  }
}

// Returns { home, env(extra), cleanup }. `env` is the environment a child needs so that every state
// directory cli/state-dirs.mjs resolves lands inside the sandbox.
export function makeSandbox({ realHome = homedir(), config = null } = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-doctor-"));
  const xdgConfig = join(home, ".xdg-config");
  const xdgState = join(home, ".xdg-state");
  const appData = join(home, "AppData", "Roaming");
  const localAppData = join(home, "AppData", "Local");
  const win = process.platform === "win32";
  const sbLatch = win ? join(appData, "MoorAI") : join(xdgConfig, "moorai");
  const sbCrumb = win ? join(localAppData, "MoorAI") : join(xdgState, "moorai");
  const legs = [
    [STATE_DIR, join(home, ".moorai")],
    [LATCH_DIR, sbLatch],
    [BREADCRUMB_DIR, sbCrumb],
    ...LEGACY_DIRS.map((d, i) => [d, join(home, i === 0 ? ".curaiq" : ".raiseme")]),
    // Pre-rebrand POSIX breadcrumb (hook-core PIN_BREADCRUMB_LEGACY = ~/.config/moorai/pinned).
    [join(realHome, ".config", "moorai"), join(home, ".config", "moorai")]
  ];
  for (const [from, to] of legs) { copyLeg(from, to, COPY); stubLeg(from, to, STUB); }
  mkdirSync(join(home, ".moorai"), { recursive: true });
  for (const s of STAMPS) writeFileSync(join(home, ".moorai", s), "");
  if (config) writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify(config), { mode: 0o600 });
  mkdirSync(join(home, "proj"), { recursive: true });
  const env = (extra = {}) => {
    const e = { ...process.env, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: xdgConfig, XDG_STATE_HOME: xdgState, APPDATA: appData, LOCALAPPDATA: localAppData, ...extra };
    // Telemetry mirrors and other hosts' homes must not follow the child into the sandbox.
    // Server mode's env binding too (cli/server-mode.mjs): the child reads the placeholder config.json
    // instead, so the real console URL and install token never reach it. MOORAI_MODE and
    // MOORAI_SERVICE_ID stay, so the self-test runs the hook in the same mode as the device.
    for (const k of ["MOORAI_OTLP_ENDPOINT", "MOORAI_OTLP_HEADERS", "CODEX_HOME", "COPILOT_HOME", "MoorAI_SERVER", "MoorAI_TENANT", "MOORAI_SERVER_URL", "MOORAI_TENANT", "MOORAI_INSTALL_TOKEN"]) delete e[k];
    return e;
  };
  const cleanup = () => { try { rmSync(home, { recursive: true, force: true, maxRetries: 3 }); } catch { /* tmp */ } };
  return { home, proj: join(home, "proj"), env, cleanup };
}
