// Read-only view of "which policy would the hook enforce on this device right now, and in which mode".
// Shared by moorai-doctor and moorai-explain so both answer from the same code the hook runs:
//   * the policy itself comes from hook-core's loadVerifiedPolicy, run in a child against a sandbox
//     copy of the device state (cli/doctor-sandbox.mjs), so the loader's cache/pin/LKG writes never
//     touch the real state;
//   * the no-policy / fail-closed / break-glass / coach resolution below mirrors main() in
//     cli/moorai-hook.mjs line for line, using the same exported primitives. The two values that are
//     private to moorai-hook.mjs (NO_POLICY_BASELINE and the break-glass anchor path) are READ out of
//     its source text — the file runs main() at import, so it cannot be imported.
import { trustedEnv } from "./server-mode.mjs";
import { readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import os from "node:os";
import { createHash } from "node:crypto";
import { ratchetPosture, readRootOwned, readText, POSTURE_STATE, POSTURE_LATCH, POSTURE_LEGACY, SYSTEM_POSTURE, verifyBreakGlass, parseTrustedKeys, offlineMode, isEnrolled, enforcementAllowed } from "./hook-core.mjs";
import { OFFLINE_DEFAULT_POLICY } from "../data/offline-default.js";
import { readState } from "./state-dirs.mjs";
import { makeSandbox, DEAD_SERVER } from "./doctor-sandbox.mjs";
import { serverMode, serviceWho } from "./server-mode.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
export const HOOK_FILE = join(HERE, "moorai-hook.mjs");
const CHILD = join(HERE, "doctor-policy-child.mjs");

export const fingerprint = (s) => createHash("sha256").update(String(s)).digest("hex").slice(0, 8);

let HOOK_SRC = null;
function hookSource() { if (HOOK_SRC == null) HOOK_SRC = readFileSync(HOOK_FILE, "utf8"); return HOOK_SRC; }

// `const NO_POLICY_BASELINE = { captureTier: "content-free", builtinDefault: true };` → object.
export function noPolicyBaseline(src = hookSource()) {
  const m = src.match(/const NO_POLICY_BASELINE = (\{[^;]*\});/);
  if (!m) throw new Error("NO_POLICY_BASELINE not found in cli/moorai-hook.mjs");
  return JSON.parse(m[1].replace(/([{,]\s*)([A-Za-z_$][\w$]*)\s*:/g, '$1"$2":'));
}

// Same two sources as trustedKeys() in moorai-hook.mjs: the root-owned BG_ANCHOR, then the MDM env var.
export function breakGlassAnchorPath() {
  return process.platform === "win32"
    ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "breakglass.pub")
    : "/etc/moorai/breakglass.pub";
}
export function breakGlassState(config) {
  const raw = readState("break-glass");
  if (!raw) return { active: false, status: "absent" };
  let keys = [];
  try { keys = parseTrustedKeys(`${readRootOwned(breakGlassAnchorPath())}\n${trustedEnv("MOORAI_BREAKGLASS_PUBKEY") || ""}`); } catch { /* none */ }
  // The hook scopes a marker to IDENTITY.device: the hostname, or in server mode the workload (svc:<id>).
  const sm = serverMode();
  const v = verifyBreakGlass(raw, { keys, tenant: config.tenant, device: sm.active ? serviceWho(sm).device : os.hostname() });
  return { active: !!v.active, status: v.status, expires: v.expires || "" };
}

export function durablePosture() {
  return ratchetPosture({
    system: readRootOwned(SYSTEM_POSTURE),
    state: readText(POSTURE_STATE),
    latch: readText(POSTURE_LATCH),
    legacy: readText(POSTURE_LEGACY),
    env: trustedEnv("MOORAI_OFFLINE_MODE")
  });
}

// Which file loadConfig() took the binding from (it does not say), in its own search order.
export function configSource(home = os.homedir()) {
  for (const dir of [".moorai", ".curaiq", ".raiseme"]) {
    const p = join(home, dir, "config.json");
    try { JSON.parse(readFileSync(p, "utf8")); return { path: p, mode: statSync(p).mode & 0o777 }; } catch { /* next */ }
  }
  return null;
}

// Run loadVerifiedPolicy in a child against a sandbox copy. offline → the child is handed a config
// whose serverUrl is a closed loopback port and whose token is a placeholder (the real one never
// leaves this process); online → the real config goes over the child's stdin, which is exactly the
// GET the hook itself makes (/api/policy and /api/policy/pubkey), and nothing else.
export function loadPolicyReadOnly(config, { offline = true, timeoutMs = 15000 } = {}) {
  const sb = makeSandbox();
  try {
    const cfg = offline
      ? { serverUrl: DEAD_SERVER, tenant: config.tenant, ...(isEnrolled(config) ? { installToken: "moorai-doctor-placeholder" } : {}) }
      : { serverUrl: config.serverUrl, tenant: config.tenant, ...(isEnrolled(config) ? { installToken: config.installToken } : {}) };
    const r = spawnSync(process.execPath, [CHILD], { input: JSON.stringify(cfg), env: sb.env(), encoding: "utf8", timeout: timeoutMs });
    if (r.status !== 0) return { error: `policy loader exited ${r.status}${r.signal ? ` (${r.signal})` : ""}: ${String(r.stderr || "").trim().split("\n").pop() || "no output"}` };
    return JSON.parse(r.stdout);
  } catch (e) {
    return { error: String(e && e.message || e) };
  } finally { sb.cleanup(); }
}

// main()'s resolution, from the loaded policy to the one decideText is handed, plus coach vs enforce.
export function resolveEffective(loaded, config) {
  const posture = durablePosture();
  const bg = breakGlassState(config);
  let policy = loaded && loaded.policy ? loaded.policy : null;
  let basis = policy ? `org policy (${loaded.source})` : "";
  let allowAll = false;
  if (!policy) {
    if (posture.posture !== "fail-closed") { policy = noPolicyBaseline(); basis = "built-in defaults (no org policy)"; }
    else if (bg.active) { allowAll = true; basis = "break-glass active: the hook allows every call"; }
    else { policy = OFFLINE_DEFAULT_POLICY; basis = "offline fail-closed default (no policy, fail-closed posture)"; }
  } else if (offlineMode(policy) === "fail-closed" && bg.active) {
    allowAll = true; basis = "break-glass active: the hook allows every call";
  }
  const server = serverMode();
  const coach = !enforcementAllowed(config, { managed: posture.posture === "fail-closed" || server.active });
  return { policy, basis, allowAll, coach, posture, breakGlass: bg, server };
}
