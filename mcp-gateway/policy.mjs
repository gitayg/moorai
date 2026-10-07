// The gateway's policy + engine, loaded exactly as the stdio proxy loads them: loadVerifiedPolicy (the
// console's ed25519 envelope against the machine anchor or the TOFU pin; an unverifiable cache is NO
// policy), the durable posture ratchet (a fail-closed device gets OFFLINE_DEFAULT_POLICY), and a lazy
// 60 s refresh because this is a long-lived process. Coach vs enforce is the shared rule; server mode
// counts as management evidence, as it does in the hook.
import { buildEngine, loadVerifiedPolicy, ratchetPosture, enforcementAllowed, readRootOwned, readText, POSTURE_STATE, POSTURE_LATCH, POSTURE_LEGACY, SYSTEM_POSTURE } from "../cli/hook-core.mjs";
import { OFFLINE_DEFAULT_POLICY } from "../data/offline-default.js";
import { isEnrolled } from "../data/enforcement.js";
import { CONFIG, SERVER_MODE, reportOnce, setTierSource } from "./report.mjs";

export const state = { POLICY: null, ENGINE: null, COACH: !isEnrolled(CONFIG) && !SERVER_MODE.active, loadedAt: 0 };
setTierSource(() => (state.POLICY && state.POLICY.captureTier) || "content-free");

function durablePosture() {
  return ratchetPosture({
    system: readRootOwned(SYSTEM_POSTURE),
    state: readText(POSTURE_STATE),
    latch: readText(POSTURE_LATCH),
    legacy: readText(POSTURE_LEGACY),
    env: process.env.MOORAI_OFFLINE_MODE
  });
}

function reportPolicyTrust({ rejected, pin, trust, absence }) {
  for (const r of rejected || []) reportOnce(`Policy signature rejected (${r.status})`, `policy:${r.source}:${r.status}`, "Critical");
  if (trust && trust.mode === "rebind") reportOnce("Policy key pin tenant rebind refused", "policy:pin:tenant-rebind", "Critical");
  if (pin && pin.corrupt) reportOnce("Policy key pin unreadable", "policy:pin:corrupt", "Critical");
  else if (pin && pin.evidenceMissing) reportOnce("Policy key pin evidence missing", "policy:pin:evidence-missing", "High");
  if (absence && absence.suspicious) reportOnce("Policy key pin absent on a device with prior operation", "policy:pin:absent-operational", "Critical");
}

// MOORAI_TEST_POLICY_REFRESH_MS: a test hook that shortens the 60 s refresh (more fetching, never less).
const REFRESH_MS = process.env.MOORAI_TEST_POLICY_REFRESH_MS != null ? Math.max(0, Number(process.env.MOORAI_TEST_POLICY_REFRESH_MS) || 0) : 60000;
let inflight = null;
export async function ensurePolicy() {
  if (Date.now() - state.loadedAt < REFRESH_MS && state.ENGINE) return;
  if (inflight) return inflight; // concurrent requests share one refresh
  inflight = (async () => {
    try {
      const v = await loadVerifiedPolicy(CONFIG);
      const posture = durablePosture();
      state.COACH = !enforcementAllowed(CONFIG, { managed: posture.posture === "fail-closed" || SERVER_MODE.active });
      reportPolicyTrust(v);
      let policy = v.policy;
      if (!policy) {
        if (posture.posture === "fail-closed") { reportOnce("Offline: fail-closed default applied", "offline:fail-closed", "High"); policy = OFFLINE_DEFAULT_POLICY; }
      } else if (v.source === "last-known-good") reportOnce("Enforcing last-known-good verified policy", "policy:lkg:applied", "High");
      state.POLICY = policy;
      state.ENGINE = buildEngine(policy); // buildEngine(null) still scans and reports, as in the proxy
      state.loadedAt = Date.now();
    } catch { /* keep what we had; with no engine the gate fails open */ }
    finally { inflight = null; }
  })();
  return inflight;
}
