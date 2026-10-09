// The proxy's trust sources, loaded as the MCP gateway loads them (mcp-gateway/policy.mjs): the console's
// policy through loadVerifiedPolicy (its ed25519 envelope against the machine anchor or the TOFU pin; an
// unverifiable cache is NO policy), the durable posture ratchet (a fail-closed device gets
// OFFLINE_DEFAULT_POLICY), and the root-owned machine-wide config (readRootOwned: root-owned, not group- or
// world-writable). Re-read at most once a minute; the first connection waits for the first load, later
// refreshes run beside the traffic; until a first load succeeds the proxy answers 503. Coach vs enforce is
// the shared rule, server mode counting as management evidence. Never an environment variable or a file
// the proxy is pointed at.
import { loadVerifiedPolicy, ratchetPosture, enforcementAllowed, readRootOwned, readText, POSTURE_STATE, POSTURE_LATCH, POSTURE_LEGACY, SYSTEM_POSTURE } from "../cli/hook-core.mjs";
import { OFFLINE_DEFAULT_POLICY } from "../data/offline-default.js";
import { isEnrolled } from "../data/enforcement.js";
import { systemConfigPath } from "../cli/server-mode.mjs";
import { CONFIG, SERVER_MODE, reportOnce } from "./report.mjs";

const REFRESH_MS = 60000;

function readSystem() {
  try { const v = JSON.parse(readRootOwned(systemConfigPath()) || "null"); return v && typeof v === "object" && !Array.isArray(v) ? v : null; } catch { return null; }
}
function durablePosture() {
  return ratchetPosture({ system: readRootOwned(SYSTEM_POSTURE), state: readText(POSTURE_STATE), latch: readText(POSTURE_LATCH), legacy: readText(POSTURE_LEGACY), env: process.env.MOORAI_OFFLINE_MODE });
}

// The posture ratchet runs on every refresh, whether or not the load succeeds. A load that throws keeps
// what an earlier load gave (and a fail-closed device holding no policy gets OFFLINE_DEFAULT_POLICY), but
// a FIRST load that throws leaves the state unloaded: getState() throws and the proxy answers 503 until a
// load succeeds. Not the offline default instead: it carries no egressRules or egressDefault, so here it
// would mean "the machine-wide egressDefault, else allow", and an unknown policy is not "no policy".
// `deps` (load, posture, system, report, now) are injected by tests.
export function createPolicySource({ load = () => loadVerifiedPolicy(CONFIG), posture = durablePosture, system = readSystem, report = reportOnce, now = Date.now } = {}) {
  const state = { policy: null, system: null, coach: !isEnrolled(CONFIG) && !SERVER_MODE.active, loadedAt: 0 };
  let inflight = null;
  const offline = () => { report("Offline: fail-closed default applied", "offline:fail-closed", "High"); return OFFLINE_DEFAULT_POLICY; };

  function refresh() {
    if (inflight) return inflight;
    inflight = (async () => {
      try {
        let v = null;
        try { v = await load(); } catch { v = null; }
        const failClosed = posture().posture === "fail-closed";
        state.coach = !enforcementAllowed(CONFIG, { managed: failClosed || SERVER_MODE.active });
        if (v) {
          for (const r of v.rejected || []) report(`Policy signature rejected (${r.status})`, `policy:${r.source}:${r.status}`, "Critical");
          state.policy = v.policy || (failClosed ? offline() : null);
        } else if (state.loadedAt) {
          if (!state.policy && failClosed) state.policy = offline();
        } else return; // first load failed: stay unloaded
        state.system = system();
        state.loadedAt = now();
      } finally { inflight = null; }
    })();
    return inflight;
  }

  // → { policy, system, serviceId, coach } for judge.mjs; throws while no load has succeeded.
  async function getState() {
    if (!state.loadedAt) await refresh();
    else if (now() - state.loadedAt >= REFRESH_MS) refresh().catch(() => {});
    if (!state.loadedAt) throw new Error("the egress policy could not be loaded");
    return { policy: state.policy, system: state.system, serviceId: SERVER_MODE.active ? SERVER_MODE.serviceId || "" : "", coach: state.coach };
  }
  return { getState };
}

export const { getState } = createPolicySource();
