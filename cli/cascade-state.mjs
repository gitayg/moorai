// The hook's side of the cascade limits (data/cascade-limits.js): one state file, ~/.moorai/cascade-limits.json
// (mode 0600), holding per keyed session hash the spawn times, pending spawns (keyed sub-agent type and tool-use
// id, depth), each agent's keyed depth, each agent's latest call signature with its failure streak, the count of
// denied calls and the hold. Every id is an HMAC under the device session key (cli/session-state.mjs); nothing
// else is stored. 32 sessions, 24 h.
//
// Fail-open and best-effort like the other session files: an unreadable file reads as empty, a write error is
// swallowed, and parallel hook calls can lose one another's update (one observation). The agent runs as the same
// user and can delete the file, which resets its own counts.
import { readSessionState, writeSessionState, sessionKeyedHash as h, callSig } from "./session-state.mjs";
import { cascadeConfig, cascadeOff, cascadeAssess, cascadeFailure, cascadeBind, cascadeDenied } from "../data/cascade-limits.js";

export const CASCADE_FILE = "cascade-limits.json";
const sk = (sessionId) => (typeof sessionId === "string" && sessionId ? h(`cl:${sessionId}`) : null);
const ak = (agentId) => (typeof agentId === "string" && agentId ? h(`cl-agent:${agentId}`) : "");
const tk = (t) => (typeof t === "string" && t ? h(`cl-type:${t}`) : "");
const uk = (id) => (typeof id === "string" && id ? h(`cl-use:${id}`) : "");
const isSpawn = (tool) => tool === "Agent" || tool === "Task";

// PreToolUse. Returns { alerts, level: null | "ask" | "block", reason, first }: `first`, the reason text of the first
// limit this call is over, whatever its action (an unenrolled device is coached with it).
export function cascadeStep({ policy, sessionId, agentId, agentType, tool, toolInput, toolUseId, now = Date.now() }) {
  const none = { alerts: [], level: null, reason: "", first: "" };
  try {
    const cfg = cascadeConfig(policy);
    if (cascadeOff(cfg)) return none;
    const s = sk(sessionId), sig = callSig(tool, toolInput);
    if (!s || !sig) return none;
    const ti = toolInput && typeof toolInput === "object" ? toolInput : {};
    const r = cascadeAssess(readSessionState(CASCADE_FILE), s, { agent: ak(agentId), agentType: tk(agentType), sig, spawn: isSpawn(tool), spawnType: tk(ti.subagent_type), spawnId: uk(toolUseId) }, now, cfg);
    if (r.dirty) writeSessionState(CASCADE_FILE, r.state);
    return { alerts: r.alerts, level: r.level, reason: r.reason, first: r.first };
  } catch { return none; }
}

// PostToolUseFailure: the call failed.
export function cascadeFailStep({ sessionId, agentId, tool, toolInput, now = Date.now() }) {
  try {
    const s = sk(sessionId), sig = callSig(tool, toolInput);
    const state = s && sig ? readSessionState(CASCADE_FILE) : null;
    if (!state) return;
    const r = cascadeFailure(state, s, { agent: ak(agentId), sig }, now);
    if (r.dirty) writeSessionState(CASCADE_FILE, r.state);
  } catch { /* best-effort */ }
}

// PostToolUse(Agent / Task): tool_response.agentId names the child the call spawned.
export function cascadeBindStep({ sessionId, agentId, toolUseId, childId, now = Date.now() }) {
  try {
    const s = sk(sessionId), child = ak(childId);
    const state = s && child ? readSessionState(CASCADE_FILE) : null;
    if (!state) return;
    const r = cascadeBind(state, s, { caller: ak(agentId), child, spawnId: uk(toolUseId) }, now);
    if (r.dirty) writeSessionState(CASCADE_FILE, r.state);
  } catch { /* best-effort */ }
}

// A PreToolUse call MoorAI denied, other than by the cascade limits.
export function cascadeDeniedStep({ policy, sessionId, now = Date.now() }) {
  try {
    const cfg = cascadeConfig(policy);
    const s = sk(sessionId);
    if (!s || cascadeOff(cfg)) return;
    const r = cascadeDenied(readSessionState(CASCADE_FILE), s, now, cfg);
    if (r.dirty) writeSessionState(CASCADE_FILE, r.state);
  } catch { /* best-effort */ }
}
