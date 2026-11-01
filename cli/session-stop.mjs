// Operator stop (kill switch). An administrator stops one agent session, or every agent on a device, in the
// console; the console adds the stop to the signed policy it serves to the matching devices (`agentStops`). The
// hook reads it from the VERIFIED policy only, so nothing in the user's write scope can add, change or lift one:
//   { id: "st-<32 hex>", scope: "session" | "device", session?: "h2:<16 hex>", at: ISO 8601, reason?: <= 200 chars }
// scope "session" matches the hook's keyed session hash (the `session` field on every alert); scope "device"
// matches every session on the device. A matching PreToolUse is denied and a matching UserPromptSubmit is blocked,
// on every call, for as long as the console serves the stop. The first matching call of a session also asks the
// agent process to end: SIGTERM to the process that ran the hook (past the hook command's shells, and the
// adapter's node for a shim), on macOS and Linux only, and only when that process is an AI CLI or node. A device
// stop also drops the desktop host's kill-session sentinel, which ends the agent the MoorAI desktop app runs.
// LIMIT: the hook learns of a stop on its next policy fetch, which happens on a hook call once the cached policy is
// 60 s old (cli/hook-core.mjs), so a stop takes effect on the first call at least 60 s after the last fetch; an idle
// agent is stopped when it next calls a tool. Windows: calls are denied, the process is not signalled.
import { defaultReadChain, isHookShell, classifyImage, imageBase } from "./ai-cli-parents.mjs";

export const STOP_CATEGORY = "Session stopped by an administrator";
const ID_RE = /^st-[0-9a-f]{32}$/;
const SESSION_RE = /^h2:[0-9a-f]{16}$/;
const MAX_STOPS = 200;
const MAX_TO_AGENT = 4;

function valid(s) {
  if (!s || typeof s !== "object" || Array.isArray(s) || !ID_RE.test(String(s.id))) return false;
  if (s.scope === "device") return true;
  return s.scope === "session" && SESSION_RE.test(String(s.session));
}

// The stops the verified policy carries, malformed entries dropped.
export function agentStops(policy) {
  const list = policy && Array.isArray(policy.agentStops) ? policy.agentStops.slice(0, MAX_STOPS) : [];
  return list.filter(valid);
}

// The stop that applies to this session (a session stop for this exact session wins over a device stop), or null.
// session: the hook's SESSION_TAG ("" when the agent sent no session id: only a device stop can match).
export function stopFor(policy, session) {
  const list = agentStops(policy);
  return (session && list.find((s) => s.scope === "session" && s.session === session)) || list.find((s) => s.scope === "device") || null;
}

const clean = (r) => String(r).replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 200);
export function stopReason(stop) {
  const what = stop.scope === "device" ? "every agent on this device" : "this agent session";
  const why = typeof stop.reason === "string" && clean(stop.reason) ? `: ${clean(stop.reason)}` : "";
  return `an administrator stopped ${what} (stop ${stop.id})${why}. No further tool calls run in it; ask your administrator to lift the stop`;
}

// The content-free record the console reads as the stop's acknowledgement. signalled: a SIGTERM is being sent
// to the agent process (findAgentPid found one).
export function stopAlert(stop, { tool, signalled }) {
  return { threatId: 0, category: STOP_CATEGORY, riskLevel: "Blocked", stage: "policy", tool, contentHash: `stop:${stop.id}`, reasonCode: "SESSION_KILL", decision: "deny",
    stopId: stop.id, stopScope: stop.scope, signalled: signalled === true };
}

// The agent process that ran this hook: walk up from startPid past the hook command's shells (and, for a shim,
// the adapter's node). Only an AI CLI or node is returned; a terminal, an IDE or anything else is 0.
export function agentProcess(chain, { shim = false } = {}) {
  const c = Array.isArray(chain) ? chain : [];
  let i = 0;
  const skipShells = () => { while (i < c.length && i < MAX_TO_AGENT && isHookShell(c[i].image)) i++; };
  skipShells();
  if (shim && i < c.length && /^(node|nodejs)$/i.test(imageBase(c[i].image))) { i++; skipShells(); }
  const a = c[i];
  if (!a || !(a.pid > 1) || a.pid === process.pid) return 0;
  const k = imageBase(a.image).toLowerCase().replace(/\.exe$/, "");
  return classifyImage(a.image) === "agent" || k === "node" || k === "nodejs" ? a.pid : 0;
}

// The pid to SIGTERM, or 0 (not macOS or Linux, no agent process found). Never throws.
export function findAgentPid({ startPid, shim = false, platform = process.platform, readChain = null } = {}) {
  if (platform !== "darwin" && platform !== "linux") return 0;
  try { return agentProcess((readChain || defaultReadChain(platform))(startPid, MAX_TO_AGENT + 2), { shim }); } catch { return 0; }
}

export function signalAgent(pid, kill = (p) => process.kill(p, "SIGTERM")) {
  if (!(pid > 1)) return false;
  try { kill(pid); return true; } catch { return false; }
}
