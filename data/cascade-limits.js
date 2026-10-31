// Cascade limits: per-session caps on the ways one agent's failure spreads into many calls and many agents.
//
// Four limits, per session (the caller keys the session; the counts span the session's main agent and
// every sub-agent, so a fan-out of children adds up):
//
//   spawn-rate          more than `spawnsPerWindow` sub-agent spawns (Agent / Task calls) inside
//                       `spawnWindowMin` minutes. The spawning call itself counts.
//   depth               a spawn whose child would sit more than `maxDepth` layers below the main agent.
//                       Depth is known where it can be observed: the main agent is 0; a child named by its
//                       spawn's result (PostToolUse tool_response.agentId) or matched to the one pending
//                       spawn of its agent type is its spawner's depth + 1; any other sub-agent counts as 1,
//                       a lower bound.
//   repeat-failure      the same call (tool + a keyed hash of its arguments) by the same agent, after
//                       `maxIdenticalFailures` consecutive runs of it that each failed. A run whose failure
//                       was not reported before the next call breaks the streak, so a call that succeeds,
//                       or a host that sends no failure event for that tool, never trips it.
//   denied              `maxDenied` calls of the session denied by MoorAI (this limit's own denials excluded).
//                       The session is then held: every later call takes the action until `holdMin` minutes
//                       have passed (0 = for the rest of the session).
//
// policy.cascadeLimits.action: "report" (default: one alert per limit per session, verdict unchanged), "ask"
// (the call is raised to ask; a deny stays a deny), "block" (the call is denied), "off". actions: { kind:
// action } overrides it per limit. A limit set to 0 is off. Only the signed policy configures it.
//
// Pure and browser-safe. The caller hashes session, agent and call signatures with a device or process key;
// the state holds those hashes, timestamps and counts, never a tool argument, a path or a byte of output.

export const CASCADE_THREAT_ID = 93;
export const CASCADE_KINDS = ["spawn-rate", "depth", "repeat-failure", "denied"];
export const CASCADE_DEFAULTS = {
  action: "report",
  spawnsPerWindow: 20,
  spawnWindowMin: 10,
  maxDepth: 3,
  maxIdenticalFailures: 5,
  maxDenied: 20,
  holdMin: 0,
  maxSessions: 32
};
const ACTIONS = ["report", "ask", "block", "off"];
const LIMIT_OF = { "spawn-rate": "spawnsPerWindow", depth: "maxDepth", "repeat-failure": "maxIdenticalFailures", denied: "maxDenied" };
const TTL = 24 * 3600000;
const MAX_PENDING = 64, MAX_AGENTS = 256, MAX_SPAWNS = 1000;

export function cascadeConfig(policy) {
  const p = policy && typeof policy.cascadeLimits === "object" && policy.cascadeLimits && !Array.isArray(policy.cascadeLimits) ? policy.cascadeLimits : {};
  const out = { action: ACTIONS.includes(p.action) ? p.action : CASCADE_DEFAULTS.action };
  for (const k of Object.keys(CASCADE_DEFAULTS)) {
    if (k === "action") continue;
    const v = p[k];
    const zeroOk = k !== "spawnWindowMin" && k !== "maxSessions";
    out[k] = Number.isFinite(v) && (v > 0 || (zeroOk && v === 0)) ? Math.floor(v) : CASCADE_DEFAULTS[k];
  }
  out.actions = {};
  const a = p.actions && typeof p.actions === "object" && !Array.isArray(p.actions) ? p.actions : {};
  for (const k of CASCADE_KINDS) out.actions[k] = ACTIONS.includes(a[k]) ? a[k] : out.action;
  return out;
}
export const cascadeOff = (cfg) => CASCADE_KINDS.every((k) => cfg.actions[k] === "off" || !cfg[LIMIT_OF[k]]);

const num = (v) => typeof v === "number" && Number.isFinite(v);
const obj = (v) => v && typeof v === "object" && !Array.isArray(v);
const str = (v) => typeof v === "string";

function cleanSession(s, now) {
  if (!obj(s) || !num(s.last) || now - s.last > TTL) return null;
  const depth = {}, fail = {}, alerted = {};
  if (obj(s.depth)) for (const [k, d] of Object.entries(s.depth).slice(-MAX_AGENTS)) if (num(d)) depth[k] = d;
  if (obj(s.fail)) for (const [k, f] of Object.entries(s.fail).slice(-MAX_AGENTS)) if (Array.isArray(f) && f.length === 3 && str(f[0]) && num(f[1]) && typeof f[2] === "boolean") fail[k] = f;
  if (obj(s.alerted)) for (const [k, t] of Object.entries(s.alerted)) if (CASCADE_KINDS.includes(k) && num(t)) alerted[k] = t;
  return {
    last: s.last,
    spawns: Array.isArray(s.spawns) ? s.spawns.filter(num).slice(-MAX_SPAWNS) : [],
    pend: Array.isArray(s.pend) ? s.pend.filter((x) => Array.isArray(x) && x.length === 4 && num(x[0]) && str(x[1]) && num(x[2]) && str(x[3]) && now - x[0] < TTL).slice(-MAX_PENDING) : [],
    depth, fail, alerted,
    denied: num(s.denied) ? s.denied : 0,
    held: num(s.held) ? s.held : 0
  };
}
export function cleanCascadeState(state, now) {
  const out = { v: 1, sessions: {} };
  const ss = obj(state) && obj(state.sessions) ? state.sessions : {};
  for (const [k, s] of Object.entries(ss)) { const c = cleanSession(s, now); if (c) out.sessions[k] = c; }
  return out;
}
function sessionOf(st, session, now) {
  let s = st.sessions[session];
  if (!s) s = st.sessions[session] = { last: now, spawns: [], pend: [], depth: {}, fail: {}, alerted: {}, denied: 0, held: 0 };
  s.last = now;
  return s;
}
function evict(st, session, maxSessions) {
  const keys = Object.keys(st.sessions);
  if (keys.length <= maxSessions) return;
  const others = keys.filter((k) => k !== session).sort((x, y) => st.sessions[x].last - st.sessions[y].last);
  for (const k of others.slice(0, keys.length - maxSessions)) delete st.sessions[k];
}

// The depth of the calling agent: 0 for the main agent (no agent key), a recorded depth, the one pending spawn
// of its type (bound now), else 1.
function depthOf(s, agent, agentType) {
  if (!agent) return 0;
  if (num(s.depth[agent])) return s.depth[agent];
  if (agentType) {
    const m = s.pend.filter((p) => p[1] === agentType);
    if (m.length === 1) { s.depth[agent] = m[0][2]; s.pend = s.pend.filter((p) => p !== m[0]); return s.depth[agent]; }
  }
  return 1;
}

const LEVEL = { report: 0, ask: 1, block: 2 };
const CATEGORY = {
  "spawn-rate": "Cascade limit: sub-agent spawn rate",
  depth: "Cascade limit: sub-agent depth",
  "repeat-failure": "Cascade limit: repeated failing call",
  denied: "Cascade limit: session held after repeated denials"
};
export const CASCADE_REASON_CODE = "CASCADE_LIMIT";

// One PreToolUse call. call = { agent: keyed agent id ("" for the main agent), agentType: keyed agent type,
// sig: keyed hash of tool + arguments, spawn: true for an Agent / Task call, spawnType: keyed subagent_type,
// spawnId: keyed tool_use_id }. Returns { state, alerts: [alert body], level: null | "ask" | "block", reason,
// first, trips: [kind], dirty }. `level` is the strictest action among the limits this call is over, `reason` its
// text; `first` is the text of the first limit the call is over, whatever its action.
export function cascadeAssess(state, session, call, now, cfg = cascadeConfig(null)) {
  const st = cleanCascadeState(state, now);
  const none = { state: st, alerts: [], level: null, reason: "", first: "", trips: [], dirty: false };
  if (!str(session) || !session || !call || !str(call.sig) || !call.sig || cascadeOff(cfg)) return none;
  const s = sessionOf(st, session, now);
  const on = (k) => cfg.actions[k] !== "off" && cfg[LIMIT_OF[k]] > 0;
  const trips = [];
  if (s.held && s.held !== -1 && now >= s.held) { s.held = 0; s.denied = 0; delete s.alerted.denied; }
  if (on("denied") && s.held) trips.push({ kind: "denied", count: s.denied, limit: cfg.maxDenied, why: `MoorAI denied ${s.denied} calls in this session; the session is held${cfg.holdMin > 0 ? ` for ${cfg.holdMin} min` : " until it ends"}` });
  const agent = str(call.agent) ? call.agent : "";
  const blockingSig = (k) => on(k) && cfg.actions[k] === "block";
  if (call.spawn) {
    const d = depthOf(s, agent, str(call.agentType) ? call.agentType : "") + 1;
    s.spawns = s.spawns.filter((t) => now - t < cfg.spawnWindowMin * 60000);
    s.spawns.push(now);
    if (on("spawn-rate") && s.spawns.length > cfg.spawnsPerWindow) trips.push({ kind: "spawn-rate", count: s.spawns.length, limit: cfg.spawnsPerWindow, windowSec: cfg.spawnWindowMin * 60, why: `${s.spawns.length} sub-agent spawns in ${cfg.spawnWindowMin} min (limit ${cfg.spawnsPerWindow})` });
    if (on("depth") && d > cfg.maxDepth) trips.push({ kind: "depth", count: d, limit: cfg.maxDepth, why: `a sub-agent ${d} layers below the main agent (limit ${cfg.maxDepth})` });
    if (!trips.some((t) => blockingSig(t.kind))) {
      s.pend.push([now, str(call.spawnType) ? call.spawnType : "", d, str(call.spawnId) ? call.spawnId : ""]);
      if (s.pend.length > MAX_PENDING) s.pend = s.pend.slice(-MAX_PENDING);
    }
  } else if (agent) depthOf(s, agent, str(call.agentType) ? call.agentType : "");
  const f = s.fail[agent || "-"];
  const streak = f && f[0] === call.sig && f[2] ? f[1] : 0;
  if (on("repeat-failure") && streak >= cfg.maxIdenticalFailures) trips.push({ kind: "repeat-failure", count: streak, limit: cfg.maxIdenticalFailures, why: `the same call failed ${streak} times in a row (limit ${cfg.maxIdenticalFailures})` });
  // The call is recorded as the agent's latest, not yet failed. A call this limit blocks never runs, so its
  // streak is kept for the next identical attempt.
  if (!(streak && trips.some((t) => t.kind === "repeat-failure" && blockingSig(t.kind)))) s.fail[agent || "-"] = [call.sig, streak, false];
  const alerts = [];
  let level = null, reason = "";
  for (const t of trips) {
    const action = cfg.actions[t.kind];
    if (!(t.kind in s.alerted)) {
      s.alerted[t.kind] = now;
      alerts.push({ threatId: CASCADE_THREAT_ID, category: CATEGORY[t.kind], riskLevel: action === "block" ? "Blocked" : "Medium", stage: "behavior", reasonCode: CASCADE_REASON_CODE, contentHash: `cascade:${t.kind}`, cascade: { kind: t.kind, count: t.count, limit: t.limit, ...(t.windowSec ? { windowSec: t.windowSec } : {}), action } });
    }
    if (action === "report") continue;
    if (level === null || LEVEL[action] > LEVEL[level]) { level = action; reason = `cascade limit: ${t.why}`; }
  }
  evict(st, session, cfg.maxSessions);
  return { state: st, alerts, level, reason, first: trips[0] ? `cascade limit: ${trips[0].why}` : "", trips: trips.map((t) => t.kind), dirty: true };
}

// A failed call (PostToolUseFailure): the agent's latest call, when it is this one, failed.
export function cascadeFailure(state, session, { agent = "", sig }, now) {
  const st = cleanCascadeState(state, now);
  const s = st.sessions[session];
  const k = str(agent) && agent ? agent : "-";
  const f = s && s.fail[k];
  if (!f || f[0] !== sig || f[2]) return { state: st, dirty: false };
  s.fail[k] = [f[0], f[1] + 1, true];
  s.last = now;
  return { state: st, dirty: true };
}

// A spawn's result names its child (PostToolUse(Agent) tool_response.agentId): the child takes the depth the
// pending spawn recorded. Without a matching pending spawn the child is one below its spawner.
export function cascadeBind(state, session, { caller = "", child, spawnId = "" }, now) {
  const st = cleanCascadeState(state, now);
  const s = st.sessions[session];
  if (!s || !str(child) || !child || num(s.depth[child])) return { state: st, dirty: false };
  const i = spawnId ? s.pend.findIndex((p) => p[3] === spawnId) : -1;
  s.depth[child] = i >= 0 ? s.pend[i][2] : depthOf(s, caller, "") + 1;
  if (i >= 0) s.pend.splice(i, 1);
  s.last = now;
  return { state: st, dirty: true };
}

// A call MoorAI denied (not by this limit). At `maxDenied` the session is held.
export function cascadeDenied(state, session, now, cfg = cascadeConfig(null)) {
  const st = cleanCascadeState(state, now);
  if (!str(session) || !session || cascadeOff(cfg)) return { state: st, dirty: false };
  const s = sessionOf(st, session, now);
  s.denied += 1;
  if (!s.held && cfg.maxDenied > 0 && s.denied >= cfg.maxDenied) s.held = cfg.holdMin > 0 ? now + cfg.holdMin * 60000 : -1;
  evict(st, session, cfg.maxSessions);
  return { state: st, dirty: true };
}

// Stable text for one call (tool + arguments, object keys sorted, capped), for a caller to hash with its own key.
// The hook hashes the same canonical form (cli/session-state.mjs callSig).
function canon(v, depth = 0) {
  if (depth > 8) return "…";
  if (Array.isArray(v)) return `[${v.slice(0, 256).map((x) => canon(x, depth + 1)).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().slice(0, 256).map((k) => `${JSON.stringify(k)}:${canon(v[k], depth + 1)}`).join(",")}}`;
  return JSON.stringify(v === undefined ? null : v);
}
export const callText = (tool, input) => `call:${tool}\n${canon(input || {}).slice(0, 65536)}`;

// The same four steps over an in-memory state, for a long-lived process (the Agent SDK runtime).
export function cascadeMemory() {
  let state = { v: 1, sessions: {} };
  const run = (r) => { state = r.state; return r; };
  return {
    assess: (session, call, now, cfg) => run(cascadeAssess(state, session, call, now, cfg)),
    failure: (session, f, now) => run(cascadeFailure(state, session, f, now)),
    bind: (session, b, now) => run(cascadeBind(state, session, b, now)),
    denied: (session, now, cfg) => run(cascadeDenied(state, session, now, cfg))
  };
}
