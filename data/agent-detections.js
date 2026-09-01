// Three content-free forensic detections over the on-device agent-event stream, borrowed from the
// AgentDFIR playbook: silently-spawned (orphan) subagents, agent-to-agent messaging/handoff, and
// discontinuities (trace gaps) in a per-agent event trace. These are the learned baseline's forensic
// complement — where data/agent-baseline.js asks "is this unusual for THIS agent?", these ask "does the
// SHAPE of the event graph show an agent nobody spawned, two agents talking, or a trace with holes?".
//
// Pure functions over the metadata rows cli/signals.mjs's readAgentEvents() returns — never a prompt,
// argument, output, or file path. Beyond the guaranteed base row
//   { ts, sig:"<tool>|<hashedActorId>", ok, risk, flags, legs, server }
// a row MAY carry optional content-free LINEAGE metadata when the recorder has it; each field is an
// opaque id, a numeric counter, or a boolean — never content:
//   agent/agentId          this event's own agent id (else the hashed actor id from `sig`)
//   parent/parentId        the id this event claims spawned it
//   session/sessionId      the trace/session this event belongs to
//   role/kind              a role marker ("subagent" | "child" | "message" | "handoff" | …)
//   to/target/targetAgent/handoffTo   a recipient agent id for a handoff
//   seq/step               a monotonic per-agent (or per-session) step counter
//   total/steps            a declared total step count for a session
//
// Each detector degrades to [] when its metadata is absent, and every one FAILS OPEN: on any error it
// returns [] and never throws into a caller that might sit on the enforcement path.
//
// Findings are content-free: { type, agent, severity, count, evidence } where `evidence` holds ONLY
// ids, timestamps, counts, and hashes.

// The actor id is the part of `sig` after the "|" and is already a one-way hash upstream; kept local so
// this module has no import edge back into data/agent-baseline.js (which imports these).
function splitActor(sig) {
  const s = String(sig || "");
  const i = s.indexOf("|");
  return i >= 0 ? s.slice(i + 1) : s;
}
function toNum(v) {
  if (typeof v === "number") return Number.isFinite(v) ? v : undefined;
  if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
  return undefined;
}
function idOf(v) { return v != null && v !== "" ? String(v) : undefined; }

function ownId(e) { return idOf(e.agent ?? e.agentId) ?? splitActor(e.sig); }
function parentOf(e) { return idOf(e.parent ?? e.parentId); }
function sessionOf(e) { return idOf(e.session ?? e.sessionId); }
function targetOf(e) { return idOf(e.to ?? e.target ?? e.targetAgent ?? e.handoffTo); }
function serverOf(e) { return idOf(e.server); }
function roleOf(e) { return String(e.role ?? e.kind ?? "").trim().toLowerCase(); }
function stepOf(e) { return toNum(e.seq ?? e.step); }
function totalOf(e) { return toNum(e.total ?? e.steps); }
function tsOf(e) { return typeof e.ts === "number" && Number.isFinite(e.ts) ? e.ts : undefined; }

const CHILD_ROLES = new Set(["subagent", "sub-agent", "child", "spawned", "task"]);
const MSG_ROLES = new Set(["message", "handoff", "a2a", "agent-message"]);
function isChildRole(r) { return CHILD_ROLES.has(r); }
function isMessaging(e) {
  const f = e.flags || {};
  return f.handoff === true || f.agentMessage === true || f.a2a === true || MSG_ROLES.has(roleOf(e));
}
function sev(n, medCut, hiCut) { return n >= hiCut ? "high" : n >= medCut ? "medium" : "low"; }
function rows(events) { return Array.isArray(events) ? events.filter((e) => e && typeof e === "object") : []; }

// ---- orphan agents. A child/subagent event whose parent id never appears as any agent's own id (nor as
// any observed session id) → the parent was never seen spawning it: a silently-injected or lost-lineage
// agent. A child-ROLE event that declares no parent at all is the same class (no visible lineage). ----
export function detectOrphanAgents(events) {
  try {
    const evs = rows(events);
    if (!evs.length) return [];
    const owners = new Set(), sessions = new Set();
    for (const e of evs) { owners.add(ownId(e)); const s = sessionOf(e); if (s) sessions.add(s); }
    const known = (id) => owners.has(id) || sessions.has(id);

    const byChild = new Map();
    for (const e of evs) {
      const child = ownId(e);
      const parent = parentOf(e);
      let reason = null;
      if (parent != null) { if (parent !== child && !known(parent)) reason = "missing-parent"; }
      else if (isChildRole(roleOf(e))) reason = "no-lineage";
      if (!reason) continue;
      let b = byChild.get(child);
      if (!b) { b = { count: 0, parents: new Set(), reasons: new Set(), firstTs: null, lastTs: null }; byChild.set(child, b); }
      b.count++;
      if (parent != null) b.parents.add(parent);
      b.reasons.add(reason);
      const t = tsOf(e);
      if (t != null) { if (b.firstTs == null || t < b.firstTs) b.firstTs = t; if (b.lastTs == null || t > b.lastTs) b.lastTs = t; }
    }
    const out = [];
    for (const [child, b] of byChild) {
      out.push({
        type: "orphan-agent",
        agent: child,
        severity: sev(b.count, 2, 5),
        count: b.count,
        evidence: { reasons: [...b.reasons].sort(), parents: [...b.parents].sort(), events: b.count, firstTs: b.firstTs, lastTs: b.lastTs }
      });
    }
    return out.sort((a, b) => b.count - a.count || a.agent.localeCompare(b.agent));
  } catch { return []; }
}

// ---- cross-agent messaging. Evidence that one agent's activity feeds another. Two content-free tells:
//   (1) an explicit handoff — an event names a DIFFERENT target agent id;
//   (2) a shared messaging channel — a messaging-marked event on a destination reached by ≥2 distinct
//       agents (the sender hands off to the others sharing that channel).
// Never inferred from merely sharing a destination: a messaging MARKER or an explicit target is required,
// so an ordinary shared MCP server does not flag. ----
export function detectCrossAgentMessaging(events) {
  try {
    const evs = rows(events);
    if (!evs.length) return [];
    const byFrom = new Map();
    const addEdge = (from, to, channel) => {
      if (!from || !to || from === to) return;
      let b = byFrom.get(from);
      if (!b) { b = { count: 0, peers: new Set(), channels: new Set() }; byFrom.set(from, b); }
      b.count++; b.peers.add(to); if (channel) b.channels.add(channel);
    };

    for (const e of evs) { const to = targetOf(e); if (to) addEdge(ownId(e), to, serverOf(e)); }

    const channelAgents = new Map(); // channel → Set(agent)
    const channelSenders = new Map(); // channel → Set(agent that emitted a messaging-marked event)
    for (const e of evs) {
      const srv = serverOf(e);
      if (!srv) continue;
      if (!channelAgents.has(srv)) channelAgents.set(srv, new Set());
      channelAgents.get(srv).add(ownId(e));
      if (isMessaging(e)) { if (!channelSenders.has(srv)) channelSenders.set(srv, new Set()); channelSenders.get(srv).add(ownId(e)); }
    }
    for (const [srv, senders] of channelSenders) {
      const agents = channelAgents.get(srv);
      if (!agents || agents.size < 2) continue;
      for (const sender of senders) for (const peer of agents) addEdge(sender, peer, srv);
    }

    const out = [];
    for (const [from, b] of byFrom) {
      const peers = [...b.peers].sort();
      out.push({
        type: "cross-agent-messaging",
        agent: from,
        severity: peers.length >= 3 || b.count >= 5 ? "high" : peers.length >= 2 || b.count >= 2 ? "medium" : "low",
        count: b.count,
        evidence: { peers, peerCount: peers.length, channels: [...b.channels].sort(), edges: b.count }
      });
    }
    return out.sort((a, b) => b.count - a.count || a.agent.localeCompare(b.agent));
  } catch { return []; }
}

// ---- trace gaps. A discontinuity in a per-agent (or per-session) event trace, computed purely from the
// metadata already on the events:
//   missing-steps      — a monotonic step counter jumps (1,2,5 → steps 3,4 missing);
//   truncated-session  — a session's declared total step count exceeds the events actually observed;
//   time-gap           — a silent gap far above the agent's OWN robust cadence (both an absolute floor
//                        and a large multiple of its median inter-arrival gap), i.e. an unexplained hole
//                        a machine-speed trace should not have.
const GAP_FLOOR_MS = 300_000;         // 5 min absolute floor — below this, even a big ratio is not alarming
const GAP_RATIO = 20;                 // …and at least this many times the agent's own median gap
const MIN_GAPS_FOR_TIME = 4;          // need a few gaps before the median is trustworthy

function median(nums) {
  const g = nums.slice().sort((a, b) => a - b);
  const n = g.length;
  if (!n) return 0;
  const mid = n >> 1;
  return n % 2 ? g[mid] : (g[mid - 1] + g[mid]) / 2;
}

export function detectTraceGaps(events) {
  try {
    const evs = rows(events);
    if (!evs.length) return [];
    const out = [];
    const byAgent = new Map();
    for (const e of evs) { const a = ownId(e); if (!byAgent.has(a)) byAgent.set(a, []); byAgent.get(a).push(e); }

    for (const [agent, list] of byAgent) {
      const bySession = new Map();
      for (const e of list) { const s = sessionOf(e) ?? " none"; if (!bySession.has(s)) bySession.set(s, []); bySession.get(s).push(e); }

      for (const [session, group] of bySession) {
        const named = session !== " none" ? session : null;

        const stepped = group.map((e) => stepOf(e)).filter((s) => s != null).sort((a, b) => a - b);
        for (let i = 1; i < stepped.length; i++) {
          const missing = stepped[i] - stepped[i - 1] - 1;
          if (missing > 0) {
            out.push({ type: "trace-gap", agent, severity: sev(missing, 2, 5), count: missing,
              evidence: { kind: "missing-steps", from: stepped[i - 1], to: stepped[i], missing, session: named } });
          }
        }

        let declared;
        for (const e of group) { const t = totalOf(e); if (t != null) declared = declared == null ? t : Math.max(declared, t); }
        if (declared != null && named != null) {
          const missing = declared - group.length;
          if (missing > 0) {
            out.push({ type: "trace-gap", agent, severity: sev(missing, 2, 5), count: missing,
              evidence: { kind: "truncated-session", session: named, declared, observed: group.length, missing } });
          }
        }
      }

      const ts = list.map(tsOf).filter((t) => t != null).sort((a, b) => a - b);
      if (ts.length >= MIN_GAPS_FOR_TIME + 1) {
        const gaps = [];
        for (let i = 1; i < ts.length; i++) gaps.push(ts[i] - ts[i - 1]);
        const med = median(gaps);
        if (med > 0) {
          for (let i = 1; i < ts.length; i++) {
            const g = ts[i] - ts[i - 1];
            if (g >= GAP_FLOOR_MS && g >= GAP_RATIO * med) {
              out.push({ type: "trace-gap", agent, severity: g >= 10 * GAP_RATIO * med ? "high" : "medium", count: 1,
                evidence: { kind: "time-gap", gapMs: g, medianMs: med, ratio: Math.round(g / med), prevTs: ts[i - 1], ts: ts[i] } });
            }
          }
        }
      }
    }
    return out;
  } catch { return []; }
}
