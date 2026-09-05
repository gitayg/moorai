// Learned per-agent behavioral baseline — treat each AI agent as a non-human digital actor and learn
// what "normal" looks like FOR THAT ACTOR, then score how far a new event/window strays from its own
// norm. This is the learned complement to data/agent-behavior.js's fixed signatures: instead of asking
// "does this match a known-bad pattern?", it asks "is this unusual for THIS agent, given everything it
// has done before?".
//
// CONTENT-FREE by construction. The only inputs are the metadata already on a content-free event —
// exactly the shape cli/signals.mjs's readAgentEvents() returns and the hook records:
//
//   event = { ts:number(ms), sig:"<tool>|<hashedActorId>", ok:boolean,
//             risk:"Low|Medium|High|Critical|Blocked", flags?:{...booleans},
//             legs?:{read,ingest,callout}, server?:string }
//
// The actor identity is a one-way hash the hook stamps as `agent` (the session for a top-level call, a
// DISTINCT id for a subagent's own calls; see actorId() below) — we group by it and never reverse it.
// Legacy rows with no `agent` fall back to the actor slot of `sig` (the part after the `|`). The tool
// name is the part before the `|`. Nothing here reads a prompt, a file, an argument, or an output — a
// stray content field on an event is simply never looked at.
//
// The whole thing is frequency/statistics, no ML dependency and no new deps: relative frequencies for
// categorical fields (tool / risk / server / flags / legs) and a robust median+IQR on inter-arrival
// gaps for cadence. Deterministic: same events in → same profile and same score out.

import { readAgentEvents } from "../cli/signals.mjs";
import {
  detectOrphanAgents, detectCrossAgentMessaging, detectTraceGaps,
  detectVelocityBurst, detectConfusedDeputy, detectFanOutAnomaly
} from "./agent-detections.js";

// Same risk ordering the hook uses (cli/moorai-hook.mjs) so a "risk spike" is measured on the same scale.
const RISK_RANK = { Low: 1, Medium: 2, High: 3, Critical: 4, Blocked: 5 };

// Cold-start honesty. An actor with fewer than MIN_EVENTS observations has no trustworthy norm yet, so
// its scores are flagged low-confidence and damped toward zero — we do NOT cry wolf on an agent's first
// few actions. Confidence ramps linearly to full at CONF_FULL events.
const MIN_EVENTS = 5;
const CONF_FULL = 12;

// Per-factor strength caps. Each factor contributes at most its weight; they are combined with a
// noisy-OR (below) so any one strong, well-understood deviation can drive the score high on its own,
// while many tiny ones do not stack past 1. Tuned so a genuinely novel tool or a risk spike dominates.
const W = {
  tool: 0.9,     // a tool this actor has never used (or almost never)
  risk: 0.9,     // a risk level above this actor's norm
  server: 0.6,   // a destination class (MCP server / "local") it has not reached before
  legs: 0.75,    // raising a trifecta leg (read/ingest/callout) it does not typically raise
  flags: 0.75,   // raising a content-tell flag it does not typically raise
  cadence: 0.8   // firing far faster than its own inter-arrival norm (machine-speed burst)
};

// A seen-but-rare categorical value should still register mildly, without ever rivaling a truly unseen
// one — so seen novelty is (1 - relativeFrequency) damped, unseen novelty is a full 1.0.
const SEEN_DAMPEN = 0.5;

// ---- sig decomposition. `sig` is "<tool>|<hashedActorId>"; the actor id is already hashed upstream. ----
function splitSig(sig) {
  const s = String(sig || "");
  const i = s.indexOf("|");
  return i >= 0 ? { tool: s.slice(0, i), actor: s.slice(i + 1) } : { tool: s, actor: s };
}
export function actorOf(sig) { return splitSig(sig).actor; }
export function toolOf(sig) { return splitSig(sig).tool; }

// The actor to profile an event under. The hook now stamps a content-free lineage id on every event
// (`agent` — the session for a top-level call, or a DISTINCT id for a subagent's own calls; see
// cli/moorai-hook.mjs), which is the identity a "per-agent" baseline must group by. `sig` cannot serve
// as that key: its actor slot is a hash of the tool TARGET (file path / command), so the autonomous-
// behavior signature can use the whole `sig` as a per-ACTION fingerprint — grouping by it would learn a
// per-target norm, not a per-agent one, and would merge every subagent back into its spawner. So prefer
// the explicit `agent` id and fall back to the `sig` actor only for legacy rows (pre-lineage) and the
// pure unit tests that carry a `sig` alone.
function actorId(e) {
  const a = e && (e.agent ?? e.agentId);
  if (a != null && a !== "") return String(a);
  return splitSig(e && e.sig).actor;
}

// ---- small robust-statistics helpers on a numeric array (no deps). ----
function quantile(sorted, q) {
  if (sorted.length === 0) return 0;
  if (sorted.length === 1) return sorted[0];
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos), hi = Math.ceil(pos);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}
function cadenceStats(gaps) {
  // Robust: median + IQR resist the occasional idle gap that would blow up a mean/std. n is the number
  // of gaps observed (one fewer than the actor's event count).
  const g = gaps.slice().sort((a, b) => a - b);
  const n = g.length;
  if (n === 0) return { n: 0, median: 0, iqr: 0, min: 0 };
  const median = quantile(g, 0.5);
  const iqr = quantile(g, 0.75) - quantile(g, 0.25);
  return { n, median, iqr, min: g[0] };
}

// Categorical novelty of value `v` against a {value -> count} tally over `total` observations.
//   unseen value           → 1.0 (fully novel for this actor)
//   seen with frequency p  → (1 - p) * SEEN_DAMPEN (rare-but-seen registers mildly, common ≈ 0)
function novelty(tally, total, v) {
  if (!total) return 0;                 // no history for this dimension → cannot call it novel
  const c = tally[v] || 0;
  if (c === 0) return 1;
  return (1 - c / total) * SEEN_DAMPEN;
}

// ---- buildBaseline: per-actor content-free profile from the event history. ----
// Returns { actors: { [actorId]: profile }, actorCount }, where each profile is:
//   { n, tools, risks, servers, flagKeys, legKeys, maxRiskRank, cadence:{n,median,iqr,min}, lastTs }
// tools/risks/servers/flagKeys/legKeys are {value -> count} tallies; every value is content-free metadata.
export function buildBaseline(events) {
  const evs = Array.isArray(events) ? events : [];
  const byActor = new Map();
  for (const e of evs) {
    if (!e || typeof e.sig !== "string") continue;
    const tool = splitSig(e.sig).tool;
    const actor = actorId(e);
    let p = byActor.get(actor);
    if (!p) {
      p = { n: 0, tools: {}, risks: {}, servers: {}, flagKeys: {}, legKeys: {}, maxRiskRank: 0, _ts: [] };
      byActor.set(actor, p);
    }
    p.n++;
    p.tools[tool] = (p.tools[tool] || 0) + 1;
    const risk = e.risk || "Low";
    p.risks[risk] = (p.risks[risk] || 0) + 1;
    p.maxRiskRank = Math.max(p.maxRiskRank, RISK_RANK[risk] || 0);
    const srv = e.server || "local";
    p.servers[srv] = (p.servers[srv] || 0) + 1;
    // Only TRUE flags/legs are norm-defining — a false flag is the absence of a tell, not a habit.
    const f = e.flags || {};
    for (const k of Object.keys(f)) if (f[k]) p.flagKeys[k] = (p.flagKeys[k] || 0) + 1;
    const l = e.legs || {};
    for (const k of Object.keys(l)) if (l[k]) p.legKeys[k] = (p.legKeys[k] || 0) + 1;
    if (typeof e.ts === "number") p._ts.push(e.ts);
  }
  const actors = {};
  for (const [actor, p] of byActor) {
    const ts = p._ts.slice().sort((a, b) => a - b);
    const gaps = [];
    for (let i = 1; i < ts.length; i++) gaps.push(ts[i] - ts[i - 1]);
    actors[actor] = {
      n: p.n, tools: p.tools, risks: p.risks, servers: p.servers,
      flagKeys: p.flagKeys, legKeys: p.legKeys, maxRiskRank: p.maxRiskRank,
      cadence: cadenceStats(gaps), lastTs: ts.length ? ts[ts.length - 1] : null
    };
  }
  return { actors, actorCount: Object.keys(actors).length };
}

// Confidence in a profile, in [0..1], ramping to full at CONF_FULL events. lowConfidence marks a profile
// still under MIN_EVENTS — its scores are damped and should not be treated as accusations.
function confidenceOf(n) { return Math.max(0, Math.min(1, n / CONF_FULL)); }

// Noisy-OR combine of independent weighted factors: 1 - Π(1 - v_i). Bounded [0,1], monotonic, and any
// single strong factor can drive it high without a pile of weak ones summing past 1.
function noisyOr(values) {
  let keep = 1;
  for (const v of values) keep *= (1 - Math.max(0, Math.min(1, v)));
  return 1 - keep;
}

// ---- scoreDeviation: how unusual is one event FOR ITS OWN ACTOR? ----
// Returns { score, confidence, lowConfidence, coldStart, actor, factors }, where factors is the sorted
// list of contributing causes (name + weighted contribution + a human-readable detail) so a person can
// read WHY. Content-free: only e.sig / e.risk / e.flags / e.legs / e.server / e.ts are consulted.
export function scoreDeviation(baseline, event) {
  const e = event || {};
  const tool = splitSig(e.sig).tool;
  const actor = actorId(e);
  const profile = baseline && baseline.actors ? baseline.actors[actor] : undefined;

  // Unknown actor: nothing learned yet. Honest cold start — near-zero score, explicitly low-confidence.
  if (!profile) {
    return { score: 0, confidence: 0, lowConfidence: true, coldStart: true, actor,
             factors: [{ name: "cold-start", contribution: 0, detail: "no baseline for this actor yet" }] };
  }

  const factors = [];
  const push = (name, factor, weight, detail) => {
    const contribution = Math.max(0, Math.min(1, factor)) * weight;
    if (contribution > 0) factors.push({ name, contribution, detail });
  };

  // Tool novelty.
  const toolNov = novelty(profile.tools, profile.n, tool);
  push("tool", toolNov, W.tool, profile.tools[tool] ? "rarely uses this tool" : "tool never used before");

  // Risk. Categorical novelty captures "a risk level it never reaches"; we additionally label it a spike
  // only when the level is above everything seen before, which is the case a human cares about.
  const risk = e.risk || "Low";
  const riskNov = novelty(profile.risks, profile.n, risk);
  const rank = RISK_RANK[risk] || 0;
  const spike = rank > profile.maxRiskRank;
  push("risk", riskNov, W.risk, spike ? `risk ${risk} above prior max` : "risk level unusual for this actor");

  // Destination class (MCP server name / "local").
  const srv = e.server || "local";
  const srvNov = novelty(profile.servers, profile.n, srv);
  push("server", srvNov, W.server, profile.servers[srv] ? "rarely reaches this destination" : "new destination class");

  // Trifecta legs raised. Only true legs matter; take the most novel one raised.
  const legs = e.legs || {};
  for (const k of Object.keys(legs)) if (legs[k]) {
    push("legs", novelty(profile.legKeys, profile.n, k), W.legs, `raises '${k}' leg it does not typically raise`);
  }

  // Content-tell flags raised (booleans only — never the matched text). Same treatment as legs.
  const flags = e.flags || {};
  for (const k of Object.keys(flags)) if (flags[k]) {
    push("flags", novelty(profile.flagKeys, profile.n, k), W.flags, `raises '${k}' flag it does not typically raise`);
  }

  // Cadence: is this event firing far faster than the actor's own inter-arrival norm? Needs the gap from
  // its previous event (baseline.lastTs) and a usable cadence distribution. "Too fast" (machine-speed
  // burst) is the interesting direction; a long idle gap is not anomalous.
  const cad = profile.cadence;
  if (typeof e.ts === "number" && profile.lastTs != null && cad.n >= 2 && cad.median > 0) {
    const gap = e.ts - profile.lastTs;
    const floor = cad.median - 1.5 * cad.iqr;              // robust lower fence
    if (gap >= 0 && gap < floor && gap < cad.median) {
      const factor = (cad.median - gap) / cad.median;      // fraction below the median gap
      push("cadence", factor, W.cadence, "firing faster than its cadence norm");
    }
  }

  factors.sort((a, b) => b.contribution - a.contribution);
  const confidence = confidenceOf(profile.n);
  const raw = noisyOr(factors.map((f) => f.contribution));
  // Damp by confidence so a thin baseline cannot produce a loud score — the cold-start guarantee.
  const score = raw * confidence;
  return { score, confidence, lowConfidence: profile.n < MIN_EVENTS, coldStart: false, actor, factors };
}

// ---- scoreWindow: how unusual is a WINDOW of events for one actor? ----
// Aggregates per-event deviations AND adds a window-level cadence check: the tightest inter-arrival gap
// inside the window versus the actor's learned cadence catches a machine-speed burst that no single
// event reveals on its own. All events in the window are expected to share one actor (the caller slices
// by actor); the first event's actor decides whose baseline is used.
export function scoreWindow(baseline, events) {
  const evs = (Array.isArray(events) ? events : []).filter((e) => e && typeof e.sig === "string");
  if (evs.length === 0) return { score: 0, confidence: 0, lowConfidence: true, coldStart: true, actor: null, factors: [] };

  const actor = actorId(evs[0]);
  const profile = baseline && baseline.actors ? baseline.actors[actor] : undefined;
  if (!profile) {
    return { score: 0, confidence: 0, lowConfidence: true, coldStart: true, actor,
             factors: [{ name: "cold-start", contribution: 0, detail: "no baseline for this actor yet" }] };
  }

  // Per-event contribution: take the strongest single deviating factor from each event, so the window
  // score reflects its most anomalous moment rather than being diluted by routine events around it.
  const perEvent = [];
  for (const e of evs) {
    const r = scoreDeviation(baseline, e);
    const top = r.factors[0];
    if (top && top.contribution > 0) perEvent.push({ ...top, ts: e.ts });
  }

  const factors = perEvent.slice().sort((a, b) => b.contribution - a.contribution);

  // Window cadence: tightest gap inside the window vs the actor's cadence norm. Catches a burst even
  // when each event on its own is a familiar tool at a familiar risk.
  const cad = profile.cadence;
  const ts = evs.map((e) => e.ts).filter((x) => typeof x === "number").sort((a, b) => a - b);
  if (ts.length >= 2 && cad.median > 0) {
    let minGap = Infinity;
    for (let i = 1; i < ts.length; i++) minGap = Math.min(minGap, ts[i] - ts[i - 1]);
    const floor = cad.median - 1.5 * cad.iqr;
    if (minGap < floor && minGap < cad.median) {
      const factor = (cad.median - minGap) / cad.median;
      factors.push({ name: "cadence", contribution: Math.max(0, Math.min(1, factor)) * W.cadence,
                     detail: "burst tighter than this actor's cadence norm" });
    }
  }

  factors.sort((a, b) => b.contribution - a.contribution);
  const confidence = confidenceOf(profile.n);
  const raw = noisyOr(factors.map((f) => f.contribution));
  const score = raw * confidence;
  return { score, confidence, lowConfidence: profile.n < MIN_EVENTS, coldStart: false, actor, events: evs.length, factors };
}

// ---- Wiring: consume the on-device event stream and produce the per-agent baseline PLUS the six
// content-free forensic detections — the graph-shape trio (orphan agents, cross-agent messaging, trace
// gaps) and the behavioral trio (velocity/burst, confused-deputy trust-boundary, subagent fan-out). The
// scoring functions above stay pure; this is the layer the CLI and any console-side collector call.
// FAIL-OPEN by construction — every read/build/detect step is wrapped and degrades to an empty result, so
// nothing here can throw into a caller that might sit on the enforcement path.

// Run all detections over an event array, each independently fail-open.
export function runAgentDetections(events) {
  const evs = Array.isArray(events) ? events : [];
  const safe = (fn) => { try { return fn(evs) || []; } catch { return []; } };
  return {
    orphans: safe(detectOrphanAgents),
    crossAgent: safe(detectCrossAgentMessaging),
    traceGaps: safe(detectTraceGaps),
    velocity: safe(detectVelocityBurst),
    confusedDeputy: safe(detectConfusedDeputy),
    fanOut: safe(detectFanOutAnomaly)
  };
}

// Read the on-device event stream (the "engine actually consumes the streams" step). Wrapped: a read
// error yields an empty window rather than propagating.
function readEvents() { try { return readAgentEvents(); } catch { return []; } }

// The full report: baseline profile per actor + the detections bucketed onto the agent they name, plus
// the complete detection lists and totals. `events` defaults to the on-device stream; tests pass an
// explicit array (no I/O). Content-free throughout — only ids, counts, timestamps, and hashes.
export function agentBaselineReport(events) {
  try {
    const evs = Array.isArray(events) ? events : readEvents();
    const baseline = buildBaseline(evs);
    const detections = runAgentDetections(evs);
    const findingsFor = (list, actor) => list.filter((f) => f.agent === actor);
    const agents = {};
    for (const [actor, profile] of Object.entries(baseline.actors)) {
      agents[actor] = {
        n: profile.n,
        tools: Object.keys(profile.tools).length,
        maxRiskRank: profile.maxRiskRank,
        servers: Object.keys(profile.servers),
        cadence: profile.cadence,
        lastTs: profile.lastTs,
        confidence: confidenceOf(profile.n),
        lowConfidence: profile.n < MIN_EVENTS,
        detections: {
          orphan: findingsFor(detections.orphans, actor),
          crossAgent: findingsFor(detections.crossAgent, actor),
          traceGaps: findingsFor(detections.traceGaps, actor),
          velocity: findingsFor(detections.velocity, actor),
          confusedDeputy: findingsFor(detections.confusedDeputy, actor),
          fanOut: findingsFor(detections.fanOut, actor)
        }
      };
    }
    return {
      events: evs.length,
      actorCount: baseline.actorCount,
      agents,
      detections,
      totals: {
        orphans: detections.orphans.length,
        crossAgent: detections.crossAgent.length,
        traceGaps: detections.traceGaps.length,
        velocity: detections.velocity.length,
        confusedDeputy: detections.confusedDeputy.length,
        fanOut: detections.fanOut.length
      }
    };
  } catch {
    return {
      events: 0, actorCount: 0, agents: {},
      detections: { orphans: [], crossAgent: [], traceGaps: [], velocity: [], confusedDeputy: [], fanOut: [] },
      totals: { orphans: 0, crossAgent: 0, traceGaps: 0, velocity: 0, confusedDeputy: 0, fanOut: 0 }
    };
  }
}
