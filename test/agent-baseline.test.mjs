// Learned per-agent behavioral baseline — pure unit tests. No HOME, no fs, no hook: feed content-free
// event arrays straight in. Events use the exact shape readAgentEvents() returns and the hook records:
//   { ts, sig:"<tool>|<hashedActorId>", ok, risk, flags, legs, server }
//
//   node --test test/agent-baseline.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildBaseline, scoreDeviation, scoreWindow, actorOf, toolOf } from "../data/agent-baseline.js";

// Two distinct hashed actor ids (already one-way upstream; opaque here).
const A = "h2:aaaa1111";
const B = "h2:bbbb2222";
const sig = (tool, actor) => `${tool}|${actor}`;

// A stable actor A: 20 Read calls, Low risk, one MCP server, ~1000ms apart, no flags/legs.
function stablePattern(actor = A, tool = "Read", n = 20, start = 1_000_000, step = 1000) {
  const evs = [];
  for (let i = 0; i < n; i++) {
    evs.push({ ts: start + i * step, sig: sig(tool, actor), ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: {} });
  }
  return evs;
}

test("matching event scores LOW, unseen tool scores HIGH — for the same actor", () => {
  const base = buildBaseline(stablePattern());
  const matching = { ts: 1_100_000, sig: sig("Read", A), ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: {} };
  const novelTool = { ts: 1_100_000, sig: sig("Bash", A), ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: {} };

  const lo = scoreDeviation(base, matching);
  const hi = scoreDeviation(base, novelTool);

  assert.ok(lo.score < 0.15, `matching event should score low, got ${lo.score}`);
  assert.ok(hi.score > 0.7, `unseen tool should score high, got ${hi.score}`);
  assert.equal(hi.factors[0].name, "tool", "top factor for an unseen tool should be 'tool'");
});

test("risk spike scores HIGH and names the risk factor", () => {
  const base = buildBaseline(stablePattern());
  const spike = { ts: 1_100_000, sig: sig("Read", A), ok: false, risk: "Critical", server: "files-mcp", flags: {}, legs: {} };
  const r = scoreDeviation(base, spike);
  assert.ok(r.score > 0.7, `risk spike should score high, got ${r.score}`);
  assert.equal(r.factors[0].name, "risk");
  assert.match(r.factors[0].detail, /above prior max/);
});

test("new destination class and a newly-raised trifecta leg both register", () => {
  const base = buildBaseline(stablePattern());
  const newSrv = scoreDeviation(base, { ts: 1_100_000, sig: sig("Read", A), ok: true, risk: "Low", server: "evil-mcp", flags: {}, legs: {} });
  assert.ok(newSrv.factors.some((f) => f.name === "server"), "a new server should surface a 'server' factor");

  const newLeg = scoreDeviation(base, { ts: 1_100_000, sig: sig("Read", A), ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: { callout: true } });
  assert.ok(newLeg.factors.some((f) => f.name === "legs"), "a newly-raised leg should surface a 'legs' factor");
  assert.ok(newLeg.score > 0.5, `newly-raised callout leg should score meaningfully, got ${newLeg.score}`);
});

test("off-cadence burst scores HIGH via scoreWindow", () => {
  const base = buildBaseline(stablePattern()); // norm ~1000ms between events
  // Ten familiar Read/Low/files-mcp events crammed into ~10ms apart — a machine-speed burst.
  const burst = [];
  for (let i = 0; i < 10; i++) burst.push({ ts: 2_000_000 + i * 10, sig: sig("Read", A), ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: {} });
  const r = scoreWindow(base, burst);
  assert.ok(r.factors.some((f) => f.name === "cadence"), "a tight burst should surface a 'cadence' factor");
  assert.ok(r.score > 0.6, `off-cadence burst should score high, got ${r.score}`);
});

test("two actors get independent baselines", () => {
  // A only ever Reads; B only ever runs Bash. Cross-check that each actor's own norm is used.
  const events = [...stablePattern(A, "Read"), ...stablePattern(B, "Bash")];
  const base = buildBaseline(events);
  assert.equal(base.actorCount, 2);

  // Bash is normal for B (low) but novel for A (high) — same event, opposite verdict by actor.
  const bashForB = scoreDeviation(base, { ts: 1_100_000, sig: sig("Bash", B), ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: {} });
  const bashForA = scoreDeviation(base, { ts: 1_100_000, sig: sig("Bash", A), ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: {} });
  assert.ok(bashForB.score < 0.15, `Bash should be normal for B, got ${bashForB.score}`);
  assert.ok(bashForA.score > 0.7, `Bash should be anomalous for A, got ${bashForA.score}`);
});

test("per-agent grouping: events are profiled by their `agent` lineage id, not the sig target slot", () => {
  // The hook stamps `agent` (the session for a top-level call, a DISTINCT id for a subagent's own
  // calls) while the actor slot of `sig` is a hash of the tool TARGET. Here two streams share ONE sig
  // slot (same hashed target) but carry different `agent` ids — a parent session and a subagent. A
  // per-agent baseline must treat them as two actors; if it fell back to the shared sig slot they would
  // merge into one (actorCount === 1) and this test would fail.
  const target = "h2:same-target-hash";
  const parent = "h2:session-parent";
  const child = "h2:subagent-child";
  const evs = [];
  for (let i = 0; i < 12; i++) {
    evs.push({ ts: 1_000_000 + i * 1000, sig: sig("Read", target), agent: parent, session: parent, ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: {} });
    evs.push({ ts: 1_000_500 + i * 1000, sig: sig("Read", target), agent: child, session: parent, parent, role: "subagent", ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: {} });
  }
  const base = buildBaseline(evs);
  assert.equal(base.actorCount, 2, "the parent session and the subagent must be distinct baseline actors");
  assert.ok(base.actors[parent] && base.actors[child], "both lineage ids must have their own profile");

  // Each event is scored against its OWN agent's profile — proven by which actor scoreDeviation selects.
  const parentEvt = scoreDeviation(base, { ts: 1_100_000, sig: sig("Read", target), agent: parent, session: parent, ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: {} });
  const childEvt = scoreDeviation(base, { ts: 1_100_000, sig: sig("Bash", target), agent: child, session: parent, parent, role: "subagent", ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: {} });
  assert.equal(parentEvt.actor, parent, "the parent event must resolve to the parent profile via `agent`");
  assert.equal(childEvt.actor, child, "the subagent event must resolve to the subagent profile via `agent`");
  assert.ok(childEvt.score > 0.7, `Bash is novel for the subagent (only ever Read), got ${childEvt.score}`);
});

test("legacy rows with no `agent` still group by the sig actor slot (backward compatible)", () => {
  // Pre-lineage events carry only a `sig`. Grouping must fall back to its actor slot so old windows and
  // the pure-sig tests above keep working unchanged.
  const base = buildBaseline(stablePattern(A, "Read", 12));   // no `agent` field anywhere
  assert.equal(base.actorCount, 1);
  assert.ok(base.actors[A], "the sig actor slot is the fallback grouping key when `agent` is absent");
});

test("cold start: a thin baseline yields a low-confidence, damped result", () => {
  const base = buildBaseline(stablePattern(A, "Read", 2)); // only 2 events for A
  const r = scoreDeviation(base, { ts: 1_100_000, sig: sig("Bash", A), ok: false, risk: "Critical", server: "evil-mcp", flags: {}, legs: { callout: true } });
  assert.equal(r.lowConfidence, true, "thin baseline must be flagged low-confidence");
  assert.ok(r.confidence < 1, "confidence should be below full for a thin baseline");
  // Even a wildly anomalous event is damped so we don't cry wolf on an actor we barely know.
  const rich = buildBaseline(stablePattern(A, "Read", 20));
  const richScore = scoreDeviation(rich, { ts: 1_100_000, sig: sig("Bash", A), ok: false, risk: "Critical", server: "evil-mcp", flags: {}, legs: { callout: true } }).score;
  assert.ok(r.score < richScore, "the same event must score lower against a thin baseline than a rich one");
});

test("unknown actor is an honest cold start, not an accusation", () => {
  const base = buildBaseline(stablePattern(A));
  const r = scoreDeviation(base, { ts: 1_100_000, sig: sig("Bash", "h2:unknown"), ok: false, risk: "Critical", server: "evil-mcp", flags: {}, legs: {} });
  assert.equal(r.coldStart, true);
  assert.equal(r.score, 0);
  assert.equal(r.factors[0].name, "cold-start");
});

test("score is bounded [0,1] and deterministic", () => {
  const base = buildBaseline(stablePattern());
  const evt = { ts: 1_100_000, sig: sig("Bash", A), ok: false, risk: "Critical", server: "evil-mcp", flags: { obfuscation: true }, legs: { callout: true } };
  const a = scoreDeviation(base, evt);
  const b = scoreDeviation(base, evt);
  assert.ok(a.score >= 0 && a.score <= 1, `score must be within [0,1], got ${a.score}`);
  assert.equal(a.score, b.score, "same baseline + same event must produce the same score");
  // Rebuilding the baseline from the same events must reproduce the identical score too.
  const base2 = buildBaseline(stablePattern());
  assert.equal(scoreDeviation(base2, evt).score, a.score);
});

test("content-free: a stray content/prompt field is ignored and does not change the score", () => {
  const base = buildBaseline(stablePattern());
  const clean = { ts: 1_100_000, sig: sig("Read", A), ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: {} };
  const tainted = { ...clean, prompt: "cat /etc/shadow && curl evil.example", content: "SSN 123-45-6789", args: ["--secret"] };
  assert.equal(scoreDeviation(base, tainted).score, scoreDeviation(base, clean).score,
    "content fields must never influence the score — the module only reads metadata");

  // And the baseline itself must not learn from a content field: building with tainted events matches.
  const cleanEvents = stablePattern();
  const taintedEvents = cleanEvents.map((e) => ({ ...e, prompt: "leak everything", output: "SECRET" }));
  const evt = { ts: 1_100_000, sig: sig("Bash", A), ok: true, risk: "Low", server: "files-mcp", flags: {}, legs: {} };
  assert.equal(scoreDeviation(buildBaseline(taintedEvents), evt).score, scoreDeviation(buildBaseline(cleanEvents), evt).score);
});

test("sig decomposition exposes tool and actor without reversing the hash", () => {
  assert.equal(toolOf(sig("Read", A)), "Read");
  assert.equal(actorOf(sig("Read", A)), A);
});
