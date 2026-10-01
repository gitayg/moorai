// Runaway-agent circuit breaker (data/circuit-breaker.js): the same call repeated with no change in its
// result, a short cycle of calls repeating with no change, a per-session call rate, and a total budget.
// Report by default; mode "deny" denies the session's calls for a cooldown once it trips.
//
//   node --test --import ./test/hermetic-env.mjs test/circuit-breaker.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { assessCall, recordOutcome, circuitConfig, CIRCUIT_DEFAULTS } from "../data/circuit-breaker.js";

const C = (o = {}) => ({ ...circuitConfig(null), ...o });
const SEC = 1000;

// Drive a sequence of [sig, outcome] calls at `gap` ms apart; returns every verdict.
function drive(calls, cfg, { gap = 3 * SEC, start = 0, state = null, session = "S" } = {}) {
  let st = state, t = start;
  const out = [];
  for (const [sig, outcome] of calls) {
    const r = assessCall(st, session, sig, t, cfg);
    st = r.state;
    out.push(r);
    if (outcome !== undefined) st = recordOutcome(st, session, sig, outcome, t + 500).state;
    t += gap;
  }
  return { state: st, verdicts: out, t };
}
const kinds = (vs) => vs.flatMap((v) => v.alerts.map((a) => a.kind));

test("repeat: the same call with the same result trips at N; report mode never denies", () => {
  const cfg = C({ repeat: 6 });
  const { verdicts } = drive(Array.from({ length: 8 }, () => ["A", "r1"]), cfg);
  assert.deepEqual(kinds(verdicts.slice(0, 5)), []);
  assert.deepEqual(kinds(verdicts), ["repeat"], "one alert, on the 6th call");
  assert.equal(verdicts[5].alerts[0].alert.threatId, 38);
  assert.equal(verdicts[5].alerts[0].alert.signature.count, 6);
  assert.ok(verdicts.every((v) => v.deny === null));
});

test("repeat: a changing result is progress and resets the count (npm test while fixing)", () => {
  const cfg = C({ repeat: 6 });
  const calls = [];
  for (let i = 0; i < 12; i++) calls.push(["npm test", `fail-${i % 4}`], [`edit-${i}`, "ok"]);
  assert.deepEqual(kinds(drive(calls, cfg).verdicts), []);
});

test("repeat: failures count as no progress; outside the window they do not add up", () => {
  const cfg = C({ repeat: 4, repeatWindowSec: 60 });
  assert.deepEqual(kinds(drive(Array.from({ length: 4 }, () => ["A", "F"]), cfg).verdicts), ["repeat"]);
  assert.deepEqual(kinds(drive(Array.from({ length: 4 }, () => ["A", "F"]), cfg, { gap: 30 * SEC }).verdicts), [], "4 calls over 90 s");
});

test("cycle: an alternating pair with unchanged results trips; the same pair with changing results does not", () => {
  const cfg = C({ cycleK: 4 });
  const stuck = [];
  for (let i = 0; i < 5; i++) stuck.push(["edit-x-to-y", "ok"], ["edit-y-to-x", "ok"]);
  const v = drive(stuck, cfg).verdicts;
  assert.deepEqual(kinds(v), ["cycle"]);
  assert.equal(v.findIndex((x) => x.alerts.length), 7, "trips when the 4th repetition completes");
  assert.equal(v[7].alerts[0].alert.signature.period, 2);
  const moving = [];
  for (let i = 0; i < 6; i++) moving.push(["npm test", `out-${i}`], ["cat log", `log-${i}`]);
  assert.deepEqual(kinds(drive(moving, cfg).verdicts), []);
  const three = [];
  for (let i = 0; i < 4; i++) three.push(["a", "F"], ["b", "F"], ["c", "F"]);
  assert.deepEqual(kinds(drive(three, cfg).verdicts), ["cycle"], "period 3");
});

test("rate and budget", () => {
  const r = drive(Array.from({ length: 12 }, (_, i) => [`c${i}`]), C({ ratePerMin: 10 }), { gap: 2 * SEC }).verdicts;
  assert.deepEqual(kinds(r), ["rate"]);
  assert.equal(r.findIndex((x) => x.alerts.length), 9);
  const b = drive(Array.from({ length: 6 }, (_, i) => [`c${i}`]), C({ maxCalls: 5 }), { gap: 60 * SEC }).verdicts;
  assert.deepEqual(kinds(b), ["budget"]);
  assert.equal(b.findIndex((x) => x.alerts.length), 4, "the 5th call reaches the budget");
});

test("deny mode: the tripping call and every call after it in the session is denied until the cooldown ends", () => {
  const cfg = C({ mode: "deny", repeat: 3, cooldownMin: 10 });
  const d = drive(Array.from({ length: 3 }, () => ["A", "same"]), cfg);
  assert.equal(d.verdicts[2].deny?.kind, "repeat");
  assert.match(d.verdicts[2].deny.reason, /circuit breaker/);
  let r = assessCall(d.state, "S", "something-else", d.t + 60 * SEC, cfg);
  assert.equal(r.deny?.kind, "repeat", "paused: any call in the session");
  assert.deepEqual(r.alerts, [], "no second alert while paused");
  const other = assessCall(r.state, "S2", "A", d.t + 60 * SEC, cfg);
  assert.equal(other.deny, null, "another session is not paused");
  r = assessCall(r.state, "S", "A", d.t + 11 * 60 * SEC, cfg);
  assert.equal(r.deny, null, "the cooldown ended and the history was cleared");
});

test("deny mode with cooldownMin 0 pauses for the rest of the session", () => {
  const cfg = C({ mode: "deny", repeat: 2, cooldownMin: 0 });
  const d = drive([["A", "x"], ["A", "x"]], cfg);
  assert.ok(d.verdicts[1].deny);
  assert.ok(assessCall(d.state, "S", "B", d.t + 12 * 3600 * SEC, cfg).deny, "12 h later, still paused (state is kept 24 h after the last call)");
});

test("config defaults; mode off; malformed state; LRU; content-free", () => {
  assert.equal(CIRCUIT_DEFAULTS.mode, "report");
  assert.deepEqual([CIRCUIT_DEFAULTS.ratePerMin, CIRCUIT_DEFAULTS.maxCalls], [0, 0], "rate and budget are opt-in");
  assert.deepEqual(kinds(drive(Array.from({ length: 400 }, (_, i) => [`c${i}`]), C(), { gap: 100 }).verdicts), [], "off by default: 400 distinct calls in 40 s");
  assert.equal(circuitConfig({ circuitBreaker: { mode: "deny" } }).mode, "deny");
  assert.equal(circuitConfig({ circuitBreaker: { mode: "nonsense", repeat: -3 } }).repeat, CIRCUIT_DEFAULTS.repeat);
  assert.equal(circuitConfig({ circuitBreaker: { cooldownMin: 0 } }).cooldownMin, 0);
  const off = drive(Array.from({ length: 30 }, () => ["A", "x"]), C({ mode: "off" })).verdicts;
  assert.deepEqual(kinds(off), []);
  for (const bad of [null, 7, [], { sessions: [] }, { sessions: { S: { ring: "x" } } }]) assert.deepEqual(assessCall(bad, "S", "A", 1, C()).alerts, []);
  let st = null;
  for (let i = 0; i < 40; i++) st = assessCall(st, `S${i}`, "A", i, C({ maxSessions: 4 })).state;
  assert.equal(Object.keys(st.sessions).length, 4);
  assert.deepEqual(recordOutcome(st, "nope", "A", "x", 1).dirty, false);
});

// Codex, Copilot, Gemini and Cursor forward no command results to the hook, so every call's result is
// unknown. Without results nothing shows the calls are unchanged: a command re-run while its output
// changes must not trip the repeat or cycle rules on those hosts.
test("no results recorded (adapter hosts): repeated and cycling calls never trip", () => {
  let st = null; const t0 = 1_700_000_000_000;
  for (let i = 0; i < 40; i++) {
    const r = assessCall(st, "adapter-session", "sig-npm-test", t0 + i * 2000);
    st = r.state;
    assert.equal(r.trip, "", `repeat tripped at call ${i + 1} with no results recorded`);
  }
  st = null;
  for (let i = 0; i < 40; i++) {
    const r = assessCall(st, "adapter-cycle", i % 2 ? "sig-a" : "sig-b", t0 + i * 2000);
    st = r.state;
    assert.equal(r.trip, "", `cycle tripped at call ${i + 1} with no results recorded`);
  }
});
