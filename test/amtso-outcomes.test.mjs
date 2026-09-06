// Falsify-first tests for the AMTSO outcome model in scripts/redteam-eval.mjs.
//
// WHY: the eval's headline recall is a DETECTION number. AMTSO's "Guidelines for Testing of Agentic
// Security Products" v1.0 says presenting a detection number as protection is a reporting error, and
// defines a six-state outcome vocabulary in which "prevented", "detected but not prevented" and
// "inconclusive" are separate claims. These tests pin:
//   1. that prevention is derived from threatActionFor — the SAME function the shipped PreToolUse hook
//      enforces with (cli/hook-core.mjs decideText) — and not from anything invented here;
//   2. that INCONCLUSIVE is genuinely reachable (a throwing scan, a blown time budget, a throwing
//      escalation) and is NOT silently scored as a miss;
//   3. that the additive fields did not disturb the legacy return shape or the legacy arithmetic that
//      score-heldout-v2 / score-benign-v2 / score-vectors / semantic-coverage all read.
//
//   node --test test/amtso-outcomes.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  evalSample, score, policyActionFor, amtsoOutcomeFor, resolvePolicy, AMTSO_OUTCOMES
} from "../scripts/redteam-eval.mjs";
import { threatActionFor } from "../cli/hook-core.mjs";

const finding = (id) => ({ threat: { id, riskLevel: "High", riskScore: 50 } });
const hit = (...ids) => () => ids.map(finding);
const miss = () => () => [];
const DUMMY = {};
const attack = (over = {}) => ({ id: "a1", family: "DAN", category: "jailbreak", shouldDetect: true, text: "x", ...over });

// ---------------------------------------------------------------------------------------------
// 1. Prevention is derived from the policy action, not from the fact that something fired.
// ---------------------------------------------------------------------------------------------

test("block → PREVENTED (hard deny): the tool call never runs", async () => {
  const r = await evalSample(DUMMY, attack(), hit(3), { policy: { threatPolicy: { 3: "block" } } });
  assert.equal(r.action, "block");
  assert.equal(r.amtso, AMTSO_OUTCOMES.PREVENTED);
  assert.equal(r.prevented, true);
  assert.equal(r.preventedHard, true);
});

test("justify → PREVENTED but NOT hard: halted pending human sign-off (hook returns ask)", async () => {
  const r = await evalSample(DUMMY, attack(), hit(3), { policy: { threatPolicy: { 3: "justify" } } });
  assert.equal(r.action, "justify");
  assert.equal(r.amtso, AMTSO_OUTCOMES.PREVENTED);
  assert.equal(r.prevented, true);
  assert.equal(r.preventedHard, false, "justify is a stop, not a hard deny — reported separately");
});

test("notify → DETECTED-BUT-NOT-PREVENTED: flagged, but the action still completes", async () => {
  const r = await evalSample(DUMMY, attack(), hit(3), { policy: { threatPolicy: { 3: "notify" } } });
  assert.equal(r.action, "notify");
  assert.equal(r.amtso, AMTSO_OUTCOMES.DETECTED_NOT_PREVENTED);
  assert.equal(r.prevented, false);
  assert.equal(r.detected, true, "still a detection — it is only the PREVENTION claim that fails");
});

test("nothing fired → MISSED, and no prevention claim is made", async () => {
  const r = await evalSample(DUMMY, attack(), miss(), { policy: { threatPolicy: { 3: "block" } } });
  assert.equal(r.amtso, AMTSO_OUTCOMES.MISSED);
  assert.equal(r.action, null);
  assert.equal(r.prevented, false);
});

test("the derivation uses the REAL threatActionFor, so it tracks hook-core's own defaults", async () => {
  // #43 (destructive commands) is in APPROVAL_THREATS → threatActionFor defaults it to "justify".
  // #3 (prompt injection) is in no tier and no approval set → "notify". Assert against the real
  // function so this test breaks if hook-core's defaults move and the eval silently disagrees.
  assert.equal(threatActionFor(null, 43), "justify");
  assert.equal(threatActionFor(null, 3), "notify");
  const destructive = await evalSample(DUMMY, attack(), hit(43));   // no policy → built-in defaults
  const injection = await evalSample(DUMMY, attack(), hit(3));
  assert.equal(destructive.amtso, AMTSO_OUTCOMES.PREVENTED);
  assert.equal(injection.amtso, AMTSO_OUTCOMES.DETECTED_NOT_PREVENTED);
});

test("policyActionFor takes the STRONGEST action across every fired threat", () => {
  const policy = { threatPolicy: { 3: "notify", 15: "justify", 39: "block" } };
  assert.equal(policyActionFor([3], policy), "notify");
  assert.equal(policyActionFor([3, 15], policy), "justify");
  assert.equal(policyActionFor([3, 15, 39], policy), "block");
  assert.equal(policyActionFor([], policy), null);
  assert.equal(policyActionFor([3], { threatPolicy: { 3: "disabled" } }), null, "a disabled threat contributes nothing");
});

test("resolvePolicy maps the shipped postures without inventing one", () => {
  assert.equal(resolvePolicy("builtin").policy, null);
  assert.equal(resolvePolicy("builtin").label, "builtin-default");
  const off = resolvePolicy("offline");
  assert.equal(off.policy.threatPolicy[39], "block", "data/offline-default.js hard-blocks secrets");
  assert.equal(off.label, "offline-fail-closed");
});

// ---------------------------------------------------------------------------------------------
// 2. INCONCLUSIVE is reachable, and is not a miss.
// ---------------------------------------------------------------------------------------------

test("a scan that THROWS is INCONCLUSIVE, not a miss", async () => {
  const boom = () => { throw new Error("engine exploded"); };
  const r = await evalSample(DUMMY, attack(), boom);
  assert.equal(r.amtso, AMTSO_OUTCOMES.INCONCLUSIVE);
  assert.notEqual(r.amtso, AMTSO_OUTCOMES.MISSED, "'we could not tell' is a different claim from 'it got through'");
  assert.equal(r.error.phase, "scan");
  assert.match(r.error.reason, /engine exploded/);
  assert.equal(r.detected, false);
  assert.equal(r.outcome, "FN", "legacy outcome stays conservative so existing arithmetic is unchanged");
});

test("a scan that HANGS past --timeout-ms is INCONCLUSIVE (environmental failure)", async () => {
  const hang = () => new Promise(() => {});   // never settles
  const r = await evalSample(DUMMY, attack(), hang, { timeoutMs: 25 });
  assert.equal(r.amtso, AMTSO_OUTCOMES.INCONCLUSIVE);
  assert.equal(r.error.phase, "scan");
  assert.match(r.error.reason, /budget/);
});

test("a semantic escalation that THROWS is INCONCLUSIVE, attributed to the escalate phase", async () => {
  const r = await evalSample(DUMMY, attack(), miss(), {
    escalate: async () => { throw new Error("model backend unreachable") }
  });
  assert.equal(r.amtso, AMTSO_OUTCOMES.INCONCLUSIVE);
  assert.equal(r.error.phase, "escalate");
});

test("a benign row that errors is INCONCLUSIVE too; a clean benign row has no AMTSO outcome", async () => {
  const benign = { id: "b1", family: "benign", shouldDetect: false, text: "x" };
  const clean = await evalSample(DUMMY, benign, miss());
  assert.equal(clean.amtso, null, "the vocabulary describes malicious attempts; a benign row's failure mode is an FP");
  assert.equal(clean.outcome, "TN");
  const errored = await evalSample(DUMMY, benign, () => { throw new Error("nope"); });
  assert.equal(errored.amtso, AMTSO_OUTCOMES.INCONCLUSIVE);
});

test("no timeout budget → no timer is armed and an async scan passes straight through", async () => {
  const slowish = async () => { await new Promise((r) => setTimeout(r, 5)); return [finding(3)]; };
  const r = await evalSample(DUMMY, attack(), slowish);   // timeoutMs omitted
  assert.equal(r.detected, true);
  assert.equal(r.error, null);
  assert.equal(r.amtso, AMTSO_OUTCOMES.DETECTED_NOT_PREVENTED);
});

test("amtsoOutcomeFor: error outranks every other signal", () => {
  assert.equal(amtsoOutcomeFor({ shouldDetect: true, detected: true, action: "block", error: { phase: "scan" } }),
    AMTSO_OUTCOMES.INCONCLUSIVE, "contradictory/unusable evidence cannot be reported as prevention");
});

// ---------------------------------------------------------------------------------------------
// 3. score(): the split, the denominator, and backward compatibility.
// ---------------------------------------------------------------------------------------------

const row = (over) => ({
  id: "r", family: "DAN", shouldDetect: true, detected: true, correctThreat: true,
  firedThreats: [3], outcome: "TP", recovered: false, action: "notify",
  prevented: false, preventedHard: false, error: null, amtso: AMTSO_OUTCOMES.DETECTED_NOT_PREVENTED, ...over
});

test("score(): the three-way split is reported overall AND per family", () => {
  const rows = [
    row({ id: "p1", family: "DAN", action: "block", prevented: true, preventedHard: true, amtso: AMTSO_OUTCOMES.PREVENTED }),
    row({ id: "d1", family: "DAN" }),
    row({ id: "m1", family: "TAP", detected: false, correctThreat: false, firedThreats: [], outcome: "FN", action: null, amtso: AMTSO_OUTCOMES.MISSED }),
    row({ id: "i1", family: "TAP", detected: false, correctThreat: false, firedThreats: [], outcome: "FN", action: null, error: { phase: "scan", reason: "x" }, amtso: AMTSO_OUTCOMES.INCONCLUSIVE })
  ];
  const sc = score(rows);
  assert.equal(sc.amtso.prevented, 1);
  assert.equal(sc.amtso.detectedNotPrevented, 1);
  assert.equal(sc.amtso.missed, 1);
  assert.equal(sc.amtso.inconclusive, 1);
  assert.equal(sc.amtso.preventedHard, 1);

  const dan = sc.families.find((f) => f.family === "DAN");
  assert.equal(dan.prevented, 1);
  assert.equal(dan.detectedNotPrevented, 1);
  const tap = sc.families.find((f) => f.family === "TAP");
  assert.equal(tap.missed, 1);
  assert.equal(tap.inconclusive, 1);
});

test("score(): inconclusive rows leave the AMTSO DENOMINATOR but stay in legacy coverage", () => {
  const rows = [
    row({ id: "p1", action: "block", prevented: true, preventedHard: true, amtso: AMTSO_OUTCOMES.PREVENTED }),
    row({ id: "d1" }),
    row({ id: "m1", detected: false, correctThreat: false, firedThreats: [], outcome: "FN", action: null, amtso: AMTSO_OUTCOMES.MISSED }),
    row({ id: "i1", detected: false, correctThreat: false, firedThreats: [], outcome: "FN", action: null, error: { phase: "scan", reason: "x" }, amtso: AMTSO_OUTCOMES.INCONCLUSIVE })
  ];
  const sc = score(rows);
  assert.equal(sc.amtso.attacks, 4);
  assert.equal(sc.amtso.conclusiveAttacks, 3, "the inconclusive attack leaves the denominator");
  assert.ok(Math.abs(sc.amtso.preventionRate - 1 / 3) < 1e-9);
  assert.ok(Math.abs(sc.amtso.detectionRate - 2 / 3) < 1e-9);
  assert.ok(Math.abs(sc.amtso.missRate - 1 / 3) < 1e-9);
  // Legacy coverage is UNCHANGED — 2 detected of 4 attacks, inconclusive still counted against us.
  assert.ok(Math.abs(sc.coverage - 2 / 4) < 1e-9, "legacy coverage must not move");
  assert.ok(Math.abs(sc.coverageExclInconclusive - 2 / 3) < 1e-9);
  assert.equal(sc.amtso.modelRefusal, 0);
  assert.equal(sc.amtso.modelRecognition, 0);
});

test("score(): legacy rows that predate the outcome model still get a derived split", () => {
  // Exactly the hand-built shape test/redteam-eval.test.mjs passes in — no amtso/action/error fields.
  const legacy = [
    { id: "a", family: "DAN", shouldDetect: true, detected: true, correctThreat: true, firedThreats: [2], outcome: "TP" },
    { id: "b", family: "DAN", shouldDetect: true, detected: false, correctThreat: false, firedThreats: [], outcome: "FN" },
    { id: "f", family: "DAN", shouldDetect: false, detected: true, correctThreat: false, firedThreats: [3], outcome: "FP" }
  ];
  const sc = score(legacy);
  assert.ok(Math.abs(sc.coverage - 1 / 2) < 1e-9, "legacy arithmetic identical");
  assert.ok(Math.abs(sc.precision - 1 / 2) < 1e-9);
  assert.equal(sc.amtso.detectedNotPrevented, 1, "no action recorded → cannot claim prevention");
  assert.equal(sc.amtso.missed, 1);
  assert.equal(sc.amtso.prevented, 0);
  assert.equal(sc.amtso.inconclusive, 0);
});

test("backward compat: evalSample's legacy fields are all still present and unchanged in meaning", async () => {
  const r = await evalSample(DUMMY, attack({ expectThreat: 3 }), hit(3));
  for (const k of ["id", "family", "category", "shouldDetect", "detected", "correctThreat", "firedThreats", "recovered", "outcome"]) {
    assert.ok(k in r, `legacy field ${k} must survive`);
  }
  assert.equal(r.outcome, "TP");
  assert.equal(r.correctThreat, true);
  assert.deepEqual(r.firedThreats, [3]);
  assert.equal(r.recovered, false);
});
