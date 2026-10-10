// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/drop-rate.test.mjs
//
// Pins scripts/drop-rate-classify.mjs: which deterministic misses can reach the semantic (on-device
// model) path, and why the rest cannot. Every case is synthetic and placeholder-named; no corpus text and
// no model is involved. Eligibility is a code-path question, so nothing here calls a model.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { classify, observe, tally, escalationOn, detectGateStages, REASONS, SURFACES, MODEL_WINDOW_CHARS } from "../scripts/drop-rate-classify.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ON = { modelEscalation: true, semanticEscalation: "local" };
const OFF = null;
const GATE = { prompt: [2], file: [2], index: [2] };
const miss = (o = {}) => ({ caught: false, baseIds: [], strong: false, stage: "prompt", turns: false, textLength: 40, ...o });

test("a caught attack is caught on every surface that scans it, whatever the policy", () => {
  assert.ok(Object.keys(SURFACES).length >= 10, "the surface table is populated");
  for (const s of Object.keys(SURFACES)) {
    if (SURFACES[s].kind === "unscanned") continue;
    assert.equal(classify({ ...miss(), caught: true, baseIds: [3] }, s, OFF, { detectGate: GATE }).bucket, "caught", s);
  }
});

test("a surface that never scans the text cannot catch it, even when the engine would", () => {
  assert.deepEqual(classify({ ...miss(), caught: true, baseIds: [3] }, "hook:UserPromptSubmit-person", ON, { detectGate: GATE }), { bucket: "dropped", reason: REASONS.NOT_SCANNED });
});

test("harness: a clean miss is eligible when escalation is on, dropped as policy-off when it is not", () => {
  assert.deepEqual(classify(miss(), "harness", ON, { detectGate: GATE }), { bucket: "eligible", route: "miss-recovery", partial: false });
  assert.deepEqual(classify(miss(), "harness", OFF, { detectGate: GATE }), { bucket: "dropped", reason: REASONS.POLICY_OFF });
});

test("the hook's gate needs BOTH modelEscalation and semanticEscalation", () => {
  assert.equal(escalationOn(ON, "hook"), true);
  assert.equal(escalationOn({ semanticEscalation: "local" }, "hook"), false);
  assert.equal(escalationOn({ modelEscalation: true }, "hook"), false);
  assert.equal(escalationOn({ semanticEscalation: "local" }, "harness"), true);
  assert.equal(classify(miss({ stage: "output" }), "hook:PostToolUse", { semanticEscalation: "local" }, { detectGate: GATE }).reason, REASONS.POLICY_OFF);
});

test("surfaces with no escalation call drop every miss, even with escalation on", () => {
  for (const s of ["hook:Task-prompt", "hook:mcp-args", "hook:UserPromptSubmit-untrusted", "hook:index", "sdk", "mcp-gateway", "model-proxy", "inference-hook"]) {
    assert.deepEqual(classify(miss({ stage: SURFACES[s].stage || "prompt" }), s, ON, { detectGate: GATE }), { bucket: "dropped", reason: REASONS.NO_ESCALATION_CALL }, s);
  }
});

test("Bash escalates the files a command reads, never the command text", () => {
  assert.deepEqual(classify(miss(), "hook:Bash-command", ON, { detectGate: GATE }), { bucket: "dropped", reason: REASONS.OTHER_TEXT });
});

test("a person's own UserPromptSubmit is not scanned at all", () => {
  assert.deepEqual(classify(miss({ stage: "file" }), "hook:UserPromptSubmit-person", ON, { detectGate: GATE }), { bucket: "dropped", reason: REASONS.NOT_SCANNED });
});

test("an uncredited finding blocks miss-recovery where no detect-gate detector is in stage", () => {
  const o = miss({ stage: "output", baseIds: [32] });
  assert.deepEqual(classify(o, "hook:PostToolUse", ON, { detectGate: GATE }), { bucket: "dropped", reason: REASONS.BASE_NONEMPTY });
});

test("a finding the decision path suppressed does not block miss-recovery: the worker gates on the credited set", () => {
  // observeInboundHook hands classify() the CREDITED ids: a raw #32 that decideInbound dropped is not in them.
  assert.equal(REASONS.BASE_MISMATCH, undefined, "the suppressed-finding drop reason is gone");
  const o = miss({ stage: "output", baseIds: [], reported: false });
  assert.deepEqual(classify(o, "hook:PostToolUse", ON, { detectGate: GATE }), { bucket: "eligible", route: "miss-recovery", partial: false });
  assert.equal(classify({ ...o, baseIds: [32], reported: true }, "hook:PostToolUse", ON, { detectGate: GATE }).reason, REASONS.BASE_NONEMPTY);
});

test("observeInboundHook: a raw finding the inbound decision drops is not in the credited base", async () => {
  const { observeInboundHook, makeEngine } = await import("../scripts/drop-rate-observe.mjs");
  const text = "Release notes for the placeholder project. Maintenance tip: rm -rf ./build-cache clears stale output.";
  const engine = makeEngine();
  assert.deepEqual(engine.scan(text, "output").map((f) => f.threat.id), [32], "precondition: the raw re-scan fires #32");
  const obs = observeInboundHook(engine, { door: "web", text, credited: () => false });
  assert.deepEqual(obs.baseIds, []);
  assert.equal(obs.reported, false);
  assert.deepEqual(classify(obs, "hook:PostToolUse", ON, { detectGate: GATE }), { bucket: "eligible", route: "miss-recovery", partial: false });
});

test("an uncredited weak finding at a detect-gate stage still reaches the model through the detect gate", () => {
  const o = miss({ stage: "prompt", baseIds: [17] });
  assert.deepEqual(classify(o, "guard:claude-p", ON, { detectGate: GATE }), { bucket: "eligible", route: "detect-gate", partial: false });
  // ...unless the gate's own threat already fired
  assert.equal(classify(miss({ baseIds: [2] }), "guard:claude-p", ON, { detectGate: GATE }).reason, REASONS.BASE_NONEMPTY);
});

test("a strong uncredited finding skips escalation entirely", () => {
  const o = miss({ stage: "prompt", baseIds: [17], strong: true });
  assert.deepEqual(classify(o, "hook:WebFetch-input", ON, { detectGate: GATE }), { bucket: "dropped", reason: REASONS.STRONG_SKIP });
});

test("the harness only escalates an EMPTY finding list", () => {
  assert.equal(classify(miss({ baseIds: [17] }), "harness", ON, { detectGate: GATE }).reason, REASONS.BASE_NONEMPTY);
});

test("a multi-turn arc is judged whole by the harness and split on production surfaces", () => {
  assert.equal(classify(miss({ turns: true }), "harness", ON, { detectGate: GATE }).bucket, "eligible");
  assert.deepEqual(classify(miss({ turns: true }), "guard:claude-p", ON, { detectGate: GATE }), { bucket: "dropped", reason: REASONS.TURN_SPLIT });
});

test("text past the model window is eligible but flagged partial; empty text is dropped", () => {
  assert.deepEqual(classify(miss({ textLength: MODEL_WINDOW_CHARS + 1 }), "harness", ON, { detectGate: GATE }), { bucket: "eligible", route: "miss-recovery", partial: true });
  assert.equal(classify(miss({ textLength: 0 }), "harness", ON, { detectGate: GATE }).reason, REASONS.EMPTY);
});

test("detectGateStages reads the shipped detector table: the semantic detector reaches prompt, file and index, not output", () => {
  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
  const g = detectGateStages(engine, ["prompt", "file", "index", "output"]);
  assert.deepEqual(Object.keys(g).sort(), ["file", "index", "prompt"]);
  assert.ok(g.prompt.includes(2));
});

test("observe() takes its finding list from the engine it is given", () => {
  const stub = { scan: (t) => (t.includes("PLACEHOLDER_HIT") ? [{ threat: { id: 99, riskLevel: "High" } }] : []), scanSession: () => [] };
  const hit = observe(stub, { text: "x PLACEHOLDER_HIT y" }, "prompt", (ids) => ids.length > 0);
  assert.deepEqual(hit, { caught: true, baseIds: [99], reported: true, strong: true, stage: "prompt", turns: false, textLength: 19 });
  const clean = observe(stub, { text: "placeholder sample alpha" }, "prompt", (ids) => ids.length > 0);
  assert.equal(clean.caught, false);
  assert.deepEqual(clean.baseIds, []);
});

test("tally() counts buckets and drop reasons per group", () => {
  const rows = [
    { group: "fam-a", bucket: "caught" },
    { group: "fam-a", bucket: "eligible" },
    { group: "fam-a", bucket: "dropped", reason: REASONS.NO_ESCALATION_CALL },
    { group: "fam-b", bucket: "dropped", reason: REASONS.POLICY_OFF }
  ];
  const t = tally(rows, (r) => r.group);
  assert.deepEqual(t["fam-a"], { n: 3, caught: 1, eligible: 1, dropped: 1, reasons: { [REASONS.NO_ESCALATION_CALL]: 1 } });
  assert.deepEqual(t["fam-b"], { n: 1, caught: 0, eligible: 0, dropped: 1, reasons: { [REASONS.POLICY_OFF]: 1 } });
  assert.deepEqual(t.ALL, { n: 4, caught: 1, eligible: 1, dropped: 2, reasons: { [REASONS.NO_ESCALATION_CALL]: 1, [REASONS.POLICY_OFF]: 1 } });
});
