// Integrity + plumbing tests for the two AMTSO vector corpora and their scorer.
//
//   node --test test/vector-corpora.test.mjs
//   (per-file runner only — never `node --test` across the whole suite; it hangs)
//
// WHAT THIS DOES NOT DO: it does NOT pin a recall or precision number. Detectors are edited by other
// work in this repo, and a corpus test that asserts "recall >= X" turns every detector change into a
// spurious failure while proving nothing about the corpus. What is asserted here is that the corpus is
// well formed, that its payloads are the thing they claim to be (the invisible-character samples really
// do carry invisible characters), that it contains no forbidden credential shapes, and that the scorer
// routes each harness to the entry point that can actually see it. The measured numbers live in
// scripts/score-vectors.mjs output, which is a snapshot, not an invariant.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { runAgentDetections } from "../data/agent-baseline.js";
import { evalVectorSample, scoreVector, VECTOR_FILES, STAGE_REACHABILITY } from "../scripts/score-vectors.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const load = (p) => JSON.parse(readFileSync(join(ROOT, p), "utf8"));
const V3 = load(VECTOR_FILES[3]);
const V5 = load(VECTOR_FILES[5]);
const all = (c) => [...(c.attacks || []), ...(c.benign || [])];

const VALID_STAGES = new Set(["prompt", "file", "index", "output", "tool"]);
const VALID_HARNESSES = new Set(["text", "steps", "events", "session"]);

function textsOf(s) {
  const out = [];
  if (typeof s.text === "string") out.push(s.text);
  for (const st of s.steps || []) if (typeof st.text === "string") out.push(st.text);
  for (const t of s.turns || []) if (typeof t === "string") out.push(t);
  return out;
}

// ---------------------------------------------------------------- corpus shape ----

test("both corpora meet the sample-count targets and declare their vector", () => {
  assert.equal(V3.vector, 3);
  assert.equal(V5.vector, 5);
  assert.ok(V3.attacks.length >= 60, `vector 3 needs >= 60 attacks, has ${V3.attacks.length}`);
  assert.ok(V3.benign.length >= 25, `vector 3 needs >= 25 benign, has ${V3.benign.length}`);
  assert.ok(V5.attacks.length >= 40, `vector 5 needs >= 40 attacks, has ${V5.attacks.length}`);
  assert.ok(V5.benign.length >= 25, `vector 5 needs >= 25 benign, has ${V5.benign.length}`);
});

test("every sample id is unique across both corpora", () => {
  const seen = new Set();
  for (const s of [...all(V3), ...all(V5)]) {
    assert.ok(s.id, "every sample needs an id");
    assert.ok(!seen.has(s.id), `duplicate sample id ${s.id}`);
    seen.add(s.id);
  }
});

test("every sample declares a known harness, a known stage, and carries scannable content", () => {
  for (const s of [...all(V3), ...all(V5)]) {
    const harness = s.harness || "text";
    assert.ok(VALID_HARNESSES.has(harness), `${s.id}: unknown harness ${harness}`);
    if (harness === "events") {
      assert.ok(Array.isArray(s.events) && s.events.length, `${s.id}: events harness needs events[]`);
      for (const e of s.events) assert.equal(typeof e.sig, "string", `${s.id}: every event row needs a sig`);
    } else if (harness === "session") {
      assert.ok(Array.isArray(s.turns) && s.turns.length >= 2, `${s.id}: session harness needs >= 2 turns`);
    } else if (harness === "steps") {
      assert.ok(Array.isArray(s.steps) && s.steps.length >= 2, `${s.id}: steps harness needs >= 2 steps`);
      for (const st of s.steps) {
        assert.ok(VALID_STAGES.has(st.stage), `${s.id}: step stage ${st.stage} is not a real engine stage`);
        assert.ok(st.text && st.text.trim(), `${s.id}: every step needs text`);
      }
      if (s.consumeStep != null) {
        assert.ok(Number.isInteger(s.consumeStep) && s.consumeStep >= 1 && s.consumeStep <= s.steps.length,
          `${s.id}: consumeStep ${s.consumeStep} is out of range for ${s.steps.length} steps`);
      }
    } else {
      assert.ok(VALID_STAGES.has(s.stage), `${s.id}: stage ${s.stage} is not a real engine stage`);
      assert.ok(s.text && s.text.trim(), `${s.id}: text harness needs text`);
    }
  }
});

test("every ATTACK sample carries the AMTSO labels and a validity justification", () => {
  for (const s of [...V3.attacks, ...V5.attacks]) {
    assert.ok(s.subTechnique, `${s.id}: missing subTechnique`);
    assert.ok(typeof s.validity === "string" && s.validity.length > 30,
      `${s.id}: missing a validity justification (AMTSO requires the malicious outcome to be reachable with the product absent)`);
    assert.ok(s.amtso && s.amtso.targetOfProtection && s.amtso.harm && s.amtso.requiredCapability,
      `${s.id}: missing AMTSO dimensions (targetOfProtection / harm / requiredCapability)`);
  }
});

test("every attack sub-technique the corpus advertises is actually populated", () => {
  for (const c of [V3, V5]) {
    const present = new Set(c.attacks.map((s) => s.subTechnique));
    for (const st of c.subTechniques) assert.ok(present.has(st), `vector ${c.vector}: declared sub-technique "${st}" has no samples`);
  }
});

// ------------------------------------------------------- payload authenticity ----

// Regression guard for a real defect this corpus shipped with once: the invisible-character payloads
// were authored double-escaped, so JSON.parse produced the literal seven characters  instead of a
// zero-width space. A visible "" is not a smuggling channel, which made every one of those
// samples invalid under the corpus's own validity gate.
test("payloads are decoded characters, not literal escape sequences", () => {
  for (const s of [...all(V3), ...all(V5)]) {
    for (const t of textsOf(s)) {
      assert.ok(!/\\u[0-9a-fA-F]{4}/.test(t), `${s.id}: contains a literal \\uXXXX escape instead of the character it denotes`);
      assert.ok(!/\\n/.test(t), `${s.id}: contains a literal \\n instead of a newline`);
    }
  }
});

test("the hidden-canary sub-technique really carries invisible characters", () => {
  const INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]|[\u{E0000}-\u{E007F}]|[\u{E0100}-\u{E01EF}]|\x1b/u;
  const canaries = V3.attacks.filter((s) => s.subTechnique === "hidden-canary-in-metadata");
  assert.ok(canaries.length >= 6, "expected a real hidden-canary slice");
  // At least the unicode/ANSI members must carry a genuinely invisible payload; the comment-smuggled
  // member deliberately does not (it hides in syntax, not in codepoints).
  const withInvisible = canaries.filter((s) => textsOf(s).some((t) => INVISIBLE.test(t)));
  assert.ok(withInvisible.length >= 5, `only ${withInvisible.length} canary samples carry invisible codepoints`);
});

test("no corpus sample contains a live-shaped provider credential", () => {
  // Documentation example values only. A Stripe sk_live_ shape in particular is blocked by GitHub push
  // protection and has cost this repo a blocked push before.
  const FORBIDDEN = [
    /sk_live_[0-9A-Za-z]{10,}/,
    /\bAKIA(?!IOSFODNN7EXAMPLE)[0-9A-Z]{16}\b/,
    /\bghp_(?!ABCDEF)[0-9A-Za-z]{36}\b/,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /\bxox[baprs]-[0-9A-Za-z-]{10,}/
  ];
  for (const s of [...all(V3), ...all(V5)]) {
    for (const t of textsOf(s)) {
      for (const re of FORBIDDEN) assert.ok(!re.test(t), `${s.id}: contains a forbidden credential shape (${re})`);
    }
  }
});

// ------------------------------------------------------------- scorer plumbing ----

const threats = load("data/threats.json");
const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);

test("events samples are scored through runAgentDetections, not the text engine", async () => {
  const sample = V5.attacks.find((s) => s.harness === "events" && (s.expectDetections || []).includes("orphans"));
  assert.ok(sample, "corpus must contain an orphan-agent events sample");
  // The text engine cannot see an event graph at all: there is no text to scan.
  assert.equal(engine.scan(JSON.stringify(sample.events), "prompt").length >= 0, true);
  const det = runAgentDetections(sample.events);
  assert.ok(det.orphans.length > 0, "runAgentDetections must see the orphan the text engine cannot");
  const row = await evalVectorSample(engine, { ...sample, shouldDetect: true }, null);
  assert.equal(row.harness, "events");
  assert.ok(row.firedDetections.includes("orphans"));
  assert.equal(row.outcome, "TP");
});

test("every attack events sample fires at least one of the buckets it names", () => {
  for (const s of V5.attacks.filter((x) => x.harness === "events")) {
    const det = runAgentDetections(s.events);
    const want = s.expectDetections || [];
    assert.ok(want.length, `${s.id}: an events attack must name expectDetections`);
    assert.ok(want.some((k) => det[k] && det[k].length > 0),
      `${s.id}: none of [${want.join(",")}] fired (got [${Object.keys(det).filter((k) => det[k].length).join(",")}])`);
  }
});

test("every BENIGN events sample is silent across all six detections", () => {
  for (const s of V5.benign.filter((x) => x.harness === "events")) {
    const det = runAgentDetections(s.events);
    const fired = Object.keys(det).filter((k) => det[k].length > 0);
    assert.deepEqual(fired, [], `${s.id}: benign trace produced ${fired.join(",")}`);
  }
});

test("steps samples are scanned at each step's own declared stage", async () => {
  // A payload whose only detectable form is at the consume step must be scored on the consume step,
  // not on the write step — that distinction is the whole point of the steps harness.
  const stub = {
    seen: [],
    scan(text, stage) { this.seen.push(stage); return stage === "output" ? [{ threat: { id: 40, riskLevel: "High", riskScore: 1 } }] : []; },
    scanSession() { return []; }
  };
  const row = await evalVectorSample(stub, {
    id: "synthetic", shouldDetect: true, harness: "steps", consumeStep: 2, expectThreat: 40,
    steps: [{ role: "write", stage: "file", text: "a" }, { role: "consume", stage: "output", text: "b" }]
  }, null);
  assert.deepEqual(stub.seen, ["file", "output"], "each step must be scanned at its own stage");
  assert.equal(row.detected, true);
  assert.equal(row.correctThreat, true);
});

test("a steps attack caught ONLY at the write step counts as a miss, not a catch", async () => {
  const stub = {
    scan(text, stage) { return stage === "file" ? [{ threat: { id: 40, riskLevel: "High", riskScore: 1 } }] : []; },
    scanSession() { return []; }
  };
  const row = await evalVectorSample(stub, {
    id: "synthetic-2", shouldDetect: true, harness: "steps", consumeStep: 2,
    steps: [{ role: "write", stage: "file", text: "a" }, { role: "consume", stage: "output", text: "b" }]
  }, null);
  assert.equal(row.anyStepDetected, true, "anyStep must record the write-time catch");
  assert.equal(row.detected, false, "the headline verdict is the consume step");
  assert.equal(row.outcome, "FN");
});

test("a benign steps sample firing at ANY step is a false positive", async () => {
  const stub = {
    scan(text, stage) { return stage === "file" ? [{ threat: { id: 40, riskLevel: "High", riskScore: 1 } }] : []; },
    scanSession() { return []; }
  };
  const row = await evalVectorSample(stub, {
    id: "synthetic-3", shouldDetect: false, harness: "steps",
    steps: [{ role: "write", stage: "file", text: "a" }, { role: "consume", stage: "output", text: "b" }]
  }, null);
  assert.equal(row.outcome, "FP");
});

test("scoreVector arithmetic is consistent with the rows it is given", () => {
  const rows = [
    { shouldDetect: true, detected: true, anyStepDetected: true, correctThreat: true, outcome: "TP", subTechnique: "a", harness: "text", stage: "tool", recovered: false },
    { shouldDetect: true, detected: false, anyStepDetected: true, correctThreat: false, outcome: "FN", subTechnique: "a", harness: "text", stage: "tool", recovered: false },
    { shouldDetect: false, detected: true, anyStepDetected: true, correctThreat: false, outcome: "FP", subTechnique: "b", harness: "text", stage: "file", recovered: false },
    { shouldDetect: false, detected: false, anyStepDetected: false, correctThreat: false, outcome: "TN", subTechnique: "b", harness: "text", stage: "file", recovered: false }
  ];
  const sc = scoreVector(rows);
  assert.equal(sc.totals.tp, 1);
  assert.equal(sc.totals.fn, 1);
  assert.equal(sc.totals.fp, 1);
  assert.equal(sc.totals.tn, 1);
  assert.equal(sc.recall, 0.5);
  assert.equal(sc.recallAnyStep, 1);   // both attacks fired at SOME step
  assert.equal(sc.precision, 0.5);
  assert.equal(sc.fpRate, 0.5);
});

// ------------------------------------------------------- reachability findings ----

// These encode what was MEASURED about the shipped harnesses, so the finding does not quietly rot. If a
// future change wires a caller for one of these stages, this test fails and the table gets updated —
// which is the point.
test("the tool stage has no shipped caller (recorded finding, not an aspiration)", () => {
  assert.equal(STAGE_REACHABILITY.tool.reachable, false);
  const toolAttacks = V3.attacks.filter((s) => s.stage === "tool");
  assert.ok(toolAttacks.length >= 30, "the vector-3 corpus must exercise the tool stage even though nothing calls it");
  // The detectors themselves DO cover the stage — the gap is the harness, not the rule set.
  const toolScoped = DETECTORS.filter((d) => (d.stages || [d.stage]).includes("tool")).map((d) => d.detectorId);
  assert.ok(toolScoped.includes("mcp-tool-poisoning"), "mcp-tool-poisoning must still be tool-scoped");
  assert.ok(toolScoped.includes("mcp-hidden-canary"), "mcp-hidden-canary must still be tool-scoped");
});
