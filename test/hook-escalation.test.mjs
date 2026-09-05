// #21 — proves the PRODUCTION enforcement hot path (cli/moorai-hook.mjs::maybeEscalate and
// cli/moorai-guard.mjs::maybeEscalate) is now wired to the engine's semantic ORCHESTRATION
// (src/semantic.js escalate/escalateMiss) instead of the bare classifyOpportunistic→#58 shortcut.
//
// Two layers, both falsifiable:
//   (1) BEHAVIORAL — runs the exact orchestration maybeEscalate composes (buildEngine → engine.scan →
//       escalate/escalateMiss with a stubbed verdict) against the REAL production detector set, at the
//       hook's stage ("file"). This proves the `semantic-persuasion` DETECT-gate detector (threat #2)
//       actually fires through this path — impossible with the old shortcut, which only ever emitted #58.
//   (2) STRUCTURAL — asserts the source of both entrypoints calls escalate()/escalateMiss(), no longer
//       calls classifyOpportunistic, keeps the policy.modelEscalation opt-in, stays fail-open (try/catch),
//       and passes the engine into the call sites. Reverting the wiring turns these red.
//
//   node --test test/hook-escalation.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildEngine } from "../cli/hook-core.mjs";
import { escalate, escalateMiss } from "../src/semantic.js";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "cli", "moorai-hook.mjs");
const GUARD = join(dirname(fileURLToPath(import.meta.url)), "..", "cli", "moorai-guard.mjs");

// Escalation ON: modelEscalation is the hook's operator opt-in; semanticEscalation is what escalate()/
// escalateMiss() gate on internally. Both are needed for the production semantic path to run.
const ON = { modelEscalation: true, semanticEscalation: "provider" };
// A span the deterministic engine finds NOTHING for — so any threat-#2 finding can only come from the
// model-gated DETECT path, and the miss-recovery path is reachable.
const CLEAN = "the quick brown fox jumps over the lazy dog";
// mirror maybeEscalate's "new findings" diff
const added = (after, base) => after.filter((f) => !base.some((b) => b.threat.id === f.threat.id));

test("DETECT gate fires through the hook path: a flagged verdict ADDS a threat-#2 finding at stage file", async () => {
  const engine = buildEngine({});
  const base = engine.scan(CLEAN, "file");
  assert.equal(base.length, 0, "fixture must be clean so #2 can only come from the model-gated detect gate");
  const verdict = async () => ({ flagged: true, category: "persuasion", confidence: 0.9 });
  const out = await escalate(engine, base, CLEAN, "file", ON, { verdict });
  const news = added(out, base);
  assert.equal(news.length, 1);
  assert.equal(news[0].threat.id, 2, "the semantic-persuasion detect gate raises threat #2");
  assert.equal(news[0].detectorId, "semantic-persuasion");
  assert.equal(news[0].match, "semantic:persuasion", "content-free: only the model's category label");
});

test("DETECT gate is inert on a benign/low-confidence verdict (no finding added)", async () => {
  const engine = buildEngine({});
  const base = engine.scan(CLEAN, "file");
  const benign = async () => ({ flagged: false, category: "benign", confidence: 0.95 });
  assert.deepEqual(await escalate(engine, base, CLEAN, "file", ON, { verdict: benign }), base);
  const lowconf = async () => ({ flagged: true, category: "persuasion", confidence: 0.3 });
  assert.deepEqual(added(await escalate(engine, base, CLEAN, "file", ON, { verdict: lowconf }), base), []);
});

test("MISS recovery fires through the hook path: a flagged verdict returns ONE content-free #58 finding", async () => {
  const engine = buildEngine({});
  const verdict = async () => ({ flagged: true, category: "crescendo", confidence: 0.8 });
  const miss = await escalateMiss(engine, CLEAN, "file", ON, { verdict });
  assert.ok(miss, "escalateMiss must return a finding when the model flags");
  assert.equal(miss.threat.id, 58);
  assert.equal(miss.match, "semantic:crescendo");
  const benign = await escalateMiss(engine, CLEAN, "file", ON, { verdict: async () => ({ flagged: false, category: "x", confidence: 0.9 }) });
  assert.equal(benign, null);
});

test("OFF by default: escalation runs no model and changes nothing when the policy flag is off", async () => {
  const engine = buildEngine({});
  const base = engine.scan(CLEAN, "file");
  const verdict = async () => ({ flagged: true, category: "persuasion", confidence: 0.99 });
  // Default policy → semanticEnabled(policy) === false → escalate/escalateMiss are no-ops (base / null).
  assert.deepEqual(await escalate(engine, base, CLEAN, "file", {}, { verdict }), base);
  assert.equal(await escalateMiss(engine, CLEAN, "file", {}, { verdict }), null);
});

test("FAIL-OPEN: a throwing model propagates, and the hook's try/catch shape swallows it (no finding, no throw)", async () => {
  const engine = buildEngine({});
  const base = engine.scan(CLEAN, "file");
  const boom = async () => { throw new Error("model exploded"); };
  // The escalators propagate the throw — which is exactly why maybeEscalate wraps them in a fail-open
  // try/catch. Prove the throw is real (so the wrapper is load-bearing)...
  await assert.rejects(() => escalate(engine, base, CLEAN, "file", ON, { verdict: boom }));
  await assert.rejects(() => escalateMiss(engine, CLEAN, "file", ON, { verdict: boom }));
  // ...then prove the wrapper shape maybeEscalate uses turns that into "no change to enforcement".
  let news = null;
  try {
    const out = await escalate(engine, base, CLEAN, "file", ON, { verdict: boom });
    news = added(out, base);
  } catch { news = []; }
  assert.deepEqual(news, [], "a throwing model must leave enforcement (and posted findings) unchanged");
});

// ---- STRUCTURAL: the wiring itself (reverting to the shortcut turns these red) ----

test("HOOK wiring: maybeEscalate calls escalate()/escalateMiss(), drops classifyOpportunistic, stays gated + fail-open", () => {
  const src = readFileSync(HOOK, "utf8");
  const body = src.slice(src.indexOf("async function maybeEscalate"), src.indexOf("function reportSkillFile"));
  assert.ok(body.length > 0, "maybeEscalate not found — update this test");
  assert.match(body, /\bescalate\(/, "hook must call the engine's escalate() detect/confirm gate");
  assert.match(body, /\bescalateMiss\(/, "hook must call escalateMiss() for the miss-recovery #58");
  assert.doesNotMatch(body, /classifyOpportunistic/, "the bare classifyOpportunistic shortcut must be gone");
  assert.match(body, /policy\.modelEscalation/, "the operator opt-in gate must be preserved (backward compat)");
  assert.match(body, /catch\s*\{/, "escalation must remain fail-open (swallowing try/catch)");
  assert.match(src, /import \{ escalate, escalateMiss, semanticVerdict \} from "\.\.\/src\/semantic\.js"/);
  // both call sites feed the engine in
  const read = src.slice(src.indexOf('if (tool === "Read")'));
  assert.match(read, /maybeEscalate\(policy, text, "file", "hook:Read", d, engine\)/);
  const bash = src.slice(src.indexOf('if (tool === "Bash")'));
  assert.match(bash, /maybeEscalate\(policy, btext, "file", "hook:Bash", \{ findings: finds \}, engine\)/);
});

test("GUARD wiring: maybeEscalate calls escalate()/escalateMiss(), drops classifyOpportunistic, stays gated", () => {
  const src = readFileSync(GUARD, "utf8");
  const body = src.slice(src.indexOf("async function maybeEscalate"), src.indexOf("async function main"));
  assert.ok(body.length > 0, "guard maybeEscalate not found — update this test");
  assert.match(body, /\bescalate\(/, "guard must call the engine's escalate()");
  assert.match(body, /\bescalateMiss\(/, "guard must call escalateMiss()");
  assert.doesNotMatch(body, /classifyOpportunistic/, "the bare classifyOpportunistic shortcut must be gone");
  assert.match(body, /policy\.modelEscalation/, "the operator opt-in gate must be preserved (backward compat)");
  assert.match(src, /import \{ escalate, escalateMiss, semanticVerdict \} from "\.\.\/src\/semantic\.js"/);
});
