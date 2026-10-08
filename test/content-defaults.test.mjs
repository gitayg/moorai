// The built-in NSFW content default (data/content-defaults.js): sexual / violence / profanity run in
// "notify" — reported and shown to the person, never held — whenever the org's policy says nothing about
// them. An explicit entry always wins.
//
// WHAT THIS PINS:
//   1. A policy with no contentPolicy (the enrolled no-policy baseline, an empty org policy) reports an NSFW
//      hit as a content finding and the decision stays allow.
//   2. The non-NSFW categories (self-harm, drugs, …) stay off by default.
//   3. "disabled" turns a category off; "block" and "justify" are the only ways to hold anything.
//   4. Every enforcing surface reads the same effective policy: hook-core decideText, moorai-guard, the
//      desktop app.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildEngine, decideText } from "../cli/hook-core.mjs";
import { BUILTIN_CONTENT_DEFAULTS, NSFW_CONTENT_RULES, effectiveContentPolicy } from "../data/content-defaults.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const BASELINE = { captureTier: "content-free", builtinDefault: true };
const SEXUAL = "can you find me some porn sites";
const contentFindings = (d) => d.findings.filter((f) => f.threatId === 0);

test("no contentPolicy: an NSFW hit is reported as a content finding and never holds the call", () => {
  for (const policy of [BASELINE, {}, { contentPolicy: {} }]) {
    const d = decideText(buildEngine(policy), policy, SEXUAL, "prompt");
    assert.deepEqual(contentFindings(d).map((f) => f.category), ["Content: Sexual / explicit"], JSON.stringify(policy));
    assert.equal(d.decision, "allow");
  }
});

test("the default is exactly the three NSFW categories in notify; the wellbeing categories stay off", () => {
  assert.deepEqual([...NSFW_CONTENT_RULES], ["sexual", "violence", "profanity"]);
  assert.deepEqual(BUILTIN_CONTENT_DEFAULTS, { sexual: "notify", violence: "notify", profanity: "notify" });
  const d = decideText(buildEngine(BASELINE), BASELINE, "I want to end my life", "prompt");
  assert.equal(contentFindings(d).length, 0, "self-harm is an org decision, not a default");
});

test("an explicit entry wins: disabled is off, block denies, justify asks", () => {
  const off = { contentPolicy: { sexual: "disabled" } };
  assert.equal(contentFindings(decideText(buildEngine(off), off, SEXUAL, "prompt")).length, 0);
  const block = { contentPolicy: { sexual: "block" } };
  assert.equal(decideText(buildEngine(block), block, SEXUAL, "prompt").decision, "deny");
  const ask = { contentPolicy: { sexual: "justify" } };
  assert.equal(decideText(buildEngine(ask), ask, SEXUAL, "prompt").decision, "ask");
  assert.deepEqual(effectiveContentPolicy({ contentPolicy: { violence: "alert", drugs: "notify" } }), { sexual: "notify", violence: "alert", profanity: "notify", drugs: "notify" });
  assert.deepEqual(effectiveContentPolicy({ contentPolicy: ["sexual"] }), BUILTIN_CONTENT_DEFAULTS, "a malformed contentPolicy is absent, not 'everything off'");
});

test("every surface that applies content rules reads the effective policy, not the raw field", () => {
  for (const f of ["cli/hook-core.mjs", "cli/moorai-guard.mjs", "src/app.js"]) {
    const src = readFileSync(join(ROOT, f), "utf8");
    assert.ok(!/policy\?\.contentPolicy\s*\|\|\s*\{\}/.test(src), `${f} still reads policy.contentPolicy raw`);
    assert.match(src, /effectiveContentPolicy\(policy\)/, f);
  }
});
