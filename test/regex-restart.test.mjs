// The restart mechanism (src/regex-restart.js) on every /g walker of detector patterns: engine.redact,
// engine._matchDetector (refine detectors) and cli/mask.mjs. A synthetic pair with the dlp-email gap's
// shape keeps this independent of any one detector: NEW refuses a start that "b" precedes through "+"s,
// OLD does not, so under /g "ab+ab" is two OLD matches and one NEW match.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DETECTORS } from "../data/detectors.js";
import { DetectionEngine } from "../src/engine.js";
import { withRestart, globalMatches } from "../src/regex-restart.js";
import { maskValue } from "../cli/mask.mjs";

const threats = JSON.parse(readFileSync(new URL("../data/threats.json", import.meta.url), "utf8"));
const OLD = /[a+]+b/;
const NEW = () => withRestart(/(?<!b\+{0,9})[a+]+b/, OLD);
const synth = (extra = {}) => ({ detectorId: "synthetic-restart", threatId: 15, stages: ["prompt"], mode: "warn", hint: "", patterns: [NEW()], ...extra });

test("restart: a pattern without one walks exactly as String.prototype.matchAll does", () => {
  const re = /(?<!b\+{0,9})[a+]+b/;
  const s = "ab+ab a+b ++ab";
  const g = new RegExp(re.source, "g");
  assert.deepEqual([...globalMatches(re, g, s)].map((m) => [m.index, m[0]]), [...s.matchAll(new RegExp(re.source, "g"))].map((m) => [m.index, m[0]]));
});

test("restart: engine.redact takes the glued match the old pattern took", () => {
  const e = new DetectionEngine(threats, [synth()], []);
  assert.equal(e.redact("ab+ab+ab x", "prompt"), "[REDACTED:#15][REDACTED:#15][REDACTED:#15] x");
});

test("restart: _matchDetector's refine walk reaches a glued match", () => {
  // refine rejects the first match, so scan must find the glued second one, as the old pattern did.
  const e = new DetectionEngine(threats, [synth({ refine: (m) => m.startsWith("+") })], []);
  assert.equal(e._matchDetector("ab+ab", e.detectors[0]), "+ab");
});

test("restart: cli/mask.mjs masks a glued match", () => {
  const e = new DetectionEngine(threats, [synth()], []);
  const r = maskValue(e, "ab+ab", { stage: "prompt", ids: [15], hash: () => "00000000" });
  assert.equal(r.value, "[MOORAI:pii:aaaaaaaa][MOORAI:pii:aaaaaaaa]");
  assert.equal(r.count, 2);
});

test("restart: every built-in restart pattern is a non-empty-matching pattern without a lookbehind", () => {
  const withR = DETECTORS.flatMap((d) => d.patterns.filter((p) => p.restart).map((p) => [d.detectorId, p]));
  assert.deepEqual(withR.map(([id]) => id), ["dlp-email"]);
  for (const [id, p] of withR) {
    assert.ok(!p.restart.source.includes("(?<"), `${id}: restart must be the pre-lookbehind pattern`);
    assert.ok(!p.restart.test(""), `${id}: restart must not match the empty string`);
    assert.equal(Object.keys(p).length, 0, `${id}: restart must stay non-enumerable`);
  }
});
