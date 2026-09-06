// Tests for scripts/measure-variance.mjs — the repeated-run variance harness.
//
// The load-bearing property is NEGATIVE: the harness must be able to SEE non-determinism. A stability
// classifier that always says "stable" would produce a beautiful, meaningless report, so the tests below
// feed it verdict vectors that are known to flip and assert it reports them as unstable with the right
// flip rate. The arithmetic tests pin the interval choices (t for the run-level mean, Wilson for the
// per-sample proportion) against hand-computed values.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  median, tCritical, summarize, wilson, classifySample, stabilityTable, runMetrics, loadSamples
} from "../scripts/measure-variance.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

test("median handles odd and even lengths", () => {
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([4, 1, 3, 2]), 2.5);
  assert.equal(median([]), null);
});

test("summarize reports the raw spread and a t-based CI, not a z-based one", () => {
  // Hand-computed: mean 2, sample sd (n-1) = 1, n = 5, t(4) = 2.776 -> half width 2.776 * 1/sqrt(5).
  const s = summarize([1, 2, 3, 2, 2]);
  assert.equal(s.n, 5);
  assert.equal(s.min, 1);
  assert.equal(s.max, 3);
  assert.equal(s.median, 2);
  assert.equal(s.mean, 2);
  assert.ok(Math.abs(s.sd - 0.7071) < 1e-3, `sd was ${s.sd}`);
  const expectedHalf = 2.776 * (s.sd / Math.sqrt(5));
  assert.ok(Math.abs((s.ci95[1] - s.mean) - expectedHalf) < 1e-6, `ci half-width ${s.ci95[1] - s.mean}`);
  // The t multiplier must be WIDER than the normal 1.96 at this n — that is the whole point of using it.
  assert.ok(s.ci95[1] - s.mean > 1.96 * (s.sd / Math.sqrt(5)));
});

test("summarize of an invariant metric has zero spread and a zero-width interval", () => {
  const s = summarize([0.9, 0.9, 0.9]);
  assert.equal(s.sd, 0);
  assert.deepEqual([s.min, s.max], [0.9, 0.9]);
  assert.equal(s.ci95[0], 0.9);
});

test("tCritical is the small-sample multiplier and falls back to z for large df", () => {
  assert.equal(tCritical(9), 2.262);
  assert.equal(tCritical(1), 12.706);
  assert.ok(tCritical(200) <= 2.045);
  assert.equal(tCritical(0), null);
});

test("wilson gives a NON-degenerate interval at k=0 and k=n (Wald would not)", () => {
  const zero = wilson(0, 10);
  assert.equal(zero[0], 0);
  // A Wald interval here is [0,0] — claiming certainty 10 runs cannot support.
  assert.ok(zero[1] > 0.2, `upper bound was ${zero[1]}`);
  const all = wilson(10, 10);
  assert.equal(all[1], 1);
  assert.ok(all[0] < 0.8, `lower bound was ${all[0]}`);
  assert.equal(wilson(0, 0), null);
});

test("classifySample separates always-caught / always-missed / unstable", () => {
  assert.equal(classifySample(10, 10).stability, "always-caught");
  assert.equal(classifySample(0, 10).stability, "always-missed");
  assert.equal(classifySample(5, 10).stability, "unstable");
  assert.equal(classifySample(5, 10).flipRate, 0.5);
  // flipRate is the MINORITY rate: a sample caught 8/10 flips 20% of the time, not 80%.
  assert.ok(Math.abs(classifySample(8, 10).flipRate - 0.2) < 1e-9);
  assert.ok(Math.abs(classifySample(2, 10).flipRate - 0.2) < 1e-9);
  assert.equal(classifySample(10, 10).flipRate, 0);
});

test("stabilityTable SEES a sample that flips between runs", () => {
  const runs = [
    { a: 1, b: 1, c: 0 },
    { a: 1, b: 0, c: 0 },
    { a: 1, b: 1, c: 0 },
    { a: 1, b: 0, c: 0 }
  ];
  const t = stabilityTable(["a", "b", "c"], runs);
  const by = Object.fromEntries(t.map((r) => [r.id, r]));
  assert.equal(by.a.stability, "always-caught");
  assert.equal(by.c.stability, "always-missed");
  assert.equal(by.b.stability, "unstable");
  assert.equal(by.b.hits, 2);
  assert.equal(by.b.flipRate, 0.5);
});

test("stabilityTable does not manufacture instability from an invariant run set", () => {
  const runs = [{ a: 1, b: 0 }, { a: 1, b: 0 }, { a: 1, b: 0 }];
  const t = stabilityTable(["a", "b"], runs);
  assert.equal(t.filter((r) => r.stability === "unstable").length, 0);
});

test("runMetrics computes recall / precision / FP from a verdict map", () => {
  const samples = [
    { id: "a1", shouldDetect: true }, { id: "a2", shouldDetect: true },
    { id: "b1", shouldDetect: false }, { id: "b2", shouldDetect: false }
  ];
  const m = runMetrics(samples, { a1: 1, a2: 0, b1: 1, b2: 0 });
  assert.deepEqual([m.tp, m.fn, m.fp, m.tn], [1, 1, 1, 1]);
  assert.equal(m.recall, 0.5);
  assert.equal(m.precision, 0.5);
  assert.equal(m.fpRate, 0.5);
});

test("loadSamples labels the heldout-v2 shape correctly", () => {
  const s = loadSamples({ attacks: [{ id: "x" }], benign: [{ id: "y" }] });
  assert.equal(s.length, 2);
  assert.equal(s.find((r) => r.id === "x").shouldDetect, true);
  assert.equal(s.find((r) => r.id === "y").shouldDetect, false);
});

// The claim the whole cost model rests on: the regex/entropy layer returns the same verdict every time,
// so N runs only need to pay for the escalation-eligible subset. Proven here against the real engine and
// the real locked corpus, not assumed.
test("the deterministic engine is invariant across repeated scans of the locked corpus", async () => {
  const { DETECTORS } = await import("../data/detectors.js");
  const { CONTENT_RULES } = await import("../data/content-rules.js");
  const { DetectionEngine } = await import("../src/engine.js");
  const { evalSample } = await import("../scripts/redteam-eval.mjs");

  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const corpus = JSON.parse(readFileSync(join(ROOT, "test/redteam/heldout-v2-test.json"), "utf8"));
  const samples = loadSamples(corpus);
  const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
  const scan = (text, stage) => engine.scan(text, stage);

  const vectors = [];
  for (let i = 0; i < 3; i++) {
    const v = {};
    for (const s of samples) v[s.id] = (await evalSample(engine, s, scan)).detected ? 1 : 0;
    vectors.push(v);
  }
  const table = stabilityTable(samples.map((s) => s.id), vectors);
  const drifted = table.filter((r) => r.stability === "unstable");
  assert.deepEqual(drifted.map((r) => r.id), [], "deterministic layer drifted between identical scans");
  // Sanity: the corpus is not trivially all-caught or all-missed, so the invariance above is meaningful.
  assert.ok(table.some((r) => r.stability === "always-caught"));
  assert.ok(table.some((r) => r.stability === "always-missed"));
});
