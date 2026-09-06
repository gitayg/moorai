// Guards the benign corpus v2 (the precision half of the measurement) and its scorer.
//
// Deliberately NOT asserted here: an exact false-positive count. Detectors change every wave, so pinning a
// number would make this test a tripwire for other people's work rather than a guard on the corpus. What IS
// asserted is everything that would silently corrupt a precision number: duplicate or missing ids, an
// unlabelled bucket, a hard negative with no twin, a live-shaped secret smuggled into a fixture (GitHub
// push protection has blocked a push over exactly that before), a sample accidentally labelled as an attack,
// and the scorer's own arithmetic.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { groupFp, parseArgs, runCorpus } from "../scripts/score-benign-v2.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const corpus = JSON.parse(readFileSync(join(ROOT, "test/redteam/benign-corpus-v2.json"), "utf8"));
const samples = corpus.benign;

test("corpus is large enough to make a precision number meaningful", () => {
  assert.ok(samples.length >= 400, `expected >= 400 benign samples, got ${samples.length}`);
});

test("hard-negative slice is large enough to be the real test", () => {
  const hn = samples.filter((s) => s.hard_negative);
  assert.ok(hn.length >= 120, `expected >= 120 hard negatives, got ${hn.length}`);
});

test("every sample has a unique id, a bucket and non-trivial text", () => {
  const ids = new Set();
  for (const s of samples) {
    assert.ok(s.id && !ids.has(s.id), `duplicate or missing id: ${s.id}`);
    ids.add(s.id);
    assert.ok(typeof s.category === "string" && s.category.length, `missing category on ${s.id}`);
    assert.ok(typeof s.text === "string" && s.text.trim().length >= 20, `text too short on ${s.id}`);
  }
});

test("no two samples share the same text (diversity, not padding)", () => {
  const seen = new Map();
  for (const s of samples) {
    const key = s.text.trim().toLowerCase();
    assert.ok(!seen.has(key), `duplicate text: ${s.id} == ${seen.get(key)}`);
    seen.set(key, s.id);
  }
});

test("every hard negative names the detector concept it is a twin of", () => {
  for (const s of samples.filter((x) => x.hard_negative)) {
    assert.ok(typeof s.twin_of === "string" && s.twin_of.length, `hard negative ${s.id} has no twin_of`);
  }
  const twins = new Set(samples.filter((s) => s.hard_negative).map((s) => s.twin_of));
  assert.ok(twins.size >= 12, `expected >= 12 distinct twin families, got ${twins.size}`);
});

test("no sample is labelled as an attack — this corpus is benign by construction", () => {
  for (const s of samples) {
    assert.notEqual(s.shouldDetect, true, `${s.id} is labelled shouldDetect:true in a benign corpus`);
    assert.equal(s.expectThreat, undefined, `${s.id} carries an expected threat`);
  }
});

// Live-shaped provider secrets must never enter the repo: GitHub push protection blocks the push, and a
// real credential in a test fixture is a real credential. Documentation placeholders are allowed and used.
test("no live-shaped provider secret appears in any fixture", () => {
  const forbidden = [
    /sk_live_[0-9a-zA-Z]{10,}/,          // Stripe live secret
    /sk_test_51[0-9a-zA-Z]{10,}/,        // Stripe test secret (still push-protected)
    /xox[baprs]-[0-9]{8,}-[0-9]{8,}/,    // Slack token
    /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    /AIza[0-9A-Za-z_-]{35}/,             // Google API key
    /glpat-[0-9A-Za-z_-]{20}/            // GitLab PAT
  ];
  for (const s of samples) {
    for (const re of forbidden) {
      assert.equal(re.test(s.text), false, `${s.id} contains a live-shaped secret matching ${re}`);
    }
  }
});

test("bucket coverage spans the whole developer surface", () => {
  const buckets = new Set(samples.map((s) => s.category));
  for (const required of [
    "coding", "refactor", "debug", "testing", "devops", "data-sql", "docs", "git", "code-review",
    "architecture", "deps", "shell", "logs", "casual", "planning", "agent-file", "agent-net",
    "security-legit", "hard-neg"
  ]) {
    assert.ok(buckets.has(required), `missing bucket: ${required}`);
  }
});

test("groupFp computes per-group false-positive rates", () => {
  const rows = [
    { bucket: "a", detected: true },
    { bucket: "a", detected: false },
    { bucket: "b", detected: false },
    { bucket: null, detected: true }
  ];
  const out = groupFp(rows, "bucket");
  assert.deepEqual(out.map((r) => r.bucket), ["a", "b"]);
  assert.equal(out[0].fp, 1);
  assert.equal(out[0].samples, 2);
  assert.equal(out[0].fpRate, 0.5);
  assert.equal(out[1].fpRate, 0);
});

test("parseArgs reads the flags the CI gate depends on", () => {
  const a = parseArgs(["--json", "--strict", "--fail-over", "2", "--file", "x.json"]);
  assert.equal(a.json, true);
  assert.equal(a.strict, true);
  assert.equal(a.failOver, 2);
  assert.equal(a.file, "x.json");
  assert.equal(parseArgs([]).failOver, null);
});

test("scorer runs the whole corpus and reports diagnosable false positives", async () => {
  const res = await runCorpus();
  assert.equal(res.totals.samples, samples.length);
  assert.equal(res.plainBenign.samples + res.hardNegative.samples, samples.length);
  assert.ok(res.fpRate >= 0 && res.fpRate <= 1);
  assert.equal(res.byTwin.reduce((n, t) => n + t.samples, 0), res.hardNegative.samples);
  // Every FP must be diagnosable: it names the detector and threat that fired.
  for (const f of res.fps) {
    assert.ok(f.detectors.length, `FP ${f.id} has no detector attribution`);
    assert.ok(f.threats.length, `FP ${f.id} has no threat attribution`);
  }
  // A sanity floor rather than a pinned number: the engine must not be firing on most benign text.
  assert.ok(res.fpRate < 0.25, `FP rate ${(res.fpRate * 100).toFixed(2)}% — the engine is firing on ordinary work`);
});
