// Structural + split integrity of the inbound web-content benign corpus.
//
// The corpus exists to replace an 11-sample anecdote with a real false-positive denominator, and a
// corpus can fail at that job in ways a green FP number would hide: 300 lookalikes instead of a
// representative spread, a hard-negative slice too thin to decide anything, a split that drifted from
// its own stated algorithm, or a fixture that carries a live-shaped credential into git.
//
// So these tests do not check the FP rate (that is scripts/score-webfetch-benign.mjs, which spawns the
// real hook). They check that the corpus can still be believed:
//   * every sample is well-formed and declares itself benign;
//   * the materialized `split` field is EXACTLY what the documented algorithm produces from the corpus
//     alone — the locked test half is worthless if the assignment is not reproducible;
//   * the split is balanced within each (channel, hard-negative) stratum;
//   * the corpus is representative and the hard-negative slice is substantial;
//   * no sample carries a push-protection-tripping or real-shaped secret.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { decisionOf, groupFp, countBy } from "../scripts/score-webfetch-benign.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS = JSON.parse(readFileSync(join(ROOT, "test/redteam/benign-web-content.json"), "utf8"));
const S = CORPUS.samples;

// The documented split algorithm, re-implemented here from the file's own _split description rather
// than imported, so that a change to the generator cannot silently redefine what "reproducible" means.
function expectedSplit(samples) {
  const buckets = new Map();
  for (const s of samples) {
    const k = `${s.channel}|${s.hard_negative ? "hn" : "plain"}`;
    if (!buckets.has(k)) buckets.set(k, []);
    buckets.get(k).push(s);
  }
  const out = new Map();
  for (const k of [...buckets.keys()].sort()) {
    const group = buckets.get(k).slice().sort((a, b) => String(a.id).localeCompare(String(b.id)));
    group.forEach((s, i) => out.set(s.id, i % 2 === 0 ? "tune" : "test"));
  }
  return out;
}

test("every sample is well-formed and declares itself benign", () => {
  assert.ok(S.length >= 280, `corpus too small to be a denominator: ${S.length}`);
  const ids = new Set();
  for (const s of S) {
    assert.equal(typeof s.id, "string", `bad id: ${JSON.stringify(s.id)}`);
    assert.ok(!ids.has(s.id), `duplicate id ${s.id}`);
    ids.add(s.id);
    assert.equal(s.shouldDetect, false, `${s.id} must declare shouldDetect:false`);
    assert.equal(s.stage, "output", `${s.id} must declare the output stage`);
    assert.equal(typeof s.channel, "string");
    assert.equal(typeof s.hard_negative, "boolean");
    assert.ok(["WebFetch", "WebSearch"].includes(s.tool), `${s.id} bad tool ${s.tool}`);
    assert.ok(["tune", "test"].includes(s.split), `${s.id} bad split ${s.split}`);
    assert.ok(typeof s.validity === "string" && s.validity.length > 20, `${s.id} needs a validity rationale`);
    assert.ok(typeof s.text === "string" && s.text.trim().length >= 120, `${s.id} text too short`);
  }
});

test("the split is exactly reproducible from the corpus alone", () => {
  const want = expectedSplit(S);
  const drifted = S.filter((s) => want.get(s.id) !== s.split).map((s) => s.id);
  assert.deepEqual(drifted, [], `materialized split drifted from the documented algorithm: ${drifted.join(", ")}`);
});

test("the split is balanced within every (channel, hard-negative) stratum", () => {
  const strata = new Map();
  for (const s of S) {
    const k = `${s.channel}|${s.hard_negative ? "hn" : "plain"}`;
    if (!strata.has(k)) strata.set(k, { tune: 0, test: 0 });
    strata.get(k)[s.split]++;
  }
  for (const [k, c] of strata) assert.ok(Math.abs(c.tune - c.test) <= 1, `stratum ${k} unbalanced: ${c.tune}/${c.test}`);
  const tune = S.filter((s) => s.split === "tune").length;
  assert.ok(Math.abs(tune - (S.length - tune)) <= strata.size, "halves are not the same size");
});

test("the corpus is representative, not 300 lookalikes", () => {
  const channels = new Map();
  for (const s of S) channels.set(s.channel, (channels.get(s.channel) || 0) + 1);
  assert.ok(channels.size >= 12, `only ${channels.size} channels`);
  // No single channel may dominate: an FP rate driven by one page shape is not a surface-level number.
  for (const [c, n] of channels) assert.ok(n / S.length <= 0.15, `channel ${c} is ${((n / S.length) * 100).toFixed(0)}% of the corpus`);
  assert.ok(S.some((s) => s.tool === "WebSearch"), "the WebSearch path is unmeasured");
});

test("the hard-negative slice is substantial and covers the buckets that decide the FP rate", () => {
  const hn = S.filter((s) => s.hard_negative);
  assert.ok(hn.length / S.length >= 0.3, `hard negatives are only ${((hn.length / S.length) * 100).toFixed(0)}% of the corpus`);
  const hnChannels = new Set(hn.map((s) => s.channel));
  // dlp-email's fate is decided by ordinary pages that merely carry a contact address, so that bucket
  // is load-bearing rather than decorative.
  for (const need of ["contact-email-page", "security-advisory", "cred-rotation-runbook", "prompt-injection-tutorial", "encoded-blob", "human-imperative", "non-english-docs"]) {
    assert.ok(hnChannels.has(need), `hard-negative channel missing: ${need}`);
  }
  assert.ok(S.filter((s) => s.channel === "contact-email-page").length >= 25, "contact-email-page bucket too thin to price dlp-email");
});

test("no sample carries a push-protection-tripping or real-shaped secret", () => {
  const forbidden = [
    [/sk_live_[0-9a-zA-Z]{10,}/, "Stripe live-key shape (blocks the push)"],
    [/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, "private key block"],
    [/AKIA(?!IOSFODNN7EXAMPLE)[A-Z0-9]{16}/, "non-placeholder AWS access key id"]
  ];
  for (const s of S) for (const [re, why] of forbidden) assert.ok(!re.test(s.text), `${s.id} contains ${why}`);
});

test("no two samples are byte-identical or share a long opening", () => {
  const seen = new Map();
  for (const s of S) {
    const head = s.text.replace(/\s+/g, " ").trim().slice(0, 160);
    assert.ok(!seen.has(head), `${s.id} duplicates the opening of ${seen.get(head)}`);
    seen.set(head, s.id);
  }
});

// The decision distribution is a headline output of the scorer, and it is derived from the hook's
// stdout. These are the three envelopes cli/moorai-hook.mjs emitPost() actually writes.
test("decisionOf reads the hook's real PostToolUse envelopes", () => {
  assert.equal(decisionOf(""), "allow");
  assert.equal(decisionOf("   "), "allow");
  assert.equal(decisionOf(JSON.stringify({ hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: "MoorAI: flagged ingested WebFetch content — #40 ..." } })), "advisory");
  assert.equal(decisionOf(JSON.stringify({ decision: "block", reason: "MoorAI: blocked", hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: "MoorAI: blocked" } })), "deny");
  assert.equal(decisionOf("not json at all"), "unknown");
});

test("the scorer's reducers count what the report claims they count", () => {
  const rows = [
    { channel: "a", alerted: true, decision: "advisory", detectors: ["dlp-email"] },
    { channel: "a", alerted: false, decision: "allow", detectors: [] },
    { channel: "b", alerted: true, decision: "allow", detectors: ["dlp-email", "inj-untrusted-directive"] }
  ];
  const g = groupFp(rows, "channel");
  assert.deepEqual(g.find((x) => x.channel === "a"), { channel: "a", samples: 2, fp: 1, advisory: 1, fpRate: 0.5 });
  assert.deepEqual(g.find((x) => x.channel === "b"), { channel: "b", samples: 1, fp: 1, advisory: 0, fpRate: 1 });
  assert.deepEqual(countBy(rows.filter((r) => r.alerted), (r) => r.detectors), [
    { key: "dlp-email", samples: 2 },
    { key: "inj-untrusted-directive", samples: 1 }
  ]);
});
