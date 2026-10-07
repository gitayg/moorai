// dlp-email must cost linear time on text with no address in it, and match exactly what it matched before.
//
// THE BUG. The pattern was /\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b/. On "a.a.a.…" (no "@") every "a" is a word
// boundary, so the engine started a match at each one, `[\w.+-]+` ran to the end of the run, then gave
// back one character at a time looking for an "@": O(n) work at O(n) starts. MEASURED, `.test()` on
// "a." repeated: 110ms at 15k, 1693ms at 60k, 6133ms at 120k. Text an agent reads or a user pastes reaches
// it on every scan surface (scan via _firstMatch, redact via a /g copy).
//
// THE FIX. `\b(?<!\w[.+-]*)` — a match may only start at the FIRST word character of a run of
// [\w.+-]: the lookbehind refuses a start that a word character precedes through [.+-] alone. That was
// already the only start that could WIN (an earlier boundary in the same run always reaches the same "@"),
// so the leftmost match is unchanged; the other starts were pure waste. `\b` comes first, so the
// lookbehind is evaluated only at boundaries, and each run of [.+-] is walked back over once: linear.
//   now: 0.05ms at 15k, 0.23ms at 60k, 0.46ms at 120k.
//
// THE ONE KNOWN DIFFERENCE, /g only (engine.redact): when an address is glued to the previous match by
// [.+-] ("a@b.com+c@d.com"), the old pattern restarted AT lastIndex, on the "+", and redacted "+c@d.com";
// the new one cannot start inside a run that began before lastIndex, so it leaves "+c@d.com" in place. A
// first match (every scan) is identical. MEASURED: no difference, first match or /g, over every tracked
// file, every JSON string leaf, the inbound corpus and the node_modules texts (2049 /g matches).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DETECTORS } from "../data/detectors.js";
import { DetectionEngine } from "../src/engine.js";
import { scalingRatio } from "./timing.mjs";

const threats = JSON.parse(readFileSync(new URL("../data/threats.json", import.meta.url), "utf8"));
const DET = DETECTORS.find((d) => d.detectorId === "dlp-email");
const [RE] = DET.patterns;
// The pre-fix pattern, frozen here so equivalence is checked against the real thing, not remembered.
const OLD = /\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b/;

const first = (re, s) => { const m = new RegExp(re.source, re.flags.replace("g", "")).exec(s); return m ? `${m.index}:${m[0]}` : null; };
const all = (re, s) => [...s.matchAll(new RegExp(re.source, re.flags.replace("g", "") + "g"))].map((m) => [m.index, m[0]]);

// 8x the input. MEASURED (CPU time, scalingRatio): new 7.18-7.81x across the three shapes; the old pattern
// read 61.00x on "a." (26.61ms → 1623.35ms). Linear is ~8x and quadratic ~64x; the bound sits between.
const SHAPES = { "a.": (n) => "a.".repeat(n / 2), "x.y-": (n) => "x.y-".repeat(n / 4), "a+": (n) => "a+".repeat(n / 2) };

test("REDOS: dlp-email scales linearly on runs with no @ (8x the input, < 20x the cost)", () => {
  assert.equal(DET.patterns.length, 1);
  for (const [name, mk] of Object.entries(SHAPES)) {
    const small = mk(7500), large = mk(60000);
    const r = scalingRatio(() => RE.test(small), () => RE.test(large));
    assert.ok(r.ratio < 20, `"${name}": 8x the input cost ${r.ratio.toFixed(2)}x (${r.small.toFixed(2)}ms → ${r.large.toFixed(2)}ms) — linear ~8x, quadratic ~64x`);
  }
});

test("REDOS: engine.redact's /g copy of dlp-email scales linearly too", () => {
  // engine.scan() is covered by test/obfuscation-signal.test.mjs, whose linear-scan test now includes
  // dlp-email. redact() compiles its own /g copy and walks every match, so it is measured separately.
  // MEASURED: new 7.02-7.19x; the old pattern read 66.58x (25.69ms → 1710.13ms).
  const e = new DetectionEngine(threats, [DET], []);
  const small = SHAPES["a."](7500), large = SHAPES["a."](60000);
  const r = scalingRatio(() => e.redact(small, "prompt"), () => e.redact(large, "prompt"));
  assert.ok(r.ratio < 20, `redact: 8x the input cost ${r.ratio.toFixed(2)}x (${r.small.toFixed(2)}ms → ${r.large.toFixed(2)}ms)`);
});

// Pinned first matches, each one what the pre-fix pattern returns. A "fix" that changes which strings
// match — dropping `\b` for a bare lookbehind, or bounding the local part to {1,64} — fails here.
const CASES = [
  ["mail me at jane.doe@example.com please", "11:jane.doe@example.com"],
  ["first.last+tag@sub.example.co.uk", "0:first.last+tag@sub.example.co.uk"],
  ["<bob_smith-1@mail-server.example.org>", "1:bob_smith-1@mail-server.example.org"],
  ["To: a@b.co, c@d.io", "4:a@b.co"],
  ["x .john@x.com", "3:john@x.com"],                  // leading "." is not part of the match
  ["--alice@corp.io", "2:alice@corp.io"],
  ["a+.b@x.io", "0:a+.b@x.io"],
  ["a@b.com+c@d.com", "0:a@b.com"],
  ["x " + "a".repeat(70) + "@example.com", "2:" + "a".repeat(70) + "@example.com"], // > RFC's 64: still matched
  ["see " + "a.".repeat(40) + "b@example.com", "4:" + "a.".repeat(40) + "b@example.com"],
  ["a.".repeat(5000), null],                          // the pathological shape: no @, no match
  ["ping @octocat and @here", null],                  // handles
  ["foo@bar", null],                                  // no TLD
  ["user@localhost", null],
  ["foo@bar.c", null],                                // one-letter TLD
  ["+@bar.com", null],                                // no word character in the local part
  ["..@bar.com", null],
  ["a@b@c.com", "2:b@c.com"]
];

test("dlp-email: realistic addresses, handles, no-TLD and no-@ text match exactly as before", () => {
  for (const [s, want] of CASES) {
    assert.equal(first(OLD, s), want, `fixture drift: the OLD pattern on ${JSON.stringify(s.slice(0, 60))}`);
    assert.equal(first(RE, s), want, `dlp-email on ${JSON.stringify(s.slice(0, 60))}`);
  }
});

test("dlp-email: same first match as the pre-fix pattern on 200k seeded strings; /g differs only on glued addresses", () => {
  const toks = ["a", "b1", "_", ".", "+", "-", "@", " ", "com", "x.y", "é", ":", "..", "@x.io", ",", "<"];
  let x = 0x2545f491;
  const rnd = (n) => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return (x >>> 0) % n; };
  let diffs = 0, glued = 0;
  for (let i = 0; i < 200000; i++) {
    let s = "";
    while (s.length < 1 + (i % 34)) s += toks[rnd(toks.length)];
    assert.equal(first(RE, s), first(OLD, s), `first match differs on ${JSON.stringify(s)}`);
    const a = all(OLD, s), b = all(RE, s);
    if (JSON.stringify(a) === JSON.stringify(b)) continue;
    diffs++;
    // The documented /g difference: OLD restarted at lastIndex on a [.+-] glued to the previous match.
    const isGlued = a.some(([idx, t], k) => k > 0 && idx === a[k - 1][0] + a[k - 1][1].length && /^[.+-]/.test(t));
    assert.ok(isGlued, `/g differs on ${JSON.stringify(s)} without a glued address: ${JSON.stringify(a)} vs ${JSON.stringify(b)}`);
    glued++;
  }
  assert.equal(diffs, glued);
});
