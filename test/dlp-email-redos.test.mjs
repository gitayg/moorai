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
// THE /g GAP, AND ITS FIX. Under /g (engine.redact) the lookbehind alone was not equivalent: a global search
// resumes at the previous match's end, and when the next address is glued to it by [.+-]
// ("a@b.com+c@d.com") the old pattern restarted right there, on the "+", and redacted "+c@d.com"; the
// lookbehind refuses every start of that run, so "+c@d.com" stayed visible (in a triple chain it even
// matched "d.com+e@f.org" instead). The pattern now carries `restart`, the pre-fix pattern, which
// engine.redact tries STICKY at each match's end before resuming the main search (src/regex-restart.js) —
// the one position the old pattern could use and the lookbehind refuses. MEASURED: 0 differences in /g
// matches against the old pattern over every tracked file and line, every JSON string leaf and the inbound
// corpus, and over 1M seeded glued strings (312,921 of them differed before the fix).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DETECTORS } from "../data/detectors.js";
import { DetectionEngine } from "../src/engine.js";
import { scalingRatio } from "./timing.mjs";
import { globalMatches } from "../src/regex-restart.js";

const threats = JSON.parse(readFileSync(new URL("../data/threats.json", import.meta.url), "utf8"));
const DET = DETECTORS.find((d) => d.detectorId === "dlp-email");
const [RE] = DET.patterns;
// The pre-fix pattern, frozen here so equivalence is checked against the real thing, not remembered.
const OLD = /\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b/;

const first = (re, s) => { const m = new RegExp(re.source, re.flags.replace("g", "")).exec(s); return m ? `${m.index}:${m[0]}` : null; };
const all = (re, s) => [...s.matchAll(new RegExp(re.source, re.flags.replace("g", "") + "g"))].map((m) => [m.index, m[0]]);
// The /g matches engine.redact walks: the main pattern plus its sticky restart.
const redactAll = (re, s) => [...globalMatches(re, new RegExp(re.source, re.flags.replace("g", "") + "g"), s)].map((m) => [m.index, m[0]]);
const oldEngine = () => new DetectionEngine(threats, [{ ...DET, patterns: [OLD] }], []);

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

test("dlp-email: engine.redact masks every address glued to the previous one by . + or -", () => {
  // Each expected output is what the pre-fix pattern's redact produced. Before the restart, the second (and
  // third) address stayed visible: "[REDACTED:#15]+c@d.com", and "[REDACTED:#15]+c@[REDACTED:#15]".
  const T = "[REDACTED:#15]";
  const e = new DetectionEngine(threats, [DET], []), o = oldEngine();
  const GLUED = [
    ["a@b.com+c@d.com", T + T],
    ["a@b.com+.c@d.com", T + T],
    ["a@b.com+-c@d.com", T + T],
    ["a@b.com.-+c@d.io", T + T],          // the domain gives back ".-": the old match restarted on the "."
    ["a@b.com-+c@d.io", T + T],           // ... and on the "-"
    ["a@b.com+c@d.com+e@f.org", T + T + T],
    ["x a@b.com.+c@d.io-+e@f.org y", `x ${T}${T}${T} y`],
    ["mail a@b.com+c@d.com, then x.y@z.io", `mail ${T}${T}, then ${T}`]
  ];
  for (const [s, want] of GLUED) {
    assert.equal(o.redact(s, "prompt"), want, `fixture drift: the OLD pattern's redact on ${JSON.stringify(s)}`);
    for (const st of ["prompt", "output"]) assert.equal(e.redact(s, st), want, `redact(${st}) on ${JSON.stringify(s)}`);
  }
});

// Seeded strings built from whole addresses glued by [.+-_@] runs (3 in 4) and from random tokens (1 in 4).
function seededEmails(n, seed, fn) {
  const inst = ["a@b.com", "x.y+z@d-e.co.uk", "c@d.io", "q_1@x.org", "b@c.de", "a.b@c.d.e", "A1@B2.CC", "a+@b.co", "-a@b.cd", "z@y.x-w.v"];
  const glue = [".", "+", "-", "_", "..", "+.", ".-", "@", "a", "1", " ", ",", "é", "", "", "", "-.+", "@x", ".com"];
  const toks = [...inst, ...glue];
  let x = seed;
  const rnd = (m) => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return (x >>> 0) % m; };
  for (let i = 0; i < n; i++) {
    let s = "";
    if (i % 4 === 3) while (s.length < 1 + (i % 40)) s += toks[rnd(toks.length)];
    else {
      const k = 2 + rnd(3);
      if (rnd(3) === 0) s += glue[rnd(glue.length)];
      for (let j = 0; j < k; j++) {
        if (j) { const g = rnd(4); for (let q = 0; q < (g === 3 ? 2 : g ? 1 : 0); q++) s += glue[rnd(glue.length)]; }
        s += inst[rnd(inst.length)];
      }
      if (rnd(3) === 0) s += glue[rnd(glue.length)];
    }
    fn(s);
  }
}

test("dlp-email: same first match and same /g matches as the pre-fix pattern on 200k seeded strings, glued addresses included", () => {
  let glued = 0;
  seededEmails(200000, 0x2545f491, (s) => {
    assert.equal(first(RE, s), first(OLD, s), `first match differs on ${JSON.stringify(s)}`);
    const a = all(OLD, s);
    if (a.some(([idx], k) => k > 0 && idx === a[k - 1][0] + a[k - 1][1].length)) glued++;
    assert.deepEqual(redactAll(RE, s), a, `/g matches differ on ${JSON.stringify(s)}`);
  });
  // MEASURED: 62,321 of the 200k carry an address the old pattern started right at the previous match's end,
  // and the /g matches of every one of them differed before the restart.
  assert.ok(glued > 10000, `the seeded strings must exercise glued addresses (got ${glued})`);
});

test("dlp-email: engine.redact output equals the pre-fix pattern's on 50k seeded glued strings", () => {
  const e = new DetectionEngine(threats, [DET], []), o = oldEngine();
  seededEmails(50000, 0x1b873593, (s) => {
    assert.equal(e.redact(s, "prompt"), o.redact(s, "prompt"), `redact differs on ${JSON.stringify(s)}`);
  });
});

test("REDOS: engine.redact stays linear on glued-address chains and on a long [.+-] tail after an address", () => {
  // The restart is one anchored attempt per match. MEASURED (CPU time, scalingRatio): 7.55-8.02x on these four
  // shapes (and 6.97-7.51x on the three above). Made unanchored (/g instead of sticky), it read 48.10x on "a@b.co+a.a.a…".
  const e = new DetectionEngine(threats, [DET], []);
  const SHAPES2 = {
    "a@b.com+": (n) => "a@b.com+".repeat(n / 8),
    "a@b.co+a.a.a…": (n) => "a@b.co+" + "a.".repeat(n / 2),
    "a@b.co+a+a+a…": (n) => "a@b.co+" + "a+".repeat(n / 2),
    "x@y.z.-+": (n) => "x@y.zz.-+".repeat(n / 9)
  };
  for (const [name, mk] of Object.entries(SHAPES2)) {
    const small = mk(7500), large = mk(60000);
    const r = scalingRatio(() => e.redact(small, "prompt"), () => e.redact(large, "prompt"));
    assert.ok(r.ratio < 20, `"${name}": 8x the input cost ${r.ratio.toFixed(2)}x (${r.small.toFixed(2)}ms → ${r.large.toFixed(2)}ms)`);
  }
});
