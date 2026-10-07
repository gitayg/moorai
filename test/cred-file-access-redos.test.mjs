// cred-file-access's bare-path pattern must cost linear time on long slash/tilde runs, and match exactly
// what it matched before.
//
// THE BUG. /[~\/][^\s"']*\.aws[\/\\]credentials\b/i — the same shape as dlp-email's: every "~" or "/" was
// a start, `[^\s"']*` ran to the end of the whitespace-free run, then gave back one character at a time
// looking for ".aws". MEASURED, `.test()`: "a/" repeated 68ms at 15k, 1470ms at 60k, 5884ms at 120k; "~"
// repeated 109 / 1690 / 6768ms; "/.aws/" repeated 41 / 637 / 2550ms. A long path list, a minified bundle or
// a URL-heavy page reaches it, on prompt and output.
//
// THE FIX. `(?<![~\/][^\s"']*?)` — a match may only start at the FIRST "~" or "/" of a run, the one start
// that could ever win (any later start in the run reaches the same ".aws/credentials", and the greedy body
// already ends at the run's last one). The lookbehind is lazy, so it walks back only to the previous "~"
// or "/": linear. now: 0.04ms at 15k, 0.18ms at 60k, 0.34ms at 120k on "a/". (A GREEDY lookbehind walks
// back to the run's start from every "/" and is quadratic again: 423ms at 60k.)
// MEASURED: no difference, first match or /g, against the old pattern over every tracked file, every JSON
// string leaf, the inbound corpus and the node_modules texts (192 /g matches), nor on 400k fuzzed strings.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DETECTORS } from "../data/detectors.js";
import { DetectionEngine } from "../src/engine.js";
import { scalingRatio } from "./timing.mjs";

const threats = JSON.parse(readFileSync(new URL("../data/threats.json", import.meta.url), "utf8"));
const DET = DETECTORS.find((d) => d.detectorId === "cred-file-access");
const RE = DET.patterns.find((p) => p.source.endsWith(String.raw`[^\s"']*\.aws[\/\\]credentials\b`));
// The pre-fix pattern, frozen here so equivalence is checked against the real thing, not remembered.
const OLD = /[~\/][^\s"']*\.aws[\/\\]credentials\b/i;

const first = (re, s) => { const m = new RegExp(re.source, re.flags.replace("g", "")).exec(s); return m ? `${m.index}:${m[0]}` : null; };
const all = (re, s) => JSON.stringify([...s.matchAll(new RegExp(re.source, re.flags.replace("g", "") + "g"))].map((m) => [m.index, m[0]]));

const SHAPES = { "a/": (n) => "a/".repeat(n / 2), "~": (n) => "~".repeat(n), "/.aws/": (n) => "/.aws/".repeat(n / 6) };

test("REDOS: cred-file-access's ~/.aws/credentials pattern scales linearly (8x the input, < 20x the cost)", () => {
  // MEASURED (CPU time, scalingRatio): new 7.47-8.43x across the three shapes; the old pattern read 87.21x
  // on "a/" (17.40ms → 1517.12ms). Linear ~8x, quadratic ~64x.
  assert.ok(RE, "the bare ~/.aws/credentials pattern is gone from cred-file-access");
  for (const [name, mk] of Object.entries(SHAPES)) {
    const small = mk(7500), large = mk(60000);
    const r = scalingRatio(() => RE.test(small), () => RE.test(large));
    assert.ok(r.ratio < 20, `"${name}": 8x the input cost ${r.ratio.toFixed(2)}x (${r.small.toFixed(2)}ms → ${r.large.toFixed(2)}ms) — linear ~8x, quadratic ~64x`);
  }
});

test("REDOS: engine.redact over cred-file-access scales linearly too", () => {
  // MEASURED: new 7.87-8.04x; the old pattern read 82.51x (18.52ms → 1528.18ms).
  const e = new DetectionEngine(threats, [DET], []);
  const small = SHAPES["a/"](7500), large = SHAPES["a/"](60000);
  const r = scalingRatio(() => e.redact(small, "prompt"), () => e.redact(large, "prompt"));
  assert.ok(r.ratio < 20, `redact: 8x the input cost ${r.ratio.toFixed(2)}x (${r.small.toFixed(2)}ms → ${r.large.toFixed(2)}ms)`);
});

// Pinned first matches, each one what the pre-fix pattern returns.
const CASES = [
  ["cat ~/.aws/credentials", "4:~/.aws/credentials"],
  ["open /home/me/.aws/credentials now", "5:/home/me/.aws/credentials"],
  ["x/y/.aws/credentials and /z/.aws/credentials", "1:/y/.aws/credentials"],
  ["/a/.aws/credentials/b/.aws/credentials", "0:/a/.aws/credentials/b/.aws/credentials"], // greedy: last in the run
  ["~/.AWS\\Credentials", "0:~/.AWS\\Credentials"],
  ["'/root/.aws/credentials'", "1:/root/.aws/credentials"],
  ["~" + "/x".repeat(300) + "/.aws/credentials", "0:~" + "/x".repeat(300) + "/.aws/credentials"],
  [".aws/credentials", null],                         // no leading ~ or /
  ["C:\\Users\\me\\.aws\\credentials", null],         // backslash-only path: never matched
  ["~/.aws/config", null],
  ["~/.aws/credentials_backup", null],                // \b
  ["a/".repeat(5000), null]
];

test("cred-file-access: credential paths and near misses match exactly as before", () => {
  for (const [s, want] of CASES) {
    assert.equal(first(OLD, s), want, `fixture drift: the OLD pattern on ${JSON.stringify(s.slice(0, 60))}`);
    assert.equal(first(RE, s), want, `cred-file-access on ${JSON.stringify(s.slice(0, 60))}`);
  }
});

test("cred-file-access: same first match and same /g matches as the pre-fix pattern on 200k seeded strings", () => {
  const toks = ["~", "/", "\\", ".aws", "/credentials", "\\credentials", "credentials", "x", " ", "'", "\"", ".", "a", "CREDENTIALS", ".AWS"];
  let x = 0x1b873593;
  const rnd = (n) => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return (x >>> 0) % n; };
  for (let i = 0; i < 200000; i++) {
    let s = "";
    while (s.length < 1 + (i % 40)) s += toks[rnd(toks.length)];
    assert.equal(first(RE, s), first(OLD, s), `first match differs on ${JSON.stringify(s)}`);
    assert.equal(all(RE, s), all(OLD, s), `/g matches differ on ${JSON.stringify(s)}`);
  }
});
