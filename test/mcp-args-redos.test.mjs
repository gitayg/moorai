// FIX 3 — ReDoS via a policy-supplied regex in decideMcpArgs().
//
// policy.mcpToolRules[tool].deny/allow are pattern STRINGS the console ships; they used to go straight
// into `new RegExp(p, "i")` with no gate at all, so one crafted pattern hung every MCP tool call on
// the device. data/detector-packs.js gated server-supplied DETECTOR patterns, but its two shape rules
// missed the overlapping-alternation family — verified here, not assumed.
//
// These assert on MEASURED milliseconds, not on the shape of the pattern: a gate that "looks right"
// but still lets a catastrophic pattern compile is worth nothing.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { decideMcpArgs, redosReason, safeRegex } from "../cli/hook-core.mjs";
import { ABS_SKIP, bestMs, scalingRatio } from "./timing.mjs";

const ms = (fn) => { const t0 = process.hrtime.bigint(); fn(); return Number(process.hrtime.bigint() - t0) / 1e6; };

// The detector-pack guard, copied here VERBATIM as a fixture so the claim "it missed this shape" is
// checked against the real thing rather than remembered. data/detector-packs.js has since been pointed
// at safeRegex(), so this fixture is now the historical record of why; test/detector-packs-redos.test.mjs
// carries the same fixture and measures the switchover.
function packsRedosProne(src) {
  if (/\([^)]*[+*][^)]*\)\s*[+*]/.test(src)) return true;
  if (/[+*}]\s*[+*]/.test(src)) return true;
  return false;
}

// Measured on node v22 / macOS arm64 with `re.test()`:
//   "(a+)+$"   vs 31 a's + "!"  →  56402 ms   (the pack guard DOES catch this one)
//   "(a|a)+$"  vs 29 a's + "!"  →  28144 ms   (the pack guard does NOT)
const EVIL = "(a|a)+$";
const EVIL_INPUT = "a".repeat(29) + "!";

test("REDOS: the detector-pack guard really does miss the overlapping-alternation family", () => {
  assert.equal(packsRedosProne("(a+)+$"), true, "the pack guard should still catch nested quantifiers");
  assert.equal(packsRedosProne(EVIL), false, "if this ever becomes true, the shared guard can be simplified");
  assert.equal(packsRedosProne("(a|aa)+$"), false);
  assert.equal(packsRedosProne(".*.*="), false);
});

test("REDOS: the unguarded compile is catastrophic — the bug, measured", () => {
  // The pre-fix line was `new RegExp(p, "i")`. Reproduced directly rather than described, at a length
  // trimmed so the suite does not sit for 28 seconds: 24 a's is already far past any sane budget.
  const re = new RegExp(EVIL, "i");
  const took = ms(() => re.test("a".repeat(24) + "!"));
  assert.ok(took > 1000, `expected the unguarded pattern to blow up, took only ${took}ms`);
});

test("REDOS: decideMcpArgs refuses the same pattern and returns in single-digit ms", () => {
  const policy = { mcpToolRules: { echo: { deny: [EVIL] } } };
  const took = ms(() => decideMcpArgs(policy, "echo", EVIL_INPUT));
  assert.ok(took < 50, `the gate must refuse, not evaluate — took ${took}ms`);
  assert.equal(redosReason(EVIL), "ambiguous-alternation");
  assert.equal(safeRegex(EVIL), null);
});

test("REDOS: the polynomial family is refused too — measured before, bounded after", () => {
  // ".*.*=" vs 1000 a's measured at 188 ms and vs 4000 a's at 8546 ms; "a.*a.*a.*=" vs 1000 a's at
  // 55990 ms. Neither is caught by the pack guard, and neither is a "nested quantifier".
  const slow = ms(() => new RegExp(".*.*=", "i").test("a".repeat(1200)));
  assert.ok(slow > 100, `expected the unguarded polynomial pattern to be slow, took ${slow}ms`);

  const policy = { mcpToolRules: { echo: { deny: [".*.*=", "a.*a.*a.*="] } } };
  const took = ms(() => decideMcpArgs(policy, "echo", "a".repeat(1200)));
  assert.ok(took < 50, `the gate must refuse both, took ${took}ms`);
});

test("REDOS: an alternation branch that is a CHARACTER CLASS overlaps too", () => {
  // Found while auditing the gate's own first draft, which special-cased `(a|a)+` but let
  // `([a-z]|x)+` through: one unbounded quantifier, no nesting, and branches that overlap on every
  // letter. Measured at 1892 ms against just 24 x's, so it is the same family, not a near miss.
  const slow = ms(() => new RegExp("([a-z]|x)+$", "i").test("x".repeat(24) + "!"));
  assert.ok(slow > 500, `expected the class-branch pattern to blow up, took ${slow}ms`);
  for (const p of ["([a-z]|x)+$", "(\\w|a)+$", "(a|[a])+$"]) {
    assert.equal(redosReason(p), "ambiguous-alternation", `${p} slipped through`);
  }
  const took = ms(() => decideMcpArgs({ mcpToolRules: { echo: { deny: ["([a-z]|x)+$"] } } }, "echo", "x".repeat(24) + "!"));
  assert.ok(took < 50, `the gate must refuse it, took ${took}ms`);
});

test("REDOS: real-world deny patterns are NOT refused — the gate must not disarm itself", () => {
  for (const p of ["BLOCKME", "AKIA[0-9A-Z]{16}", "password", "secret.*token", "(foo|bar)+$", "[A-Za-z0-9]{20,}", "^https?://internal\\.example\\.com/", "[*+]{3}x"]) {
    assert.equal(redosReason(p), "", `${p} was refused but is safe`);
  }
  // ...and they still enforce.
  assert.equal(decideMcpArgs({ mcpToolRules: { echo: { deny: ["BLOCKME"] } } }, "echo", '{"msg":"please BLOCKME"}').decision, "deny");
  assert.equal(decideMcpArgs({ mcpToolRules: { echo: { deny: ["BLOCKME"] } } }, "echo", '{"msg":"fine"}').decision, "allow");
  assert.equal(decideMcpArgs({ mcpToolRules: { echo: { allow: ["^\\{\"msg\""] } } }, "echo", '{"msg":"ok"}').decision, "allow");
  assert.equal(decideMcpArgs({ mcpToolRules: { echo: { allow: ["^\\{\"msg\""] } } }, "echo", '{"other":1}').decision, "deny");
});

test("REDOS: a refused ALLOW pattern fails CLOSED, a refused DENY pattern is dropped", () => {
  // The pre-existing semantics of an uncompilable pattern, preserved deliberately: an allow-list that
  // cannot be evaluated denies (safe), a deny rule that cannot be evaluated stops enforcing (the cost
  // of the gate, and the reason the gate must not over-reject).
  assert.equal(decideMcpArgs({ mcpToolRules: { echo: { allow: [EVIL] } } }, "echo", "anything").decision, "deny");
  assert.equal(decideMcpArgs({ mcpToolRules: { echo: { deny: [EVIL] } } }, "echo", EVIL_INPUT).decision, "allow");
});

test("REDOS: a huge argument is bounded for quantifier-bearing patterns, unbounded for literals", () => {
  // A pattern that survives the gate is still O(n²) because .test() retries at every start position:
  // "a*b" vs 50 KB measured at 905 ms. The 16 KB scan window keeps that under ~100 ms, and applies
  // ONLY to quantifier-bearing patterns — a literal is linear and gets the whole argument.
  //
  // WAS AN ABSOLUTE WALL-CLOCK ASSERTION (`took < 500`, one 200 KB call), AND IT FAILED ON THE RUNNER, NOT
  // THE CODE: 609.7ms in the v1.4.2 CI run and 529-848ms in 11 of 11 runs under local CPU contention,
  // against 105ms idle on an M-series Mac. The bounded path IS a quadratic scan of 16 KB, so its absolute
  // cost tracks the machine, not the bound. The claim is now a SCALING RATIO measured in this process
  // (test/timing.mjs scalingRatio, CPU time): the same pattern against 4x the window (64 KB) must cost
  // about what it costs against exactly the window (16 KB), because both are cut to 16 KB. MEASURED:
  //   bounded (this code)                    0.97-1.01x idle; 0.67-1.03x under CPU contention
  //   unbounded (window removed: the break)  15.08x idle (101ms → 1526ms); 14.35x under contention
  // The bound is 4: ~4x above the worst bounded reading, ~3.6x below the unbounded one. WHAT THIS GIVES UP:
  // no absolute ceiling on the 16 KB window's own cost by default — a slower regex engine passes, and so
  // does the window raised to ~30 KB ((30/16)² = 3.5x); the absolute budget survives as the opt-in test
  // below, at the original 500ms.
  const big = "a".repeat(200000);
  const policy = { mcpToolRules: { echo: { deny: ["a*b"] } } };
  const atWindow = "a".repeat(16384), past = "a".repeat(65536);
  const r = scalingRatio(() => decideMcpArgs(policy, "echo", atWindow), () => decideMcpArgs(policy, "echo", past));
  assert.ok(r.ratio < 4,
    `a quantifier-bearing pattern must be scan-bounded: 4x the input cost ${r.ratio.toFixed(2)}x (${r.small.toFixed(1)}ms at 16 KB → ${r.large.toFixed(1)}ms at 64 KB); unbounded reads ~16x`);

  // The cost of that window, stated rather than hidden: a quantifier-bearing pattern cannot match past
  // 16 KB. A literal one still can, which is what real deny rules are.
  assert.equal(decideMcpArgs({ mcpToolRules: { echo: { deny: ["z+!"] } } }, "echo", big + "zzz!").decision, "allow");
  assert.equal(decideMcpArgs({ mcpToolRules: { echo: { deny: ["zzz!"] } } }, "echo", big + "zzz!").decision, "deny");
});

// The original absolute budget, kept OPT-IN (see test/timing.mjs): set MOORAI_PERF_ABS=1 on an idle machine.
test("REDOS: a huge argument's quantifier-bearing scan stays inside its absolute budget (opt-in: MOORAI_PERF_ABS=1)", { skip: ABS_SKIP }, () => {
  const quantified = bestMs(() => decideMcpArgs({ mcpToolRules: { echo: { deny: ["a*b"] } } }, "echo", "a".repeat(200000)));
  assert.ok(quantified < 500, `a quantifier-bearing pattern must be scan-bounded, took ${quantified}ms`);
});
