// data/detector-packs.js compiles org-supplied pattern STRINGS from the policy server. It used to
// carry its own `redosProne`/`safePattern` pair, which is now replaced by the shared guard in
// src/safe-regex.js — the same one decideMcpArgs() uses.
//
// The old pair let three catastrophic families through and falsely refused one safe pattern. Both
// halves are asserted here on MEASURED milliseconds, because a gate that "looks right" but still
// compiles a catastrophic pattern is worth nothing.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { compilePacks } from "../data/detector-packs.js";

const ms = (fn) => { const t0 = process.hrtime.bigint(); fn(); return Number(process.hrtime.bigint() - t0) / 1e6; };

// The OLD guard, copied verbatim from data/detector-packs.js as it stood before this change, so the
// claim "it missed these" is checked against the real thing rather than remembered.
function oldRedosProne(src) {
  if (/\([^)]*[+*][^)]*\)\s*[+*]/.test(src)) return true;
  if (/[+*}]\s*[+*]/.test(src)) return true;
  return false;
}

const pack = (patterns, flags) => compilePacks([{
  packId: "p", detectors: [{ detectorId: "r", threatId: 1, patterns, flags }]
}]);

// Measured on node v22 / macOS arm64 via re.test(), compiled by the OLD guard:
//   "(a|a)+$"     vs 26 a's + "!"  →  7673 ms   (28144 ms at 29 a's)
//   "([a-z]|x)+$" vs 24 x's + "!"  →  1988 ms
//   ".*.*="       vs 2000 a's      →  1672 ms
const EVIL = [
  { pat: "(a|a)+$", input: "a".repeat(24) + "!", floor: 500 },
  { pat: "([a-z]|x)+$", input: "x".repeat(24) + "!", floor: 500 },
  { pat: ".*.*=", input: "a".repeat(1500), floor: 100 }
];

test("PACKS: the old guard really did miss these three families", () => {
  for (const { pat } of EVIL) {
    assert.equal(oldRedosProne(pat), false, `${pat} — if this ever becomes true the fixture is stale`);
  }
  assert.equal(oldRedosProne("(a+)+$"), true, "the old guard did catch nested quantifiers");
});

test("PACKS: each family is catastrophic when compiled — the bug, measured", () => {
  for (const { pat, input, floor } of EVIL) {
    const took = ms(() => new RegExp(pat).test(input));
    assert.ok(took > floor, `${pat} was expected to blow up, took only ${took}ms`);
  }
});

test("PACKS: compilePacks now refuses all three, and returns in single-digit ms", () => {
  for (const { pat, input } of EVIL) {
    const took = ms(() => {
      const out = pack([pat]);
      // Refused pattern → no patterns left → the detector is dropped entirely.
      assert.deepEqual(out, [], `${pat} still compiled into a detector`);
    });
    assert.ok(took < 50, `${pat} must be refused, not evaluated — took ${took}ms`);
    assert.ok(input.length > 0);
  }
});

test("PACKS: the old guard's false positive is gone — [*+]{3}x is data, not a quantifier", () => {
  assert.equal(oldRedosProne("[*+]{3}x"), true, "the old guard falsely refused it");
  const out = pack(["[*+]{3}x"]);
  assert.equal(out.length, 1, "the shared guard must compile it — the *+ is inside a character class");
  assert.equal(out[0].patterns[0].test("**+x"), true);
});

test("PACKS: legitimate org patterns still compile and still match", () => {
  const out = pack(["ACME-[0-9]{6}", "CUST_[A-Z]{3}\\d+", "(foo|bar)+$"]);
  assert.equal(out.length, 1);
  assert.equal(out[0].patterns.length, 3);
  assert.equal(out[0].patterns[0].test("ticket ACME-123456 here"), true);
  assert.equal(out[0].patterns[0].test("ticket ACME-12 here"), false);
});

test("PACKS: flags are still sanitized, not passed through to throw", () => {
  // An invalid flag makes RegExp throw, which would silently drop the whole pattern. The sanitizer
  // strips the bad character and keeps the good one, which is the pre-existing behavior.
  const out = pack(["ACME-[0-9]{6}"], "gx");
  assert.equal(out.length, 1, "a pattern must survive a sloppy flag string");
  assert.equal(out[0].patterns[0].flags, "g");
});

test("PACKS: pack patterns stay CASE-SENSITIVE by default", () => {
  // safeRegex() defaults to "i"; detector packs never did. If that default ever leaks in, every org
  // pattern silently widens.
  const out = pack(["SECRET"]);
  assert.equal(out[0].patterns[0].flags, "", "no flags should be applied by default");
  assert.equal(out[0].patterns[0].test("SECRET"), true);
  assert.equal(out[0].patterns[0].test("secret"), false, "the \"i\" default leaked in");
});
