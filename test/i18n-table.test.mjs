// The multilingual injection table (data/injection-i18n.js, INJECTION_I18N_BY_LANG) and the flattened
// arrays data/detectors.js consumes. Pins that the arrays are exactly the table, that every language has
// an override pattern, which languages have NO reveal pattern (a ratchet), and pattern hygiene.
//
//   node --test test/i18n-table.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  INJECTION_I18N_BY_LANG, INJECTION_I18N_OVERRIDE, INJECTION_I18N_REVEAL, INJECTION_I18N, REVEAL_GAP
} from "../data/injection-i18n.js";
import { redosReason, unboundedQuantifiers, ambiguousQuantifiedAlternation } from "../src/safe-regex.js";

const LANGS = Object.entries(INJECTION_I18N_BY_LANG);

test("flattened exports equal the table, in table order", () => {
  const override = LANGS.flatMap(([, e]) => e.override);
  const reveal = LANGS.flatMap(([, e]) => e.reveal);
  assert.deepEqual(INJECTION_I18N_OVERRIDE, override);
  assert.deepEqual(INJECTION_I18N_REVEAL, reveal);
  assert.deepEqual(INJECTION_I18N, [...override, ...reveal]);
  // same RegExp objects, not equal copies
  override.forEach((r, i) => assert.equal(INJECTION_I18N_OVERRIDE[i], r));
  reveal.forEach((r, i) => assert.equal(INJECTION_I18N_REVEAL[i], r));
});

test("keys are lowercase English names and every entry has both lists", () => {
  for (const [k, e] of LANGS) {
    assert.match(k, /^[a-z]+(?:-[a-z]+)*$/, `bad key ${k}`);
    assert.ok(Array.isArray(e.override) && Array.isArray(e.reveal), `${k}: override/reveal must be arrays`);
    for (const r of [...e.override, ...e.reveal]) assert.ok(r instanceof RegExp, `${k}: non-RegExp entry`);
  }
});

test("every language has at least one override pattern", () => {
  for (const [k, e] of LANGS) assert.ok(e.override.length >= 1, `${k} has no override pattern`);
});

// RATCHET. The languages whose reveal list is empty: "reveal your system prompt" in one of them fires
// nothing. This list may only SHRINK. When you add a reveal pattern for one of these languages this test
// fails — remove that language from the list below in the same change.
const EXPECTED_REVEAL_GAP = [
  "arabic", "czech", "dutch", "finnish", "greek", "hindi", "hungarian", "indonesian-malay", "italian",
  "korean", "norwegian-danish", "persian", "polish", "portuguese", "romanian", "russian", "swedish",
  "thai", "turkish", "ukrainian", "vietnamese"
];

test("REVEAL_GAP ratchet: the reveal-gap languages are exactly the expected list", () => {
  const closed = EXPECTED_REVEAL_GAP.filter((k) => !REVEAL_GAP.includes(k));
  const opened = REVEAL_GAP.filter((k) => !EXPECTED_REVEAL_GAP.includes(k));
  assert.deepEqual(closed, [],
    `reveal gap CLOSED for [${closed.join(", ")}] — remove them from EXPECTED_REVEAL_GAP in test/i18n-table.test.mjs (the list only shrinks)`);
  assert.deepEqual(opened, [],
    `reveal gap OPENED for [${opened.join(", ")}] — a language lost its reveal pattern, or a new language was added without one`);
  assert.ok(Object.isFrozen(REVEAL_GAP));
  assert.deepEqual([...REVEAL_GAP], [...REVEAL_GAP].sort());
});

// Pattern hygiene, with the same src/safe-regex.js checks test/hebrew-injection.test.mjs applies.
// Hebrew: zero unbounded quantifiers, and redosReason may only be the policy-data length cap ("too-long",
// from the bounded niqqud classes). The one-line patterns of the other languages use `\s+` between words
// and so carry several unbounded quantifiers; safe-regex refuses that shape for policy DATA
// ("multiple-unbounded-quantifiers"), so for them that reason is tolerated here and linearity is instead
// measured on adversarial input below. No pattern may carry an ambiguous quantified alternation.
const isHebrew = (k) => k === "hebrew";

for (const [k, e] of LANGS) {
  test(`${k}: patterns pass the safe-regex shape checks`, () => {
    for (const p of [...e.override, ...e.reveal]) {
      assert.equal(ambiguousQuantifiedAlternation(p.source), false, `ambiguous alternation in ${p.source.slice(0, 60)}`);
      if (isHebrew(k)) {
        assert.equal(unboundedQuantifiers(p.source), 0, `unbounded quantifier in ${p.source.slice(0, 60)}`);
        assert.ok(["", "too-long"].includes(redosReason(p.source)), `redosReason=${redosReason(p.source)}`);
      } else {
        assert.ok(["", "multiple-unbounded-quantifiers"].includes(redosReason(p.source)),
          `redosReason=${redosReason(p.source)} for ${p.source.slice(0, 60)}`);
      }
    }
  });
}

test("every pattern stays linear on adversarial input (64 KB runs)", () => {
  const inputs = [" ".repeat(65536), "a ".repeat(32768), "\t\n".repeat(32768), "x".repeat(65536)];
  for (const [k, e] of LANGS) {
    for (const p of [...e.override, ...e.reveal]) {
      for (const s of inputs) {
        const t0 = process.hrtime.bigint();
        p.test(s);
        const ms = Number(process.hrtime.bigint() - t0) / 1e6;
        assert.ok(ms < 250, `${k}: ${ms.toFixed(1)} ms on a ${s.length}-char input for ${p.source.slice(0, 40)}`);
      }
    }
  }
});
