// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/model-proxy-json-strict-fuzz.test.mjs
//
// Differential fuzz of model-proxy/json-strict.mjs's own scanner against JSON.parse, on generated inputs from
// a fixed seed (deterministic; a failure prints the seed index and the input). For every input:
//   * the scanner says valid exactly when JSON.parse does not throw;
//   * when valid, the value the scanner builds is deep-equal to JSON.parse's (every string and key decoded
//     the same: \u0000, \/, surrogate pairs and unpaired halves, every escape; numbers through the same
//     conversion, -0 included; a repeated key keeps the last value);
//   * for a generated (unmutated) document, `duplicate-key` and `key-collision` are flagged exactly when the
//     generator put a repeated or colliding key in one object.
import { test } from "node:test";
import assert from "node:assert/strict";
import { strictScan, MAX_DEPTH } from "../model-proxy/json-strict.mjs";

const CASES = 6000;
const SEED = 0x5eed1135;

function rng(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

function gen(r) {
  const pick = (a) => a[Math.floor(r() * a.length)];
  const int = (n) => Math.floor(r() * n);
  const ws = () => (r() < 0.7 ? "" : pick([" ", "\n", "\t", "\r", "  \n "]));
  const hex4 = (c) => c.toString(16).padStart(4, "0");
  const CHARS = ["a", "b", "c", "C", "é", "😀", " ", "\u007f", "ſ", "K", "/", "\u0000", "\ud800", "\udc00", "\ud83d", "\ude00", "\"", "\\", "\n", "\t", "\b", "\f", "\r", "\u001f"];
  // A JSON string literal for `v`, each character in one of its legal forms (raw where JSON allows it).
  const lit = (v) => {
    let out = "\"";
    for (const ch of v) {
      for (let k = 0; k < ch.length; k++) {
        const c = ch.charCodeAt(k), x = ch[k];
        const short = { "\"": "\\\"", "\\": "\\\\", "\n": "\\n", "\t": "\\t", "\b": "\\b", "\f": "\\f", "\r": "\\r", "/": "\\/" }[x];
        const forms = [`\\u${hex4(c)}`, `\\u${hex4(c).toUpperCase()}`];
        if (short) forms.push(short);
        if (c >= 0x20 && x !== "\"" && x !== "\\") forms.push(x, x, x);
        out += pick(forms);
      }
    }
    return out + "\"";
  };
  const str = () => { let s = ""; const n = int(5); for (let k = 0; k < n; k++) s += pick(CHARS); return s; };
  const NUMS = ["0", "-0", "1", "-1", "12", "1.5", "-0.25", "1e3", "1E-3", "2.5e+2", "9007199254740991", "9007199254740993", "-9007199254740992", "1e400", "-1e400", "1e-400", "123456789012345678901234567890", "0.1", "5e-324"];
  const expect = { dup: false, collide: false };
  function value(depth) {
    const t = depth > 6 ? int(4) : int(7);
    if (t === 0) return pick(NUMS);
    if (t === 1) return pick(["true", "false", "null"]);
    if (t <= 3) return lit(str());
    if (t === 4) { const n = int(4); const a = []; for (let k = 0; k < n; k++) a.push(ws() + value(depth + 1) + ws()); return `[${a.join(",")}]`; }
    const n = int(5), keys = [], parts = [];
    for (let k = 0; k < n; k++) {
      let key = r() < 0.25 && keys.length ? pick(keys) : r() < 0.2 && keys.length ? pick(keys).toUpperCase() : str();
      if (keys.includes(key)) expect.dup = true;
      else if (keys.some((x) => fold(x) === fold(key))) expect.collide = true;
      keys.push(key);
      parts.push(`${ws()}${lit(key)}${ws()}:${ws()}${value(depth + 1)}${ws()}`);
    }
    return `{${parts.join(",")}}`;
  }
  return { text: ws() + value(0) + ws(), expect };
}
// The test's own statement of what collides (kept independent of the module's helper).
const fold = (k) => k.split("\0")[0].replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, "�").toUpperCase().toLowerCase();

function mutate(r, s) {
  const SIG = ["{", "}", "[", "]", ",", ":", "\"", "\\", "u", "0", "-", ".", "e", " ", "t", "n", "NaN", "Infinity", "//", "/*", "'", "\u0000", "\u001f", "﻿"];
  let out = s;
  const m = 1 + Math.floor(r() * 3);
  for (let k = 0; k < m; k++) {
    const p = Math.floor(r() * (out.length + 1));
    const op = Math.floor(r() * 3);
    const ins = SIG[Math.floor(r() * SIG.length)];
    out = op === 0 ? out.slice(0, p) + ins + out.slice(p) : op === 1 ? out.slice(0, p) + out.slice(p + 1) : out.slice(0, p) + ins + out.slice(p + 1);
  }
  return out;
}

test(`json-strict scanner vs JSON.parse: ${CASES} generated inputs (seed ${SEED}) agree on validity and on every decoded value`, () => {
  const r = rng(SEED);
  let valid = 0, invalid = 0, dups = 0, collisions = 0;
  for (let n = 0; n < CASES; n++) {
    const { text: base, expect } = gen(r);
    const mutated = r() < 0.4;
    const text = mutated ? mutate(r, base) : base;
    let parsed, ok = true;
    try { parsed = JSON.parse(text); } catch { ok = false; }
    const scan = strictScan(text, { build: true });
    const where = `case ${n}${mutated ? " (mutated)" : ""}: ${JSON.stringify(text).slice(0, 400)}`;
    assert.equal(scan.valid, ok, where);
    if (!ok) { invalid++; assert.equal(scan.problem, "not-json", where); continue; }
    valid++;
    assert.deepStrictEqual(scan.value, parsed, where);
    if (!mutated) {
      assert.equal(scan.problems.has("duplicate-key"), expect.dup, `duplicate-key ${where}`);
      if (!expect.dup) assert.equal(scan.problems.has("key-collision"), expect.collide, `key-collision ${where}`);
      dups += expect.dup; collisions += expect.collide;
    }
  }
  // The generator must actually exercise both sides and the key conditions.
  assert.ok(valid > CASES / 3 && invalid > CASES / 10 && dups > 50 && collisions > 20, JSON.stringify({ valid, invalid, dups, collisions }));
});

test("json-strict scanner vs JSON.parse: hand-picked edges (escapes, depth, numbers, whitespace, BOM)", () => {
  const cases = ['"\\u0000"', '"\\/"', '"\\uD83D\\uDE00"', '"\\ud83d"', '{"a\\u0000b":1}', '{"":1,"":2}', "[]", "{}", " \t\n\r1 \t\n\r", "-0", "0.0e-0",
    "﻿{}", "{}\u0000", "01", "1.", ".1", "+1", "1e", "0x10", '"\\x41"', '"\\u12"', '"\t"', '" "', "nul", "true false", "[1,]", '{"a":1,}', "{'a':1}", "NaN", "Infinity", "-Infinity", "[1 2]", '{"a" 1}', '{"a":}', "", " "];
  for (const t of cases) {
    let ok = true, v;
    try { v = JSON.parse(t); } catch { ok = false; }
    const s = strictScan(t, { build: true });
    assert.equal(s.valid, ok, JSON.stringify(t));
    if (ok) assert.deepStrictEqual(s.value, v, JSON.stringify(t));
  }
  const deep = (d) => "[".repeat(d) + "]".repeat(d);
  assert.equal(strictScan(deep(MAX_DEPTH)).problem, null);
  assert.equal(strictScan(deep(MAX_DEPTH + 1)).problem, "too-deep");
  assert.equal(strictScan(deep(200000)).valid, true, "iterative: no stack overflow on very deep input");
});
