// Hostile-input tests for cli/sanitize.mjs. The inputs here are the anti-analysis payloads a hostile
// agent/model can seed into the on-device logs: raw ANSI escapes, zero-width / bidi-control Unicode,
// and malformed / oversize JSONL. Each assertion checks the payload is NEUTRALIZED or surfaced as a
// visible gap — never rendered raw, never able to crash or hang the parser. Hostile characters are
// written as \x / \u escapes so the invisible bytes survive editing intact.
//
//   node --test test/sanitize.test.mjs   (per-file runner only — never the whole suite)
import { test } from "node:test";
import assert from "node:assert/strict";
import { stripAnsi, neutralizeInvisible, sanitizeForDisplay, boundedParseJsonl } from "../cli/sanitize.mjs";

test("stripAnsi removes CSI colour and OSC hyperlink escapes", () => {
  assert.equal(stripAnsi("\x1b[31mRED\x1b[0m"), "RED");
  assert.equal(stripAnsi("\x1b[1;33;40mwarn\x1b[0m"), "warn");
  assert.equal(stripAnsi("\x1b]8;;http://evil\x07label\x1b]8;;\x07"), "label");
  assert.equal(stripAnsi("plain"), "plain");
  assert.ok(!stripAnsi("\x1b[2J\x1b[Hhome").includes("\x1b"), "no ESC byte survives");
});

test("neutralizeInvisible removes zero-width, bidi-control, BOM, soft-hyphen and C0/C1 controls", () => {
  assert.equal(neutralizeInvisible("a​b"), "ab", "ZWSP");
  assert.equal(neutralizeInvisible("a‎‏b"), "ab", "LRM/RLM");
  assert.equal(neutralizeInvisible("a‮b"), "ab", "RLO bidi override");
  assert.equal(neutralizeInvisible("a⁦b⁩c"), "abc", "bidi isolates");
  assert.equal(neutralizeInvisible("﻿x­y᠎z"), "xyz", "BOM/soft-hyphen/MVS");
  assert.equal(neutralizeInvisible("a\x00\x07\x1bb"), "ab", "C0 NUL/BEL/ESC");
  assert.equal(neutralizeInvisible("a\x9bb"), "ab", "C1 CSI");
  assert.equal(neutralizeInvisible("a\tb\nc"), "a\tb\nc", "tab and newline are preserved");
});

test("sanitizeForDisplay composes strip+neutralize, and coerces non-strings without throwing", () => {
  assert.equal(sanitizeForDisplay("\x1b[31mcl​aude\x1b[0m"), "claude");
  assert.equal(sanitizeForDisplay(null), "");
  assert.equal(sanitizeForDisplay(undefined), "");
  assert.equal(sanitizeForDisplay(42), "42");
  assert.equal(sanitizeForDisplay({}), "[object Object]");
  const hostileToString = { toString() { throw new Error("boom"); } };
  assert.doesNotThrow(() => sanitizeForDisplay(hostileToString), "a throwing toString must degrade, not propagate");
  assert.equal(sanitizeForDisplay(hostileToString), "");
});

test("sanitizeForDisplay hard-caps length with an explicit truncated marker", () => {
  const out = sanitizeForDisplay("x".repeat(5000));
  assert.ok(out.length <= 2048 + "…[truncated]".length, "capped near 2048");
  assert.ok(out.endsWith("…[truncated]"), "explicit truncated marker present");
  assert.equal(sanitizeForDisplay("x".repeat(2048)).endsWith("…[truncated]"), false, "exactly at cap is not marked");
});

test("boundedParseJsonl parses valid lines and surfaces a malformed line as a TRACE_GAP", () => {
  const text = ['{"a":1}', "THIS IS NOT JSON {broken", '{"b":2}'].join("\n");
  const { records, gaps } = boundedParseJsonl(text);
  assert.deepEqual(records, [{ a: 1 }, { b: 2 }], "the good lines still parse");
  assert.equal(gaps.length, 1, "one gap");
  assert.equal(gaps[0].type, "TRACE_GAP");
  assert.equal(gaps[0].reason, "malformed JSON");
  assert.equal(gaps[0].index, 1, "gap points at the offending line index");
});

test("boundedParseJsonl gaps an oversize line and respects maxLines, never throwing", () => {
  const over = boundedParseJsonl('{"a":1}\n' + "z".repeat(500), { maxLineBytes: 10 });
  assert.deepEqual(over.records, [{ a: 1 }]);
  assert.equal(over.gaps[0].reason, "line exceeded maxLineBytes");

  const many = boundedParseJsonl(['{"a":1}', '{"b":2}', '{"c":3}'].join("\n"), { maxLines: 2 });
  assert.equal(many.records.length, 2);
  assert.equal(many.gaps.some((g) => g.reason === "exceeded maxLines"), true);

  assert.doesNotThrow(() => boundedParseJsonl(null));
  assert.doesNotThrow(() => boundedParseJsonl(12345));
});
