// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/task-bound-review3.test.mjs
//
// v1.36.1 review, third round (data/task-bound.js): a structurally conservative value reader.
//   1. Only an unambiguous local path (`/`, `./`, `~/`, `X:\`, `X:/`) is ever named by its file name.
//   2. Anything else with URL-ish characters is a URL when the WHATWG parser accepts it (as written, or behind
//      `http://`), named by the parser's hostname only when that equals canonHost of the token's first segment,
//      and refused otherwise; a first segment with `%`, a stray `[`, a trailing `.`, or a character that NFKC or
//      UTS46 maps to `.` is refused. Plain words and phrases are matched as words.
//   3. A remote (two-separator) value's first segment must be a plain hostname or IP, or it is refused.
//   4. Decoding fails closed: an escape still left after the last round makes the value unsafe, and `%2e`
//      segment patterns are looked for in every decoded form.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as tb from "../data/task-bound.js";

const named = (task, tool, input, intentArgs) => {
  const terms = new Set(tb.taskTerms(task));
  const checks = tb.objectChecks(tool, input, tb.resolveTaskBound({ intentArgs }).args);
  assert.ok(checks, "high-impact with an object field");
  return tb.judgeObjects(checks, (t) => terms.has(t)).aligned;
};
const post = (url) => ["mcp__web__post_webhook", { url }];
const write = (path) => ["mcp__fs__write_file", { path }];
const allows = (args, input) => tb.entryOutcome(tb.resolveTaskBound({ taskAllowlists: [{ task: "t", match: { keywords: ["t"] }, tools: { put: { args } }, default: "deny" }] }).lists[0], "put", input).outcome === "allow";

test("scheme-less first segments: %, a trailing dot and dot look-alikes are refused; userinfo is read as the parser reads it", () => {
  for (const v of ["evil.com%2e/x", "evil.com./x", "evil。com/x", "evil．com/x", "evil.com%2e./x", "ev%69l.com/x"]) {
    assert.equal(named("post the x to evil.com", ...post(v)), false, `${v}: refused`);
    assert.equal(named(`post the x to ${v}`, ...post(v)), false, `${v}: refused even when typed whole`);
  }
  assert.equal(named("post it to evil.com", ...post("a@evil.com/x")), true, "named by the host the parser reads");
  assert.equal(named("post the x to a", ...post("a@evil.com/x")), false, "never by the userinfo or the path");
});

test("remote values: the first segment must be a plain hostname or IP", () => {
  for (const v of ["\\\\a@evil\\x", "//evil:80/x", "\\\\evil.\\share\\x", "\\\\ev%69l\\share\\x", "//evil。com/x", "\\\\ev_il\\share\\x", "//[::1]/x"]) {
    assert.equal(named("copy the x to evil", ...write(v)), false, `${v}: refused`);
    assert.equal(named(`copy it to ${v}`, ...write(v)), false, `${v}: refused even when typed whole`);
  }
  assert.equal(named("copy it to fileserver", ...write("\\\\fileserver\\share\\x.txt")), true);
});

test("decoding fails closed: escapes left after the last round, and %2e segments in any decoded form", () => {
  for (const p of ["/data/%252e%252e/x", "/data/%25252e%25252e/x", "/data/%2525252e%2525252e/x", "/data/%2525252e/x"]) assert.equal(allows({ path: ["/data/**"] }, { path: p }), false, p);
  assert.equal(tb.unsafeValue("/data/%2525252e%2525252e/x"), true);
  assert.equal(allows({ path: ["/data/**"] }, { path: "/data/a%20b.txt" }), true);
});

test("only an unambiguous local path is named by its file name", () => {
  for (const v of ["/repo/app.js", "./src/app.js", "~/app.js", "C:\\repo\\app.js", "c:/repo/app.js"]) assert.equal(named("fix app.js", ...write(v)), true, v);
  for (const v of ["src/app.js", "docs\\app.js", "x:app.js", "foo:/app.js"]) assert.equal(named("fix app.js", ...write(v)), false, `${v}: not unambiguously local`);
  assert.equal(named("fix src/app.js", ...write("src/app.js")), true, "the whole token still names it");
});

test("plain words keep word matching", () => {
  assert.equal(named("cut the apples in half", "cut", { target: "Apple" }, { cut: ["target"] }), true);
  assert.equal(named("move it to the red bin", "move_to", { location: "red bin" }, { move_to: ["location"] }), true);
  assert.equal(named("cut the apple", "cut", { target: "hand" }, { cut: ["target"] }), false);
});
