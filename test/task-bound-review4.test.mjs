// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/task-bound-review4.test.mjs
//
// v1.36.1 review, fourth round (data/task-bound.js):
//   1. A scheme-less value is host-led only when its first segment is a real host: a dotted name whose last label
//      is 2-63 letters, a dotted-quad IPv4 literal or a bracketed IPv6 literal. Anything else (`reports/x`, `a/b`,
//      userinfo, a port) is plain: named only by its whole token.
//   2. unsafeValue runs on every kind before any term: a `..` segment, a control character or a leftover escape
//      names nothing, whatever the kind.
//   3. A drive letter is local only as `X:\` / `X:/` not followed by another separator, and only under a key known
//      to hold a filesystem path; elsewhere it is plain.
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

test("host-led only for a real host first segment; anything else is plain (whole token only)", () => {
  assert.equal(named("send the reports", ...post("reports/x")), false, "reports is not a host");
  assert.equal(named("send x to b", ...post("a/b")), false, "plain: not named by a part");
  assert.equal(named("send it to a/b", ...post("a/b")), true, "plain: named by its whole token");
  assert.equal(named("post it to docs.example.com", ...post("docs.example.com/x")), true, "a dotted host with a letters-only last label");
  assert.equal(named("post it to example.com", ...post("docs.example.com/x")), true, "and its site");
  assert.equal(named("post it to 10.0.0.9", ...post("10.0.0.9/x")), true, "a dotted-quad IPv4");
  assert.equal(named("post it to 10.0.0.9", ...post("0x0a.0.0.9/x")), false, "a hex IPv4 form is not a literal: plain");
  assert.equal(named("post it to evil.com", ...post("a@evil.com/x")), false, "userinfo: plain");
  assert.equal(named("post it to evil.com", ...post("evil.com:8080/x")), false, "a port: plain");
  assert.equal(named("post it to v1.2", ...post("v1.2/x")), false, "a last label with a digit is not a host");
});

test("a .. segment, a control character or a leftover escape names nothing, on every kind", () => {
  for (const v of ["reports/../x", "../x", "./a/../x", "/repo/../x", "https://x.example/a/../b", "\\\\fileserver\\share\\..\\x", "evil.com/../x", "a/..%2fx", "a/%2e%2e/x", "x\u0000y", "a/%2525252e/x"]) {
    assert.equal(named(`write ${v} please`, ...write(v)), false, `${JSON.stringify(v)}: names nothing, even typed whole`);
  }
});

test("drive letters: local only as X:\\ or X:/ (not X://) and only under a filesystem-path key", () => {
  assert.equal(named("update notes.txt", ...write("C:\\docs\\notes.txt")), true, "under path: a local path, named by its file name");
  assert.equal(named("update notes.txt", "mcp__fs__write_file", { file_path: "c:/docs/notes.txt" }), true, "file_path too");
  assert.equal(named("update notes.txt", ...post("C:\\docs\\notes.txt")), false, "under url: plain");
  assert.equal(named("send C:\\docs\\notes.txt", ...post("C:\\docs\\notes.txt")), true, "plain: its whole token");
  assert.equal(named("fix the x", ...write("c://evil.com/x")), false, "X:// is not a drive path");
  assert.equal(named("fix the x", ...post("c://evil.com/x")), false);
});

test("schemed URLs: a host segment with %, a trailing dot or a dot look-alike names nothing, even typed whole", () => {
  for (const v of ["https://ev%69l.com/x", "https://evil.com./x", "https://evil。com/x", "https://evil．com/x"]) {
    assert.equal(named("post it to evil.com", ...post(v)), false, `${v}: not by the parser's host`);
    assert.equal(named(`post it to ${v}`, ...post(v)), false, `${v}: refused`);
  }
  assert.equal(named("post it to evil.com", ...post("https://evil.com/x")), true);
});
