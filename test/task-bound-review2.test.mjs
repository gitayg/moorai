// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/task-bound-review2.test.mjs
//
// v1.36.1 review, second round (data/task-bound.js): one reading per value.
//   1. A URL-shaped value (one with a scheme, or that the WHATWG parser accepts) is never named by a file name;
//      when the parser's host and the token reading disagree it names nothing. A scheme-less value led by a host
//      (with userinfo, an IPv4 address, or a `\` after the host) is read as a URL.
//   2. A value starting with two separators (`\\host\share`, `//host/x`, `\/`, `/\`) is remote: named by its whole
//      token or its host, never by a file name.
//   3. Percent-decoding is lenient (one valid %XX at a time), a malformed escape makes the value unsafe, and the
//      raw string is checked for `%2e` segment patterns.
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

test("URL-shaped values are never named by a file name", () => {
  const T = "post the status to apple.com";
  assert.equal(named(T, ...post("https:\\\\evil.com\\apple.com")), false, "special scheme with backslashes: the parser's host is evil.com");
  assert.equal(named(T, ...post("https:evil.com/apple.com")), false, "special scheme without slashes");
  assert.equal(named(T, ...post("foo:/x/apple.com")), false, "a scheme with no host: only the whole token");
  assert.equal(named(T, ...post("https://evil.com/apple.com")), false);
  assert.equal(named("post the status to https:evil.com/apple.com", ...post("https:evil.com/apple.com")), false, "parser and token reading disagree: names nothing, even typed whole");
  assert.equal(named("update the README", ...write("c:\\docs\\README.md")), false, "a drive letter parses as a scheme: whole token only");
  assert.equal(named("update c:\\docs\\README.md", ...write("c:\\docs\\README.md")), true, "the whole token still names it");
});

test("scheme-less host-led values: a backslash after the host, userinfo, an IPv4 host", () => {
  const T = "post the status to apple.com";
  assert.equal(named(T, ...post("evil.com\\apple.com")), false);
  assert.equal(named(T, ...post("user@evil.com/apple.com")), false);
  assert.equal(named(T, ...post("10.0.0.9/apple.com")), false);
  assert.equal(named("post the status to 10.0.0.9", ...post("10.0.0.9/status")), true);
  assert.equal(named(T, ...post("apple.com\\status")), true);
  assert.equal(named(T, ...post("0x0a.0.0.9/apple.com")), false, "a hex IPv4 the URL parser reads as 10.0.0.9");
  assert.equal(named("post the status to 10.0.0.9", ...post("0x0a.0.0.9/status")), true, "named by the host the parser reads");
});

test("UNC and double-separator paths are remote: whole token or host, never a file name", () => {
  const T = "copy it to apple.com";
  for (const v of ["\\\\evil.com\\share\\apple.com", "//evil.com/apple.com", "/\\evil.com/apple.com", "\\/evil.com/apple.com"]) assert.equal(named(T, ...write(v)), false, v);
  assert.equal(named("copy it to \\\\fileserver\\share\\notes.txt", ...write("\\\\fileserver\\share\\notes.txt")), true, "the whole token");
  assert.equal(named("copy it to fileserver.corp.example", ...write("\\\\fileserver.corp.example\\share\\x.txt")), true, "its host");
  assert.equal(named("update notes.txt", ...write("\\\\fileserver\\share\\notes.txt")), false, "never the file name");
});

test("decoding: lenient per %XX, a malformed escape is unsafe, raw %2e segments are caught", () => {
  for (const p of ["/data/%2e%2e/%ZZ", "/data/.%2E/x%ZZ", "/data/%2e./etc", "/data/x%ZZ", "/data/%%32%65%%32%65/etc", "/data/%252e%252e/%C3"]) assert.equal(allows({ path: ["/data/**"] }, { path: p }), false, p);
  assert.equal(allows({ path: ["/data/**"] }, { path: "/data/a%20b.txt" }), true, "a valid escape that decodes to nothing unsafe");
  assert.equal(named("update the README", ...write("/repo/%2e%2e/%zz/README.md")), false);
  assert.equal(named("update the README", ...write("/repo/docs/README.md")), true);
  assert.equal(tb.unsafeValue("50%"), true, "a % that is not an escape: decoding fails, so the value is unsafe");
});
