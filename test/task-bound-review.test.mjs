// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/task-bound-review.test.mjs
//
// v1.36.1 security review of data/task-bound.js: every place where this module's reading of a value can differ
// from what the tool (or fetch) receives.
//   1. URL hosts come from WHATWG URL parsing and must agree with the token reading, or the value names nothing:
//      `https://evil.com\@apple.com/` is evil.com, not apple.com.
//   2. Allowlist values are matched raw (fold only for keys an entry marks), globs do not cross `/` unless `**`,
//      and a value with a `..` segment (raw or percent-decoded), a control or a format character is refused.
//   3. An explicit task id only adds entries: keyword-matched entries still apply, strictest wins.
//   4. The rest of the pass: allowlist tool names are exact (no case folding, no bare name for an MCP tool),
//      synonyms expand on whole values only, negative and zero-padded amounts are not caps or task numbers,
//      phrases do not cross sentence punctuation, and a path with traversal or control characters names nothing
//      but itself.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as tb from "../data/task-bound.js";

const named = (task, tool, input, intentArgs) => {
  const terms = new Set(tb.taskTerms(task));
  const checks = tb.objectChecks(tool, input, tb.resolveTaskBound({ intentArgs }).args);
  assert.ok(checks, "high-impact with an object field");
  return tb.judgeObjects(checks, (t) => terms.has(t)).aligned;
};
const hook = (url) => ["mcp__web__post_webhook", { url }];
const entry = (args, extra = {}) => tb.resolveTaskBound({ taskAllowlists: [{ task: "t", match: { keywords: ["t"] }, tools: { put: { args } }, default: "deny", ...extra }] }).lists[0];
const allows = (args, input, extra) => tb.entryOutcome(entry(args, extra), "put", input).outcome === "allow";

// ---- 1. URL hosts ----

test("URL: a backslash before @ is a path separator to WHATWG — the host is evil.com", () => {
  assert.equal(named("post the status to apple.com", ...hook("https://evil.com\\@apple.com/")), false);
  assert.equal(named("post the status to evil.com", ...hook("https://evil.com\\@apple.com/")), true, "the host the request goes to");
});

test("URL: userinfo stops at # and ? — `https://apple.com#@evil.com` goes to apple.com", () => {
  assert.equal(named("post the status to evil.com", ...hook("https://apple.com#@evil.com")), false);
  assert.equal(named("post the status to evil.com", ...hook("https://apple.com?@evil.com")), false);
  assert.equal(named("post the status to apple.com", ...hook("https://apple.com?@evil.com")), true);
});

test("URL: @ in a path is not userinfo", () => {
  assert.equal(named("post the status to apple.com", ...hook("https://apple.com/@evil.com")), true);
  assert.equal(named("post the status to evil.com", ...hook("https://apple.com/@evil.com")), false);
});

test("URL: IDN hosts compare in their punycode form; a homograph is another host", () => {
  assert.equal(named("upload it to bücher.de", ...hook("https://bücher.de/x")), true);
  assert.equal(named("upload it to bücher.de", ...hook("https://xn--bcher-kva.de/y")), true, "the same host, ASCII form");
  assert.equal(named("post the status to apple.com", ...hook("https://аpple.com/")), false, "Cyrillic а");
  assert.equal(named("post the status to apple.com", ...hook("https://apple.com／@evil.com")), false, "a fullwidth solidus is not a separator to the parser");
});

test("URL: IPv6 literals; an unparseable URL names nothing", () => {
  assert.equal(named("send it to http://[::1]:8080/in", ...hook("http://[::1]:9090/x")), true);
  assert.equal(named("send it to http://[::1]:8080/in", ...hook("http://[::2]/x")), false);
  assert.equal(named("post the status to apple.com", ...hook("https://apple.com:99999/")), false, "an invalid port: fetch refuses it, so it names nothing");
  assert.equal(named("post the status to https://apple.com:99999/", ...hook("https://apple.com:99999/")), false, "not even when the task has the same string");
  assert.equal(named("post the status to apple.com", ...hook("git://apple.com\\@evil.com/x")), false, "a non-special scheme: the parser reads evil.com, the token reading apple.com — they disagree, so it names nothing");
  assert.equal(named("post the status to apple.com", ...hook("https://apple.com/x\u0000y")), false, "a control character anywhere in a URL");
});

test("URL: a missing scheme — a host-led value is read as a URL, not a path whose file name is in the task", () => {
  assert.equal(named("post the status to apple.com", ...hook("evil.com/apple")), false);
  assert.equal(named("post the status to apple.com", ...hook("//evil.com/apple.com")), false, "protocol-relative");
  assert.equal(named("post the status to apple.com", ...hook("apple.com/status")), true);
});

// ---- 2. allowlist values ----

test("allowlist glob: * stops at /, ** crosses segments", () => {
  assert.equal(allows({ path: ["/data/*"] }, { path: "/data/a.txt" }), true);
  assert.equal(allows({ path: ["/data/*"] }, { path: "/data/sub/a.txt" }), false);
  assert.equal(allows({ path: ["/data/**"] }, { path: "/data/sub/a.txt" }), true);
  assert.equal(allows({ path: ["/data/*.txt"] }, { path: "/data/x/../y.txt" }), false);
});

test("allowlist: a .. segment, raw, with backslashes or percent-encoded, is refused", () => {
  for (const p of ["/data/../etc/passwd", "/data/sub/..", "/data\\..\\etc\\passwd", "/data/%2e%2e/etc/passwd", "/data/%2E%2E/etc", "/data/%252e%252e/etc"]) {
    assert.equal(allows({ path: ["/data/**"] }, { path: p }), false, p);
  }
  assert.equal(allows({ path: ["/data/**"] }, { path: "/data/a..b/c" }), true, "two dots inside a name are not a segment");
});

test("allowlist: NUL, control and format characters are refused", () => {
  assert.equal(allows({ target: ["app*"] }, { target: "apple\u0000x" }), false);
  assert.equal(allows({ target: ["ap*"] }, { target: "ap​ple" }), false);
  assert.equal(allows({ target: ["app*"] }, { target: "apple%00" }), false, "percent-encoded NUL");
});

test("allowlist: values match raw; only keys an entry marks (foldArgs) are case- and Unicode-folded", () => {
  assert.equal(allows({ target: ["apple"] }, { target: "apple" }), true);
  assert.equal(allows({ target: ["apple"] }, { target: "APPLE" }), false);
  assert.equal(allows({ target: ["apple"] }, { target: "ａｐｐｌｅ" }), false, "fullwidth");
  assert.equal(allows({ target: ["apple"] }, { target: "apple " }), false, "no trimming");
  assert.equal(allows({ target: ["apple"] }, { target: "APPLE" }, { foldArgs: ["target"] }), true);
  assert.equal(allows({ target: ["apple"] }, { target: "ａｐｐｌｅ" }, { foldArgs: ["target"] }), true);
  assert.equal(tb.entryOutcome(entry({ target: ["apple"] }, { foldArgs: "target" }), "put", { target: "apple" }).reason, "invalid-policy");
});

test("allowlist numbers: a JSON number or a plain decimal string; ranges start at 0 unless min is set", () => {
  const r = { amount: [{ max: 500 }] };
  assert.equal(allows(r, { amount: 100 }), true);
  assert.equal(allows(r, { amount: "100" }), true);
  for (const v of ["100 ", " 100", "0100", "1e2", "$100", "1,00", "0x64", "Infinity", -5, "-5"]) assert.equal(allows(r, { amount: v }), false, JSON.stringify(v));
  assert.equal(allows({ amount: [{ min: -10, max: 500 }] }, { amount: -5 }), true, "an explicit min allows negatives");
  assert.equal(allows({ amount: [100] }, { amount: "100.0" }), true, "a plain decimal string equal to the number");
});

// ---- 3. task ids only add ----

test("task id: id-selected entries apply TOGETHER with keyword-matched ones, strictest wins", () => {
  const lists = tb.resolveTaskBound({ taskAllowlists: [
    { task: "harvest", match: { keywords: ["harvest"] }, tools: { cut: { args: { target: ["apple"] } } }, default: "deny" },
    { task: "pay", match: { taskId: "pay-1" }, tools: { transfer: { args: { amount: [{ max: 500 }] } }, cut: true }, default: "deny" }
  ] }).lists;
  const terms = new Set(tb.taskTerms("harvest the orchard and pay"));
  const entries = tb.applicableEntries(lists, (t) => terms.has(t), (id) => id === "pay-1");
  assert.deepEqual(entries.map((e) => e.task).sort(), ["harvest", "pay"]);
  assert.equal(tb.judgeAllowlists(entries, "transfer", { amount: 100 })?.outcome, "deny", "the keyword entry still holds what it does not list");
  assert.equal(tb.judgeAllowlists(entries, "cut", { target: "hand" })?.outcome, "deny", "the id entry's `cut: true` cannot widen the keyword entry");
});

// ---- 4. the rest of the pass ----

test("allowlist tool names are exact: no case folding, and a bare name never matches an MCP tool", () => {
  const e = tb.resolveTaskBound({ taskAllowlists: [{ task: "t", match: { keywords: ["t"] }, tools: { cut: true, "mcp__robot__grip": true }, default: "deny" }] }).lists[0];
  assert.equal(tb.entryOutcome(e, "cut", {}).outcome, "allow");
  assert.equal(tb.entryOutcome(e, "CUT", {}).outcome, "deny");
  assert.equal(tb.entryOutcome(e, "mcp__evil__cut", {}).outcome, "deny", "another server's tool of the same name");
  assert.equal(tb.entryOutcome(e, "mcp__robot__grip", {}).outcome, "allow");
  assert.equal(tb.entryOutcome(e, "mcp__robot__GRIP", {}).outcome, "deny");
});

test("synonyms expand on a whole value, not on a host, site or file name inside it", () => {
  const args = { notify: ["to"], synonyms: { boss: ["https://hooks.corp.example/inbox"] } };
  assert.equal(named("notify the boss", "notify", { to: "https://hooks.corp.example/inbox" }, args), true);
  assert.equal(named("notify the boss", "notify", { to: "https://evil.corp.example/y" }, args), false, "same site, not the same value");
  assert.equal(named("notify https://hooks.corp.example/inbox", "notify", { to: "boss" }, args), true);
});

test("amounts: a negative amount is never under a cap, and a zero-padded number is not the task's number", () => {
  const args = { transfer: ["amount"], caps: { "transfer.amount": 100 } };
  assert.equal(named("transfer 50 to the vendor", "transfer", { amount: 80 }, args), true);
  assert.equal(named("transfer 50 to the vendor", "transfer", { amount: -5000 }, args), false);
  assert.equal(named("transfer 50 to the vendor", "transfer", { amount: "-5000" }, args), false);
  assert.equal(named("transfer 250 to the vendor", "transfer", { amount: "0250" }, { transfer: ["amount"] }), false);
  assert.equal(named("transfer 250 to the vendor", "transfer", { amount: "250" }, { transfer: ["amount"] }), true);
});

test("phrases do not cross sentence punctuation", () => {
  const args = { move_to: ["location"] };
  assert.equal(named("cut the red. Bin the rest", "move_to", { location: "red bin" }, args), false);
  assert.equal(named("cut it, red bin later", "move_to", { location: "red bin" }, args), true);
  assert.equal(named("put it in the red bin.", "move_to", { location: "red bin" }, args), true);
});

test("object check: a path with traversal or control characters names nothing but itself", () => {
  assert.equal(named("update the README", "mcp__fs__write_file", { path: "/repo/../../etc/README.md" }), false);
  assert.equal(named("update the README", "mcp__fs__write_file", { path: "/repo/%2e%2e/x/README.md" }), false);
  assert.equal(named("update the README", "mcp__fs__write_file", { path: "/repo/README.md" }), true);
  assert.equal(named("cut the apple", "cut", { target: "apple\u0000" }, { cut: ["target"] }), false);
  assert.equal(named("cut the apple", "cut", { target: "ap​ple" }, { cut: ["target"] }), false);
});
