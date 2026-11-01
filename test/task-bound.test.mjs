// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/task-bound.test.mjs
//
// Task-bound tool calls (data/task-bound.js, held per session by data/intent-server.mjs):
//   1. the object check — for a high-impact call, the object of the action must be named in the task
//      (policy.intentArgs: object fields per tool, synonyms, amount caps); class "object-not-in-task";
//   2. task allowlists — policy.taskAllowlists: a session whose task matches an entry may call only the tools
//      and argument values the entry lists; anything else is held at the entry's default; class
//      "outside-task-allowlist". An unreadable entry denies everything it would have covered.
// The surfaces (model proxy, moorai-serve, Agent SDK, the hook's MCP path) are in task-bound-surfaces.test.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { taskTerms, valueTerms, objectChecks, judgeObjects, resolveTaskBound, applicableEntries, judgeAllowlists, highImpact } from "../data/task-bound.js";
import { createIntentStore } from "../data/intent-server.mjs";

const KEY = Buffer.alloc(32, 9);
const ROBOT = { intentArgs: { cut: ["target"], move_to: ["location"], transfer: ["to_account", "amount"], synonyms: { apple: ["granny smith"] }, caps: { "transfer.amount": 100 } } };
const judgeText = (task, tool, input, policy = ROBOT) => {
  const terms = new Set(taskTerms(task));
  const checks = objectChecks(tool, input, resolveTaskBound(policy).args);
  return checks ? judgeObjects(checks, (t) => terms.has(t)) : null;
};

test("object check: \"cut the apple\" allows cut(apple) and holds cut(hand)", () => {
  assert.equal(judgeText("Please cut the apple", "cut", { target: "apple" }).aligned, true);
  const r = judgeText("Please cut the apple", "cut", { target: "hand" });
  assert.equal(r.aligned, false);
  assert.equal(r.unmatched, 1);
  assert.equal(judgeText("cut the apples in half", "cut", { target: "Apple" }).aligned, true, "case and a simple plural fold");
  assert.equal(judgeText("cut the apple", "cut", { target: "the apple." }).aligned, true, "articles and punctuation fold");
  assert.equal(judgeText("cut the pineapple", "cut", { target: "apple" }).aligned, false, "a token, not a substring");
});

test("object check: a phrase value must appear as a phrase", () => {
  assert.equal(judgeText("move the arm to the red bin", "move_to", { location: "red bin" }).aligned, true);
  assert.equal(judgeText("move the arm to the red bin", "move_to", { location: "blue bin" }).aligned, false);
  assert.equal(judgeText("put the red apple in the bin", "move_to", { location: "red bin" }).aligned, false, "both words present but not as a phrase");
});

test("object check: synonyms (intentArgs.synonyms) name a value through its group, in both directions", () => {
  assert.equal(judgeText("cut the apple", "cut", { target: "Granny Smith" }).aligned, true);
  assert.equal(judgeText("cut the granny smith", "cut", { target: "apple" }).aligned, true);
  assert.equal(judgeText("cut the apple", "cut", { target: "pear" }).aligned, false);
  assert.equal(judgeText("cut the apple", "cut", { target: "Granny Smith" }, { intentArgs: { cut: ["target"] } }).aligned, false, "no synonym map, no synonym");
});

test("object check: an amount must be the amount the task names, or at or under the cap", () => {
  const task = "transfer 250 to account 4471";
  assert.equal(judgeText(task, "transfer", { to_account: "4471", amount: 250 }).aligned, true, "the task's amount");
  assert.equal(judgeText(task, "transfer", { to_account: "4471", amount: "$250.00" }).aligned, true, "a currency string folds to the same number");
  assert.equal(judgeText(task, "transfer", { to_account: "4471", amount: 90 }).aligned, true, "under the cap");
  assert.equal(judgeText(task, "transfer", { to_account: "4471", amount: 100 }).aligned, true, "at the cap");
  assert.equal(judgeText(task, "transfer", { to_account: "4471", amount: 2500 }).aligned, false, "over the task amount and over the cap");
  assert.equal(judgeText("transfer 1,500 to account 4471", "transfer", { to_account: "4471", amount: 1500 }).aligned, true, "a grouped number");
  assert.equal(judgeText(task, "transfer", { to_account: "9999", amount: 250 }).aligned, false, "the account is an object field too");
  assert.equal(judgeText(task, "transfer", { to_account: "4471", amount: 2500 }, { intentArgs: { transfer: ["to_account", "amount"] } }).aligned, false, "no cap: only the task's amount");
});

test("object check: built-in defaults cover recipients, URLs and paths of high-impact software tools", () => {
  assert.equal(judgeText("email the report to bob@corp.example", "send_email", { to: "bob@corp.example", body: "x" }, {}).aligned, true);
  assert.equal(judgeText("email the report to bob@corp.example", "send_email", { to: "eve@evil.example", body: "x" }, {}).aligned, false);
  assert.equal(judgeText("email the report to bob", "send_email", { to: "bob@evil.example" }, {}).aligned, false, "an address must appear whole");
  assert.equal(judgeText("post the build status to hooks.corp.example", "mcp__web__post_webhook", { url: "https://hooks.corp.example/x?y=1" }, {}).aligned, true, "a URL's host");
  assert.equal(judgeText("update the README", "mcp__fs__write_file", { path: "/repo/README.md", content: "x" }, {}).aligned, true, "a path's stem");
  assert.equal(judgeText("update the README", "mcp__fs__write_file", { path: "/repo/.github/workflows/release.yml" }, {}).aligned, false);
});

test("high-impact: reads, everyday calls and the hook's own tools are not object-checked", () => {
  for (const [tool, input] of [["get_weather", { city: "Paris" }], ["search", { query: "hand" }], ["mcp__fs__read_file", { path: "/etc/passwd" }],
    ["mcp__github__list_issues", { repo: "evil/x" }], ["Bash", { command: "rm -rf /" }], ["Write", { file_path: "/x" }], ["list_accounts", { account: "1" }]]) {
    assert.equal(objectChecks(tool, input, resolveTaskBound({}).args), null, tool);
  }
  assert.equal(highImpact("cut", resolveTaskBound({}).args), false, "cut is not high-impact until a policy marks it");
  assert.equal(highImpact("cut", resolveTaskBound(ROBOT).args), true);
  assert.equal(highImpact("refund_order", resolveTaskBound({}).args), true, "a business-impact class");
  assert.equal(highImpact("mcp__gmail__send_email", resolveTaskBound({}).args), true, "an MCP write");
  assert.equal(objectChecks("set_timer", { minutes: 5 }, resolveTaskBound({}).args), null, "high-impact name but no object field");
});

test("policy: the admin binding wins over the signed policy, key by key; an unreadable intentArgs entry checks every argument", () => {
  const c = resolveTaskBound({ intentArgs: { cut: ["target"] } }, { intentArgs: { cut: ["tool"] } });
  assert.deepEqual(c.args.tools.get("cut"), ["tool"]);
  const bad = resolveTaskBound({ intentArgs: { cut: "target" } });
  assert.ok(bad.problems.includes("intentArgs-tool-keys"));
  const checks = objectChecks("cut", { target: "hand", speed: 3 }, bad.args);
  assert.deepEqual(checks.map((x) => x.key).sort(), ["speed", "target"]);
});

// ---- task allowlists ----

const LISTS = {
  taskAllowlists: [
    { task: "harvest", match: { keywords: ["harvest", "pick apples"] }, tools: { cut: { args: { target: ["apple", "stem-*"] } }, move_to: { args: { location: ["bin"] } }, get_status: true }, default: "deny" },
    { task: "inspect", match: { keywords: ["inspect"] }, tools: { get_status: {}, move_to: { args: { location: ["bin", "dock"] } } }, default: "ask" },
    { task: "pay-vendor", match: { taskId: "pay-vendor-1" }, tools: { transfer: { args: { amount: [{ max: 500 }], to_account: ["4471"] } } }, default: "deny" }
  ]
};
const allow = (policy, task, tool, input, taskId) => {
  const cfg = resolveTaskBound(policy);
  const terms = task === null ? null : new Set(taskTerms(task));
  const entries = applicableEntries(cfg.lists, terms ? (t) => terms.has(t) : null, taskId ? (id) => id === taskId : null);
  return judgeAllowlists(entries, tool, input);
};

test("allowlist: a matching task allows listed tools and values; a miss is held at the entry's default", () => {
  assert.equal(allow(LISTS, "harvest the orchard", "cut", { target: "apple" }), null);
  assert.equal(allow(LISTS, "harvest the orchard", "cut", { target: "stem-12" }), null, "a glob");
  assert.equal(allow(LISTS, "harvest the orchard", "get_status", { anything: 1 }), null, "true: any arguments");
  assert.deepEqual(pick(allow(LISTS, "harvest the orchard", "cut", { target: "hand" })), { outcome: "deny", reason: "argument-not-allowed", task: "harvest" });
  assert.deepEqual(pick(allow(LISTS, "harvest the orchard", "open_gate", {})), { outcome: "deny", reason: "tool-not-listed", task: "harvest" });
  assert.deepEqual(pick(allow(LISTS, "please pick apples", "cut", { target: ["apple", "hand"] })), { outcome: "deny", reason: "argument-not-allowed", task: "harvest" }, "a phrase keyword; every array element");
  assert.equal(allow(LISTS, "write a poem", "open_gate", {}), null, "no entry matches: nothing applies");
  assert.equal(allow(LISTS, null, "open_gate", {}), null, "no task: no keyword entry applies");
});

test("allowlist: several entries match → the strictest outcome wins", () => {
  assert.equal(pick(allow(LISTS, "inspect the trees", "move_to", { location: "dock" })), undefined, "inspect alone allows dock");
  assert.deepEqual(pick(allow(LISTS, "inspect then harvest", "move_to", { location: "dock" })), { outcome: "deny", reason: "argument-not-allowed", task: "harvest" }, "harvest denies dock: deny beats allow");
  assert.deepEqual(pick(allow(LISTS, "inspect then harvest", "open_gate", {})), { outcome: "deny", reason: "tool-not-listed", task: "harvest" }, "deny beats ask");
  assert.deepEqual(pick(allow(LISTS, "inspect the trees", "open_gate", {})), { outcome: "ask", reason: "tool-not-listed", task: "inspect" });
  const askFirst = { taskAllowlists: [LISTS.taskAllowlists[1], LISTS.taskAllowlists[0]] };
  assert.deepEqual(pick(allow(askFirst, "inspect then harvest", "open_gate", {})), { outcome: "deny", reason: "tool-not-listed", task: "harvest" }, "whatever the order of the entries");
});

test("allowlist: an explicit task id adds its entry (it never replaces keyword entries); numeric ranges", () => {
  assert.equal(allow(LISTS, "pay the vendor", "transfer", { amount: 400, to_account: "4471" }, "pay-vendor-1"), null, "the taskId entry allows it");
  assert.deepEqual(pick(allow(LISTS, "pay the vendor", "transfer", { amount: 900, to_account: "4471" }, "pay-vendor-1")), { outcome: "deny", reason: "argument-not-allowed", task: "pay-vendor" });
  assert.deepEqual(pick(allow(LISTS, "harvest and pay", "transfer", { amount: 400, to_account: "4471" }, "pay-vendor-1")), { outcome: "deny", reason: "tool-not-listed", task: "harvest" }, "the harvest keyword entry still applies");
  assert.deepEqual(pick(allow(LISTS, "harvest and pay", "transfer", { amount: 400, to_account: "4471" }, "unknown-id")), { outcome: "deny", reason: "tool-not-listed", task: "harvest" }, "an id no entry names falls back to keywords");
});

test("allowlist: an invalid policy denies everything the entry would have covered, and is reported as fixed tokens", () => {
  const notArray = resolveTaskBound({ taskAllowlists: { task: "x" } });
  assert.deepEqual(notArray.problems, ["taskAllowlists-not-array"]);
  assert.deepEqual(pick(allow({ taskAllowlists: { task: "x" } }, null, "get_weather", { city: "Paris" })), { outcome: "deny", reason: "invalid-policy", task: "" }, "not an array: covers every session, even with no task");
  const badTools = { taskAllowlists: [{ task: "harvest", match: { keywords: ["harvest"] }, tools: { cut: { args: { target: "apple" } } }, default: "deny" }] };
  assert.ok(resolveTaskBound(badTools).problems.includes("taskAllowlists-tools"));
  assert.deepEqual(pick(allow(badTools, "harvest", "cut", { target: "apple" })), { outcome: "deny", reason: "invalid-policy", task: "harvest" }, "unreadable tools: deny in the sessions it matches");
  assert.equal(allow(badTools, "write a poem", "cut", { target: "apple" }), null, "its match is readable, so other sessions are not covered");
  const badMatch = { taskAllowlists: [{ task: "harvest", match: { keyword: "harvest" }, tools: { cut: true } }] };
  assert.deepEqual(pick(allow(badMatch, "write a poem", "get_weather", {})), { outcome: "deny", reason: "invalid-policy", task: "harvest" }, "unreadable match: every session");
  const badDefault = { taskAllowlists: [{ task: "harvest", match: { keywords: ["harvest"] }, tools: { cut: true }, default: "allow" }] };
  assert.deepEqual(pick(allow(badDefault, "harvest", "cut", {})), { outcome: "deny", reason: "invalid-policy", task: "harvest" });
  const badGlob = { taskAllowlists: [{ task: "h", match: { keywords: ["h"] }, tools: { cut: { args: { target: [/x/] } } } }] };
  assert.equal(pick(allow(badGlob, "h", "cut", { target: "x" })).reason, "invalid-policy");
});

test("allowlist: a glob is linear (no backtracking blow-up)", () => {
  const p = { taskAllowlists: [{ task: "g", match: { keywords: ["g"] }, tools: { t: { args: { v: ["*a*a*a*a*a*a*a*a*a*a*b"] } } } }] };
  const t0 = performance.now();
  assert.equal(pick(allow(p, "g", "t", { v: "a".repeat(4000) })).reason, "argument-not-allowed");
  assert.ok(performance.now() - t0 < 500);
});

function pick(r) { return r ? { outcome: r.outcome, reason: r.reason, task: r.task } : undefined; }

// ---- the store ----

test("store: judgeBound holds hashes only, answers task-unknown with no task, and alerts once per target", () => {
  const s = createIntentStore({ key: KEY });
  const pol = { policy: ROBOT };
  const none = s.judgeBound("s1", "cut", { target: "hand" }, pol);
  assert.equal(none.objects.class, "task-unknown");
  assert.equal(none.objects.aligned, false);
  s.captureTask("s1", "cut the apple");
  assert.equal(s.judgeBound("s1", "cut", { target: "apple" }, pol).objects.aligned, true);
  const r = s.judgeBound("s1", "cut", { target: "hand" }, pol);
  assert.deepEqual([r.objects.aligned, r.objects.class, r.objects.firstForTarget], [false, "object-not-in-task", true]);
  assert.match(r.objects.targetHash, /^[0-9a-f]{16}$/);
  assert.equal(s.judgeBound("s1", "cut", { target: "hand" }, pol).objects.firstForTarget, false);
  assert.equal(s.judgeBound("s1", "get_weather", { city: "Paris" }, pol).objects, null, "a benign call");
  assert.equal(s.judgeBound("s1", "get_weather", { city: "Paris" }, pol).allowlist, null);
  assert.equal(s.judgeBound("s1", "cut", { target: "hand" }, pol, "", { objects: false }).objects, null, "objects: false skips the object check");
});

test("store: authenticatedOnly ignores unauthenticated captures and task ids", () => {
  const s = createIntentStore({ key: KEY });
  s.captureTask("s1", "cut the hand", "", { authenticated: false });
  assert.equal(s.judgeBound("s1", "cut", { target: "hand" }, { policy: ROBOT }).objects.aligned, true);
  assert.equal(s.judgeBound("s1", "cut", { target: "hand" }, { policy: ROBOT }, "", { authenticatedOnly: true }).objects.class, "task-unknown");
  const t = createIntentStore({ key: KEY });
  t.captureTask("s1", "pay the vendor");
  assert.deepEqual(t.setTaskId("s1", "pay-vendor-1", "", { authenticated: false }), { taskId: true });
  assert.equal(t.judgeBound("s1", "transfer", { amount: 900, to_account: "4471" }, { policy: LISTS }).allowlist, null, "an unauthenticated task id never selects an entry");
  t.setTaskId("s1", "pay-vendor-1");
  assert.equal(t.judgeBound("s1", "transfer", { amount: 900, to_account: "4471" }, { policy: LISTS }).allowlist.reason, "argument-not-allowed");
  assert.equal(t.judgeBound("s1", "transfer", { amount: 400, to_account: "4471" }, { policy: LISTS }).allowlist, null);
  assert.deepEqual(t.setTaskId("s1", "bad id!"), { taskId: false });
});

test("store: allowlist verdicts are per session and owner, with the entry's name and a keyed target hash", () => {
  const s = createIntentStore({ key: KEY });
  s.captureTask("s1", "harvest the orchard", "alice");
  const r = s.judgeBound("s1", "open_gate", {}, { policy: LISTS }, "alice");
  assert.deepEqual([r.allowlist.decision, r.allowlist.class, r.allowlist.task, r.allowlist.reason, r.allowlist.firstForTarget], ["deny", "outside-task-allowlist", "harvest", "tool-not-listed", true]);
  assert.equal(s.judgeBound("s1", "open_gate", {}, { policy: LISTS }, "bob").allowlist, null, "another owner's session has no task");
  const inv = s.judgeBound("s9", "get_weather", {}, { policy: { taskAllowlists: "nope" } });
  assert.equal(inv.allowlist.decision, "deny");
  assert.equal(inv.allowlist.invalid, true);
  assert.deepEqual(inv.problems, ["taskAllowlists-not-array"]);
});

test("terms: no plaintext of the task is kept by the store", () => {
  const s = createIntentStore({ key: KEY });
  s.captureTask("s1", "cut the zebra-quartz-7731 apple");
  const r = JSON.stringify(s.judgeBound("s1", "cut", { target: "hand" }, { policy: ROBOT }));
  assert.ok(!r.includes("zebra") && !r.includes("hand") && !r.includes("apple"));
  assert.ok(valueTerms("Hand").includes("w:hand"));
});
