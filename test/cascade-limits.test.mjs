// data/cascade-limits.js: configuration, the four limits, holds, and the Agent SDK path (in-memory state, the
// same verdict rules: report alerts, ask raises an allow, block denies, a deny stays a deny).
//
//   node --test test/cascade-limits.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { cascadeConfig, cascadeOff, cascadeAssess, cascadeFailure, cascadeBind, cascadeDenied, CASCADE_DEFAULTS } from "../data/cascade-limits.js";
import { moorAIHooks } from "../packages/agent-sdk/src/index.mjs";

const MIN = 60000;

test("cascadeConfig: defaults, per-limit actions, zero turns a limit off, junk falls back", () => {
  const d = cascadeConfig(null);
  assert.equal(d.action, "report");
  assert.equal(d.spawnsPerWindow, CASCADE_DEFAULTS.spawnsPerWindow);
  assert.deepEqual(d.actions, { "spawn-rate": "report", depth: "report", "repeat-failure": "report", denied: "report" });
  const c = cascadeConfig({ cascadeLimits: { action: "ask", actions: { depth: "block", denied: "nope" }, maxDenied: 0, spawnWindowMin: 0, maxDepth: "3" } });
  assert.equal(c.actions.depth, "block");
  assert.equal(c.actions.denied, "ask", "an unknown per-limit action falls back to the action");
  assert.equal(c.maxDenied, 0);
  assert.equal(c.spawnWindowMin, CASCADE_DEFAULTS.spawnWindowMin, "a zero window is not a window");
  assert.equal(c.maxDepth, CASCADE_DEFAULTS.maxDepth, "a string is not a number");
  assert.equal(cascadeOff(cascadeConfig({ cascadeLimits: { action: "off" } })), true);
  assert.equal(cascadeOff(cascadeConfig({ cascadeLimits: { spawnsPerWindow: 0, maxDepth: 0, maxIdenticalFailures: 0, maxDenied: 0 } })), true);
});

test("spawn rate: the window slides", () => {
  const cfg = cascadeConfig({ cascadeLimits: { action: "block", spawnsPerWindow: 2, spawnWindowMin: 1 } });
  let st = null;
  const spawn = (t) => { const r = cascadeAssess(st, "S", { sig: `s${t}`, spawn: true }, t, cfg); st = r.state; return r; };
  assert.equal(spawn(0).level, null);
  assert.equal(spawn(1000).level, null);
  const r = spawn(2000);
  assert.equal(r.level, "block");
  assert.deepEqual(r.trips, ["spawn-rate"]);
  assert.equal(r.alerts.length, 1);
  assert.equal(spawn(3000).alerts.length, 0, "one alert per limit per session");
  assert.equal(spawn(2000 + MIN + 1).level, null, "a minute later the window has slid");
});

test("depth: bound children, the pending spawn of the child's type, and the lower bound", () => {
  const cfg = cascadeConfig({ cascadeLimits: { action: "block", maxDepth: 2 } });
  let st = null;
  const step = (call) => { const r = cascadeAssess(st, "S", call, 0, cfg); st = r.state; return r; };
  assert.equal(step({ sig: "a", spawn: true, spawnType: "T1", spawnId: "u1" }).level, null);
  // The child's first call names its type: the one pending spawn of that type gives it depth 1.
  assert.equal(step({ sig: "b", agent: "c1", agentType: "T1", spawn: true, spawnType: "T2", spawnId: "u2" }).level, null);
  st = cascadeBind(st, "S", { caller: "c1", child: "g1", spawnId: "u2" }, 0).state;
  const r = step({ sig: "c", agent: "g1", agentType: "T2", spawn: true, spawnType: "T3" });
  assert.equal(r.level, "block");
  assert.deepEqual(r.alerts[0].cascade, { kind: "depth", count: 3, limit: 2, action: "block" });
  assert.equal(step({ sig: "d", agent: "unknown", agentType: "T9", spawn: true }).level, null, "an unbound sub-agent is depth 1");
});

test("repeat failure: consecutive failures of the same call, per agent", () => {
  const cfg = cascadeConfig({ cascadeLimits: { action: "block", maxIdenticalFailures: 3 } });
  let st = null;
  const pre = (sig, agent = "") => { const r = cascadeAssess(st, "S", { sig, agent }, 0, cfg); st = r.state; return r; };
  const fail = (sig, agent = "") => { st = cascadeFailure(st, "S", { sig, agent }, 0).state; };
  for (let i = 0; i < 3; i++) { assert.equal(pre("x").level, null); fail("x"); }
  assert.equal(pre("x").level, "block");
  assert.equal(pre("x").level, "block", "a blocked call never ran: the streak holds");
  assert.equal(pre("y").level, null, "a different call breaks the streak");
  assert.equal(pre("x").level, null);
  fail("x"); fail("x");
  assert.equal(pre("x").level, null, "one run reports one failure");
});

test("denied: the hold, its expiry, and report mode", () => {
  const cfg = cascadeConfig({ cascadeLimits: { action: "ask", maxDenied: 2, holdMin: 5 } });
  let st = null;
  st = cascadeDenied(st, "S", 0, cfg).state;
  assert.equal(cascadeAssess(st, "S", { sig: "a" }, 0, cfg).level, null);
  st = cascadeDenied(st, "S", 0, cfg).state;
  const r = cascadeAssess(st, "S", { sig: "a" }, 1000, cfg);
  assert.equal(r.level, "ask");
  assert.match(r.reason, /held for 5 min/);
  st = r.state;
  assert.equal(cascadeAssess(st, "S", { sig: "a" }, 5 * MIN + 1, cfg).level, null, "the hold ends");
  const rep = cascadeConfig({ cascadeLimits: { maxDenied: 1 } });
  const s2 = cascadeDenied(null, "S", 0, rep).state;
  const r2 = cascadeAssess(s2, "S", { sig: "a" }, 0, rep);
  assert.equal(r2.level, null, "report: no decision change");
  assert.equal(r2.alerts.length, 1);
  assert.equal(r2.alerts[0].reasonCode, "CASCADE_LIMIT");
});

function fakeConsole() {
  const bodies = [];
  const fetch = async (url, init) => { bodies.push(init && init.body ? JSON.parse(init.body) : null); return { ok: true, status: 200, json: async () => ({}), text: async () => "{}" }; };
  return { bodies, fetch, console: { serverUrl: "http://console.invalid", tenant: "t-unit", installToken: "tok-unit" } };
}
const call = (hooks, ev, input) => hooks[ev][0].hooks[0](input, input.tool_use_id, { signal: new AbortController().signal });
const decisionOf = (o) => (o.hookSpecificOutput && o.hookSpecificOutput.permissionDecision) || "allow";

test("Agent SDK: spawn rate, depth via the spawn result, repeat failure and the hold, in memory", async () => {
  const fc = fakeConsole();
  const hooks = moorAIHooks({ policy: { captureTier: "content-free", tagActions: { network: "block" }, cascadeLimits: { action: "block", spawnsPerWindow: 3, maxDepth: 2, maxIdenticalFailures: 2, maxDenied: 2 } }, console: fc.console, fetch: fc.fetch, serviceId: "unit", headlessAsk: "pass-through" });
  const pre = (session, tool_name, tool_input, extra = {}) => call(hooks, "PreToolUse", { hook_event_name: "PreToolUse", session_id: session, tool_name, tool_input, cwd: "/tmp", ...extra });
  const agent = { subagent_type: "general-purpose", description: "d", prompt: "look at the bluebird numbers" };
  const launched = (session, caller, toolUseId, child) => call(hooks, "PostToolUse", { hook_event_name: "PostToolUse", session_id: session, tool_name: "Agent", tool_use_id: toolUseId, tool_input: agent, tool_response: { status: "async_launched", agentId: child }, ...(caller ? { agent_id: caller, agent_type: "worker" } : {}) });
  // Depth: the children report a type no pending spawn names, so only the spawn results bind them.
  assert.equal(decisionOf(await pre("A", "Agent", agent, { tool_use_id: "u1" })), "allow");
  await launched("A", "", "u1", "kid");
  assert.equal(decisionOf(await pre("A", "Agent", agent, { agent_id: "kid", agent_type: "worker", tool_use_id: "u2" })), "allow", "kid -> depth 2");
  await launched("A", "kid", "u2", "grandkid");
  const deep = await pre("A", "Agent", agent, { agent_id: "grandkid", agent_type: "worker", tool_use_id: "u3" });
  assert.equal(decisionOf(deep), "deny");
  assert.match(deep.hookSpecificOutput.permissionDecisionReason, /a sub-agent 3 layers below the main agent \(limit 2\)/);
  for (let n = 1; n <= 3; n++) assert.equal(decisionOf(await pre("E", "Agent", agent, { tool_use_id: `e${n}` })), "allow", `spawn ${n}`);
  assert.equal(decisionOf(await pre("E", "Agent", agent, { tool_use_id: "e4" })), "deny", "spawn 4 of 3");

  const cmd = { command: "ls /nonexistent-cascade-dir" };
  for (let i = 0; i < 2; i++) {
    assert.equal(decisionOf(await pre("B", "Bash", cmd)), "allow");
    await call(hooks, "PostToolUseFailure", { hook_event_name: "PostToolUseFailure", session_id: "B", tool_name: "Bash", tool_input: cmd, error: "exit 1" });
  }
  assert.equal(decisionOf(await pre("B", "Bash", cmd)), "deny");

  const web = { url: "https://example.com", prompt: "x" };
  assert.equal(decisionOf(await pre("C", "WebFetch", web)), "deny");
  assert.equal(decisionOf(await pre("C", "WebFetch", web)), "deny");
  const held = await pre("C", "Bash", { command: "pwd" });
  assert.equal(decisionOf(held), "deny");
  assert.match(held.hookSpecificOutput.permissionDecisionReason, /the session is held until it ends/);
  assert.equal(decisionOf(await pre("D", "Bash", { command: "pwd" })), "allow", "another session");
  await hooks.moorai.flush();
  const cas = fc.bodies.flat().filter((b) => b && typeof b === "object").flatMap((b) => (Array.isArray(b.alerts) ? b.alerts : [b])).filter((a) => a && a.reasonCode === "CASCADE_LIMIT");
  assert.deepEqual([...new Set(cas.map((a) => a.cascade.kind))].sort(), ["denied", "depth", "repeat-failure", "spawn-rate"]);
  assert.ok(!JSON.stringify(fc.bodies).includes("bluebird"), "content-free");
});

test("Agent SDK: under ask a branch deny stays a deny", async () => {
  const hooks = moorAIHooks({ policy: { captureTier: "content-free", tagActions: { network: "block" }, cascadeLimits: { action: "ask", maxIdenticalFailures: 1 } }, fetchPolicy: false, headlessAsk: "pass-through" });
  const web = { hook_event_name: "PreToolUse", session_id: "K", tool_name: "WebFetch", tool_input: { url: "https://example.com", prompt: "x" }, cwd: "/tmp" };
  const bash = { hook_event_name: "PreToolUse", session_id: "K", tool_name: "Bash", tool_input: { command: "ls /nonexistent-cascade-dir" }, cwd: "/tmp" };
  assert.equal(decisionOf(await call(hooks, "PreToolUse", bash)), "allow");
  await call(hooks, "PostToolUseFailure", { ...bash, hook_event_name: "PostToolUseFailure", error: "exit 1" });
  assert.equal(decisionOf(await call(hooks, "PreToolUse", bash)), "ask", "the repeat is raised to ask");
  assert.equal(decisionOf(await call(hooks, "PreToolUse", web)), "deny");
  await call(hooks, "PostToolUseFailure", { ...web, hook_event_name: "PostToolUseFailure", error: "x" });
  assert.equal(decisionOf(await call(hooks, "PreToolUse", web)), "deny", "the tagActions deny is not softened to the cascade ask");
});

test("Agent SDK: report (the default) never changes a verdict", async () => {
  const hooks = moorAIHooks({ policy: { captureTier: "content-free", cascadeLimits: { spawnsPerWindow: 1, maxDenied: 1 } }, fetchPolicy: false, headlessAsk: "pass-through" });
  const agent = { subagent_type: "general-purpose", description: "d", prompt: "p" };
  for (let i = 0; i < 4; i++) assert.equal(decisionOf(await call(hooks, "PreToolUse", { hook_event_name: "PreToolUse", session_id: "R", tool_name: "Agent", tool_input: agent, cwd: "/tmp" })), "allow");
});
