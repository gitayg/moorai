// Cascade limits end to end through the real hook (policy.cascadeLimits): sub-agent spawn rate and depth, the
// same call after consecutive failures, and a session held after repeated denials. Report by default (alert,
// verdict unchanged), "ask" and "block" by policy. Content-free alerts and state.
//
//   node --test --import ./test/hermetic-env.mjs test/cascade-limits-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { CASCADE_THREAT_ID } from "../data/cascade-limits.js";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

async function withServer(policy, fn, { enrolled = true } = {}) {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(policy)); return; }
    if (req.url === "/api/alerts" && req.method === "POST") {
      let b = ""; req.on("data", (c) => { b += c; }); req.on("end", () => { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const home = mkdtempSync(join(tmpdir(), "moorai-cascade-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${server.address().port}`, tenant: "acme", ...(enrolled ? { installToken: "tok-cascade" } : {}) }));
  try { return await fn(home, alerts); } finally { server.close(); rmTree(home); }
}

async function runHook(home, payload) {
  const child = spawn(process.execPath, [HOOK], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" } });
  let out = "";
  child.stdout.on("data", (c) => { out += c; });
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify({ cwd: home, ...payload }));
  await new Promise((r) => child.on("exit", r));
  const t = out.trim();
  if (!t) return { decision: "allow", reason: "", raw: "" };
  const h = JSON.parse(t).hookSpecificOutput || {};
  return { decision: h.permissionDecision || "allow", reason: h.permissionDecisionReason || "", raw: t };
}
const SECRET_PROMPT = "summarise the quarterly numbers for project bluebird";
const spawnCall = (session, n, extra = {}) => ({ hook_event_name: "PreToolUse", session_id: session, tool_name: "Agent", tool_use_id: `tu-${n}`, tool_input: { subagent_type: "general-purpose", description: `part ${n}`, prompt: SECRET_PROMPT }, ...extra });
const spawned = (session, n, child, extra = {}) => ({ hook_event_name: "PostToolUse", session_id: session, tool_name: "Agent", tool_use_id: `tu-${n}`, tool_input: { subagent_type: "general-purpose", description: `part ${n}`, prompt: SECRET_PROMPT }, tool_response: { status: "async_launched", agentId: child }, ...extra });
const bash = (session, command, extra = {}) => ({ hook_event_name: "PreToolUse", session_id: session, tool_name: "Bash", tool_input: { command }, ...extra });
const bashFailed = (session, command, extra = {}) => ({ hook_event_name: "PostToolUseFailure", session_id: session, tool_name: "Bash", tool_input: { command }, error: "exit 1", ...extra });
const cascade = (alerts, kind) => alerts.filter((a) => a.category && a.category.startsWith("Cascade limit: ") && a.cascade && a.cascade.kind === kind);

test("hook e2e: spawn rate in report mode alerts once, content-free, and changes no verdict", async () => {
  await withServer({ captureTier: "content-free", cascadeLimits: { spawnsPerWindow: 2 } }, async (home, alerts) => {
    for (let n = 1; n <= 4; n++) assert.notEqual((await runHook(home, spawnCall("r1", n))).decision, "deny", `spawn ${n}`);
    const hits = cascade(alerts, "spawn-rate");
    assert.equal(hits.length, 1, "one alert per limit per session");
    assert.equal(hits[0].threatId, CASCADE_THREAT_ID);
    assert.equal(hits[0].reasonCode, "CASCADE_LIMIT");
    assert.equal(hits[0].riskLevel, "Medium");
    assert.deepEqual(hits[0].cascade, { kind: "spawn-rate", count: 3, limit: 2, windowSec: 600, action: "report" });
    assert.ok(!JSON.stringify(alerts).includes("bluebird"), "no prompt text in any alert");
    const st = readFileSync(join(home, ".moorai", "cascade-limits.json"), "utf8");
    assert.ok(!st.includes("bluebird") && !st.includes("general-purpose") && !st.includes("r1"), "state holds keyed hashes only");
    if (process.platform !== "win32") assert.equal(statSync(join(home, ".moorai", "cascade-limits.json")).mode & 0o777, 0o600);
  });
});

test("hook e2e: spawn rate under action block denies the spawn over the limit", async () => {
  await withServer({ captureTier: "content-free", cascadeLimits: { action: "block", spawnsPerWindow: 2 } }, async (home, alerts) => {
    assert.notEqual((await runHook(home, spawnCall("b1", 1))).decision, "deny");
    assert.notEqual((await runHook(home, spawnCall("b1", 2))).decision, "deny");
    const r = await runHook(home, spawnCall("b1", 3));
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /cascade limit: 3 sub-agent spawns in 10 min \(limit 2\)/);
    assert.equal(cascade(alerts, "spawn-rate")[0].riskLevel, "Blocked");
    assert.notEqual((await runHook(home, spawnCall("b2", 1))).decision, "deny", "another session has its own count");
    assert.equal((await runHook(home, bash("b1", "ls -la"))).decision, "allow", "a call that is not a spawn is untouched");
  });
});

test("hook e2e: depth — a bound child is one below its spawner; a spawn past maxDepth is denied", async () => {
  await withServer({ captureTier: "content-free", cascadeLimits: { maxDepth: 2, actions: { depth: "block" } } }, async (home, alerts) => {
    assert.notEqual((await runHook(home, spawnCall("d1", 1))).decision, "deny", "main agent -> depth 1");
    // The children report a type no pending spawn names, so only the spawn's result (tool_response.agentId) binds them.
    await runHook(home, spawned("d1", 1, "child-a"));
    assert.notEqual((await runHook(home, spawnCall("d1", 2, { agent_id: "child-a", agent_type: "worker" }))).decision, "deny", "child -> depth 2");
    await runHook(home, spawned("d1", 2, "grandchild-b", { agent_id: "child-a", agent_type: "worker" }));
    const r = await runHook(home, spawnCall("d1", 3, { agent_id: "grandchild-b", agent_type: "worker" }));
    assert.equal(r.decision, "deny", "grandchild -> depth 3 > 2");
    assert.match(r.reason, /cascade limit: a sub-agent 3 layers below the main agent \(limit 2\)/);
    assert.deepEqual(cascade(alerts, "depth")[0].cascade, { kind: "depth", count: 3, limit: 2, action: "block" });
    assert.notEqual((await runHook(home, spawnCall("d1", 4, { agent_id: "stray", agent_type: "Explore" }))).decision, "deny", "an unbound sub-agent counts as depth 1 (a lower bound)");
  });
});

test("hook e2e: the same failing call under action ask is raised to ask; a success breaks the streak", async () => {
  await withServer({ captureTier: "content-free", cascadeLimits: { action: "ask", maxIdenticalFailures: 2 } }, async (home, alerts) => {
    const cmd = "ls /nonexistent-cascade-dir";
    for (let i = 0; i < 2; i++) {
      assert.equal((await runHook(home, bash("f1", cmd))).decision, "allow", `run ${i + 1}`);
      await runHook(home, bashFailed("f1", cmd));
    }
    const r = await runHook(home, bash("f1", cmd));
    assert.equal(r.decision, "ask");
    assert.match(r.reason, /cascade limit: the same call failed 2 times in a row \(limit 2\)/);
    assert.equal(cascade(alerts, "repeat-failure").length, 1);
    // f2: fail, run without a failure (it succeeded), run again -> the streak restarted.
    assert.equal((await runHook(home, bash("f2", cmd))).decision, "allow");
    await runHook(home, bashFailed("f2", cmd));
    assert.equal((await runHook(home, bash("f2", cmd))).decision, "allow");
    assert.equal((await runHook(home, bash("f2", cmd))).decision, "allow");
    // A sub-agent's failures are its own: the main agent's identical call is not over the limit.
    for (let i = 0; i < 2; i++) { await runHook(home, bash("f3", cmd, { agent_id: "sub-1", agent_type: "Explore" })); await runHook(home, bashFailed("f3", cmd, { agent_id: "sub-1", agent_type: "Explore" })); }
    assert.equal((await runHook(home, bash("f3", cmd))).decision, "allow");
    assert.equal((await runHook(home, bash("f3", cmd, { agent_id: "sub-1", agent_type: "Explore" }))).decision, "ask");
  });
});

test("hook e2e: after maxDenied denials the session is held; block denies an otherwise allowed call", async () => {
  await withServer({ captureTier: "content-free", tagActions: { network: "block" }, cascadeLimits: { maxDenied: 2, actions: { denied: "block" } } }, async (home, alerts) => {
    const fetchCall = (s) => ({ hook_event_name: "PreToolUse", session_id: s, tool_name: "WebFetch", tool_input: { url: "https://example.com", prompt: "x" } });
    assert.equal((await runHook(home, bash("h1", "ls -la"))).decision, "allow");
    assert.equal((await runHook(home, fetchCall("h1"))).decision, "deny", "denied by tagActions");
    assert.equal((await runHook(home, bash("h1", "ls -la"))).decision, "allow", "one denial: not held");
    assert.equal((await runHook(home, fetchCall("h1"))).decision, "deny");
    const r = await runHook(home, bash("h1", "ls -la"));
    assert.equal(r.decision, "deny", "held");
    assert.match(r.reason, /cascade limit: MoorAI denied 2 calls in this session; the session is held until it ends/);
    assert.equal((await runHook(home, bash("h1", "pwd"))).decision, "deny", "every later call");
    assert.equal(cascade(alerts, "denied").length, 1);
    assert.equal((await runHook(home, bash("h2", "ls -la"))).decision, "allow", "another session is not held");
  });
});

test("hook e2e: a held session under action ask asks on a tool no branch covers", async () => {
  await withServer({ captureTier: "content-free", tagActions: { network: "block" }, cascadeLimits: { action: "ask", maxDenied: 1 } }, async (home) => {
    assert.equal((await runHook(home, { hook_event_name: "PreToolUse", session_id: "u1", tool_name: "TodoWrite", tool_input: { todos: [] } })).decision, "allow");
    assert.equal((await runHook(home, { hook_event_name: "PreToolUse", session_id: "u1", tool_name: "WebFetch", tool_input: { url: "https://example.com", prompt: "x" } })).decision, "deny");
    const r = await runHook(home, { hook_event_name: "PreToolUse", session_id: "u1", tool_name: "TodoWrite", tool_input: { todos: [] } });
    assert.equal(r.decision, "ask");
    assert.match(r.reason, /cascade limit: MoorAI denied 1 calls in this session/);
  });
});

test("hook e2e: an unenrolled device is coached once per limit, never denied", async () => {
  await withServer({ captureTier: "content-free", cascadeLimits: { action: "block", spawnsPerWindow: 1 } }, async (home) => {
    assert.equal((await runHook(home, spawnCall("c1", 1))).raw.includes("cascade limit"), false);
    const r = await runHook(home, spawnCall("c1", 2));
    assert.notEqual(r.decision, "deny");
    assert.match(r.raw, /cascade limit: 2 sub-agent spawns in 10 min \(limit 1\)/);
    const again = await runHook(home, spawnCall("c1", 3));
    assert.notEqual(again.decision, "deny");
    assert.equal(again.raw.includes("cascade limit"), false, "once per limit");
  }, { enrolled: false });
});

test("hook e2e: action off, and a hard deny stays a deny under ask", async () => {
  await withServer({ captureTier: "content-free", tagActions: { network: "block" }, cascadeLimits: { action: "off", spawnsPerWindow: 1 } }, async (home, alerts) => {
    for (let n = 1; n <= 3; n++) await runHook(home, spawnCall("o1", n));
    assert.equal(alerts.filter((a) => (a.category || "").startsWith("Cascade limit: ")).length, 0);
  });
  await withServer({ captureTier: "content-free", tagActions: { network: "block" }, cascadeLimits: { action: "ask", maxIdenticalFailures: 1 } }, async (home) => {
    const f = { hook_event_name: "PreToolUse", session_id: "a1", tool_name: "WebFetch", tool_input: { url: "https://example.com", prompt: "x" } };
    await runHook(home, f);
    await runHook(home, { ...f, hook_event_name: "PostToolUseFailure", error: "x" });
    assert.equal((await runHook(home, f)).decision, "deny", "the tagActions deny is not softened to the cascade ask");
  });
});
