// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/task-bound-surfaces.test.mjs
//
// Task-bound tool calls (data/task-bound.js) on every surface that judges a tool call against the person's task:
// the model proxy (a tool call in the model's reply, before the framework runs it), moorai-serve /v1/tool-call
// (real CLI process over HTTP), the Agent SDK (its hooks, in process) and the endpoint hook's MCP path (real hook
// process). The apple / hand case on each: the task "cut the apple" allows cut({target:"apple"}) and holds
// cut({target:"hand"}). Plus allowlists (match, miss, strictest wins, invalid → deny), amounts, no task, and a
// benign everyday call that stays clean. Alerts never carry the task or an argument.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, statSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { createProxy } from "../model-proxy/server.mjs";
import { startFakeProvider, sendJson, anthropicMessage } from "../model-proxy/test/fake-provider.mjs";
import { request } from "../model-proxy/test/harness.mjs";
import { SESSION_ID_HEADER } from "../model-proxy/intent.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CATEGORY = "Action outside the stated task";
const SECRET = "zebra-quartz-7731";
const TASK = `Please cut the apple for ${SECRET}`;
const ROBOT = { intentArgs: { cut: ["target"], transfer: ["to_account", "amount"], synonyms: { apple: ["granny smith"] }, caps: { "transfer.amount": 100 } } };
const LISTS = [
  { task: "harvest", match: { keywords: ["harvest"] }, tools: { cut: { args: { target: ["apple", "stem-*"] } }, get_status: true }, default: "deny" },
  { task: "inspect", match: { keywords: ["inspect"] }, tools: { get_status: true, move_to: { args: { location: ["bin", "dock"] } } }, default: "ask" },
  { task: "pay-vendor", match: { taskId: "pay-vendor-1" }, tools: { transfer: { args: { amount: [{ max: 500 }], to_account: ["4471"] } } }, default: "deny" }
];
const noLeak = (alerts, ...words) => { const s = JSON.stringify(alerts); for (const w of [SECRET, "hand", ...words]) assert.ok(!s.includes(w), `an alert carries ${w}`); };

// ---- model proxy ----

let fp;
const proxies = [];
before(async () => { fp = await startFakeProvider(); });
after(async () => { for (const p of proxies) await p.close(); await fp?.close(); });

async function proxy(mode, policy) {
  const px = await createProxy({ port: 0, mode, policy, routes: { "/anthropic": fp.url }, systemConfig: null, env: {} });
  proxies.push(px);
  const alerts = [];
  const post = px.runtime.reporter.post;
  px.runtime.reporter.post = (a, o) => { alerts.push(a); return post(a, o); };
  return { px, alerts };
}
let psid = 0;
async function proxyCall(p, task, call) {
  fp.on((r, res) => sendJson(res, anthropicMessage({ text: "On it.", tools: [call] })));
  const body = { model: "claude-fake", max_tokens: 64, tools: [{ name: call.name, description: "robot action", input_schema: { type: "object" } }], messages: [{ role: "user", content: task }] };
  const n = p.alerts.length;
  const r = await request(p.px.url, "/anthropic/v1/messages", { body, headers: { "anthropic-version": "2023-06-01", [SESSION_ID_HEADER]: `tb-${++psid}` } });
  await new Promise((res) => setTimeout(res, 60));
  return { status: r.status, text: r.raw.toString("utf8"), alerts: p.alerts.slice(n) };
}
const classes = (alerts) => alerts.filter((a) => a.category === CATEGORY).map((a) => a.intent.class);

test("model proxy: cut(hand) under \"cut the apple\" is refused in enforce + block; cut(apple) is delivered", async () => {
  const p = await proxy("enforce", { intentAlignment: "block", ...ROBOT });
  const bad = await proxyCall(p, TASK, { name: "cut", input: { target: "hand" } });
  assert.equal(bad.status, 403, bad.text);
  assert.deepEqual(classes(bad.alerts), ["object-not-in-task"]);
  noLeak(bad.alerts, "apple");
  const good = await proxyCall(p, TASK, { name: "cut", input: { target: "apple" } });
  assert.equal(good.status, 200);
  assert.deepEqual(classes(good.alerts), []);
  const syn = await proxyCall(p, TASK, { name: "cut", input: { target: "Granny Smith" } });
  assert.equal(syn.status, 200, "a synonym of a named object");
});

test("model proxy: report mode alerts and delivers; a benign call is clean; no session task → task-unknown", async () => {
  const p = await proxy("report", ROBOT);
  const bad = await proxyCall(p, TASK, { name: "cut", input: { target: "hand" } });
  assert.equal(bad.status, 200);
  assert.match(bad.text, /hand/, "report mode never withholds the call");
  assert.deepEqual(classes(bad.alerts), ["object-not-in-task"]);
  assert.equal(bad.alerts.find((a) => a.category === CATEGORY).decision, "notify");
  const benign = await proxyCall(p, TASK, { name: "get_weather", input: { city: "Paris" } });
  assert.deepEqual(benign.alerts, []);
  const e = await proxy("enforce", { intentAlignment: "block", ...ROBOT });
  fp.on((r, res) => sendJson(res, anthropicMessage({ tools: [{ name: "cut", input: { target: "apple" } }] })));
  const r = await request(e.px.url, "/anthropic/v1/messages", { body: { model: "m", max_tokens: 8, tools: [{ name: "cut", input_schema: { type: "object" } }], messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: "x", content: "cut the apple" }] }] }, headers: { "anthropic-version": "2023-06-01", [SESSION_ID_HEADER]: "tb-none" } });
  assert.equal(r.status, 403, "no person's turn: the task is unknown and block fails closed");
});

test("model proxy: task allowlists — match, miss, strictest wins, invalid policy denies (enforce)", async () => {
  const p = await proxy("enforce", { taskAllowlists: LISTS });
  assert.equal((await proxyCall(p, "harvest the orchard", { name: "cut", input: { target: "stem-4" } })).status, 200, "listed tool and value");
  const miss = await proxyCall(p, "harvest the orchard", { name: "open_gate", input: {} });
  assert.equal(miss.status, 403);
  assert.deepEqual(miss.alerts.filter((a) => a.category === CATEGORY).map((a) => [a.intent.class, a.intent.task, a.intent.reason]), [["outside-task-allowlist", "harvest", "tool-not-listed"]]);
  assert.equal((await proxyCall(p, "inspect the trees", { name: "move_to", input: { location: "dock" } })).status, 200);
  assert.equal((await proxyCall(p, "inspect, then harvest", { name: "move_to", input: { location: "dock" } })).status, 403, "harvest's deny beats inspect's allow");
  assert.equal((await proxyCall(p, "write a poem", { name: "open_gate", input: {} })).status, 200, "no entry matches");
  const off = await proxy("enforce", { intentAlignment: "off", taskAllowlists: LISTS });
  assert.equal((await proxyCall(off, "harvest the orchard", { name: "open_gate", input: {} })).status, 403, "intentAlignment off: the task is still captured for the allowlist");
  const inv = await proxy("enforce", { taskAllowlists: { harvest: true } });
  const r = await proxyCall(inv, "write a poem", { name: "get_weather", input: { city: "Paris" } });
  assert.equal(r.status, 403, "an unreadable taskAllowlists denies everything it would have covered");
  assert.deepEqual(r.alerts.filter((a) => a.category === "Task-bound policy invalid").map((a) => a.taskBoundPolicy.problems), [["taskAllowlists-not-array"]]);
});

// ---- moorai-serve ----

const SERVE = join(ROOT, "cli", "moorai-serve.mjs");
function startServe(home, args, env) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [SERVE, "--port", "0", ...args], { cwd: join(home, "proj"), env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MOORAI_SERVICE_ID: "serve-bot", ...env } });
    let out = "", err = "";
    const t = setTimeout(() => { c.kill(); rej(new Error(`serve did not start: ${err}`)); }, 15000);
    c.stderr.on("data", (d) => (err += d));
    c.stdout.on("data", (d) => {
      out += d;
      const nl = out.indexOf("\n");
      if (nl < 0) return;
      clearTimeout(t);
      res({ ...JSON.parse(out.slice(0, nl)), stop: () => new Promise((r) => { c.once("close", r); c.kill("SIGTERM"); }) });
    });
    c.on("close", (code) => { clearTimeout(t); if (!out) rej(new Error(`serve exited ${code}: ${err}`)); });
  });
}
function req(url, path, body, token) {
  const u = new URL(path, url);
  const data = JSON.stringify(body);
  return new Promise((res, rej) => {
    const r = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data), ...(token ? { authorization: `Bearer ${token}` } : {}) } }, (resp) => {
      let s = ""; resp.on("data", (d) => (s += d)); resp.on("end", () => res({ status: resp.statusCode, raw: s, json: JSON.parse(s) }));
    });
    r.on("error", rej);
    r.end(data);
  });
}
async function fakeConsole(policy) {
  const alerts = [];
  const srv = http.createServer((q, r) => {
    let b = ""; q.on("data", (d) => (b += d));
    q.on("end", () => {
      if (q.url.startsWith("/api/policy")) { if (policy) { r.writeHead(200, { "Content-Type": "application/json" }); r.end(JSON.stringify(policy)); } else { r.writeHead(404); r.end("{}"); } return; }
      if (q.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } }
      r.writeHead(201); r.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { alerts, port: srv.address().port, close: () => srv.close() };
}
const TOKEN = "tok-task-bound-serve-0001";
async function withServe(policy, fn, { token = false } = {}) {
  const con = await fakeConsole();
  const home = mkdtempSync(join(tmpdir(), "moorai-tb-serve-"));
  mkdirSync(join(home, "proj"), { recursive: true });
  writeFileSync(join(home, "policy.json"), JSON.stringify({ captureTier: "content-free", ...policy }));
  if (token) writeFileSync(join(home, "tokens"), `${TOKEN}\n`);
  let s = null, stopped = false;
  const stop = async () => { if (s && !stopped) { stopped = true; await s.stop(); } };
  try {
    s = await startServe(home, ["--policy-file", join(home, "policy.json"), ...(token ? ["--token-file", join(home, "tokens")] : [])], { MOORAI_SERVER_URL: `http://127.0.0.1:${con.port}`, MOORAI_INSTALL_TOKEN: "tok-tb-serve-1", MOORAI_TENANT: "t-tb" });
    const tk = token ? TOKEN : undefined;
    await fn({ task: (b) => req(s.listening, "/v1/task", b, tk), call: (b) => req(s.listening, "/v1/tool-call", b, tk), con, stop });
  } finally { await stop(); con.close(); rmTree(home); }
}

test("moorai-serve: cut(hand) is denied under block, cut(apple) allowed; report keeps the verdict and alerts once", async () => {
  await withServe({ intentAlignment: "block", ...ROBOT }, async ({ task, call }) => {
    await task({ session: "s1", prompt: TASK });
    const bad = await call({ tool: "cut", input: { target: "hand" }, session: "s1" });
    assert.equal(bad.json.decision, "deny");
    assert.deepEqual(bad.json.intent, { class: "object-not-in-task", mode: "block" });
    assert.ok(!bad.raw.includes("hand") && !bad.raw.includes(SECRET));
    assert.equal((await call({ tool: "cut", input: { target: "apple" }, session: "s1" })).json.decision, "allow");
    assert.equal((await call({ tool: "get_weather", input: { city: "Paris" }, session: "s1" })).json.decision, "allow", "a benign call");
    assert.equal((await call({ tool: "cut", input: { target: "apple" }, session: "never-sent" })).json.intent.class, "task-unknown", "no task fails closed");
  }, { token: true });
  await withServe(ROBOT, async ({ task, call, con, stop }) => {
    await task({ session: "s1", prompt: TASK });
    const r = await call({ tool: "cut", input: { target: "hand" }, session: "s1" });
    assert.equal(r.json.decision, "allow");
    assert.deepEqual(r.json.intent, { class: "object-not-in-task", mode: "report" });
    await call({ tool: "cut", input: { target: "hand" }, session: "s1" });
    await stop();
    const a = con.alerts.filter((x) => x.category === CATEGORY);
    assert.equal(a.length, 1);
    assert.equal(a[0].intent.class, "object-not-in-task");
    noLeak(con.alerts, "apple");
  });
});

test("moorai-serve: amounts — the task's amount and under the cap pass, over both is denied", async () => {
  await withServe({ intentAlignment: "block", ...ROBOT }, async ({ task, call }) => {
    await task({ session: "p1", prompt: "transfer 250 to account 4471" });
    assert.equal((await call({ tool: "transfer", input: { to_account: "4471", amount: 250 }, session: "p1" })).json.decision, "allow");
    assert.equal((await call({ tool: "transfer", input: { to_account: "4471", amount: 80 }, session: "p1" })).json.decision, "allow");
    assert.equal((await call({ tool: "transfer", input: { to_account: "4471", amount: 2500 }, session: "p1" })).json.decision, "deny");
  }, { token: true });
});

test("moorai-serve: task allowlists by task id and keywords; strictest wins; invalid denies; taskId validated", async () => {
  await withServe({ taskAllowlists: LISTS }, async ({ task, call }) => {
    assert.equal((await task({ session: "v1", taskId: "bad id!" })).status, 400);
    const set = await task({ session: "v1", prompt: "pay the vendor", taskId: "pay-vendor-1" });
    assert.equal(set.json.taskId, true);
    assert.equal((await call({ tool: "transfer", input: { amount: 400, to_account: "4471" }, session: "v1" })).json.decision, "allow", "the task id's entry");
    await task({ session: "v2", prompt: "harvest the orchard and pay", taskId: "pay-vendor-1" });
    assert.equal((await call({ tool: "transfer", input: { amount: 400, to_account: "4471" }, session: "v2" })).json.decision, "deny", "a task id only adds: the harvest keyword entry still holds transfer");
    const over = await call({ tool: "transfer", input: { amount: 900, to_account: "4471" }, session: "v1" });
    assert.equal(over.json.decision, "deny");
    assert.equal(over.json.configuredDecision, "deny", "the entry's default, not an ask the headless rule settled");
    assert.deepEqual(over.json.intent, { class: "outside-task-allowlist", mode: "deny", task: "pay-vendor" });
    await task({ session: "k1", prompt: "harvest the orchard" });
    assert.equal((await call({ tool: "cut", input: { target: "apple" }, session: "k1" })).json.decision, "allow");
    assert.equal((await call({ tool: "cut", input: { target: "hand" }, session: "k1" })).json.decision, "deny");
    await task({ session: "k2", prompt: "inspect the trees" });
    const ask = await call({ tool: "open_gate", input: {}, session: "k2" });
    assert.equal(ask.json.decision, "deny", "an ask with no approver is settled as a deny (headless)");
    assert.equal(ask.json.configuredDecision, "ask");
    await task({ session: "k3", prompt: "inspect then harvest" });
    assert.equal((await call({ tool: "move_to", input: { location: "dock" }, session: "k3" })).json.decision, "deny", "strictest wins");
    assert.equal((await call({ tool: "open_gate", input: {}, session: "nobody" })).json.decision, "allow", "no task, no keyword entry");
  }, { token: true });
  await withServe({ taskAllowlists: [{ task: "harvest", match: { keywords: ["harvest"] }, tools: "cut" }] }, async ({ task, call, con, stop }) => {
    await task({ session: "i1", prompt: "harvest the orchard" });
    assert.equal((await call({ tool: "get_status", input: {}, session: "i1" })).json.decision, "deny");
    assert.equal((await call({ tool: "get_status", input: {}, session: "i2" })).json.decision, "allow", "its match is readable: other tasks are not covered");
    await stop();
    assert.ok(con.alerts.some((a) => a.category === "Task-bound policy invalid" && a.taskBoundPolicy.problems.includes("taskAllowlists-tools")));
  });
});

// ---- Agent SDK ----

const { moorAIHooks } = await import(pathToFileURL(join(ROOT, "packages", "agent-sdk", "src", "index.mjs")).href);
function sdk(policy) {
  const bodies = [];
  const fetch = async (url, init) => { bodies.push(JSON.parse(init.body)); return { ok: true, status: 201 }; };
  const hooks = moorAIHooks({ policy: { captureTier: "content-free", ...policy }, console: { serverUrl: "http://console.invalid", tenant: "t", installToken: "tok-tb-sdk-1" }, fetch });
  const call = (event, input) => hooks[event][0].hooks[0]({ session_id: "s1", transcript_path: "", cwd: ROOT, permission_mode: "default", tool_use_id: "tu", ...input, hook_event_name: event }, "tu", { signal: AbortSignal.timeout(10000) });
  const decision = (o) => (o.hookSpecificOutput && o.hookSpecificOutput.permissionDecision) || "allow";
  return { hooks, call, decision, alerts: async () => { await hooks.moorai.flush(); return bodies; } };
}

test("Agent SDK: an SDK tool cut(hand) is denied under block after the prompt \"cut the apple\"; cut(apple) and a benign call pass", async () => {
  const s = sdk({ intentAlignment: "block", ...ROBOT });
  await s.call("UserPromptSubmit", { prompt: TASK });
  const bad = await s.call("PreToolUse", { tool_name: "mcp__robot__cut", tool_input: { target: "hand" } });
  assert.equal(s.decision(bad), "deny");
  assert.match(bad.hookSpecificOutput.permissionDecisionReason, /object your request never named/);
  assert.equal(s.decision(await s.call("PreToolUse", { tool_name: "mcp__robot__cut", tool_input: { target: "apple" } })), "allow");
  assert.equal(s.decision(await s.call("PreToolUse", { tool_name: "mcp__weather__get_forecast", tool_input: { city: "Paris" } })), "allow");
  assert.equal(s.decision(await s.call("PreToolUse", { session_id: "s-none", tool_name: "mcp__robot__cut", tool_input: { target: "apple" } })), "deny", "no task: task-unknown fails closed under block");
  noLeak(await s.alerts(), "apple");
});

test("Agent SDK: setTaskId selects the allowlist entry; a miss is denied", async () => {
  const s = sdk({ taskAllowlists: LISTS });
  await s.call("UserPromptSubmit", { prompt: "pay the vendor" });
  await s.hooks.moorai.setTaskId("s1", "pay-vendor-1");
  assert.equal(s.decision(await s.call("PreToolUse", { tool_name: "transfer", tool_input: { amount: 100, to_account: "4471" } })), "allow");
  assert.equal(s.decision(await s.call("PreToolUse", { tool_name: "transfer", tool_input: { amount: 100, to_account: "9999" } })), "deny");
  assert.equal(s.decision(await s.call("PreToolUse", { tool_name: "Bash", tool_input: { command: "ls" } })), "deny", "a tool the entry does not list");
});

// ---- the endpoint hook, MCP path ----

const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
async function withHook(policy, fn) {
  const con = await fakeConsole({ captureTier: "content-free", ...policy });
  const home = mkdtempSync(join(tmpdir(), "moorai-tb-hook-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${con.port}`, tenant: "acme", installToken: "tok-tb-hook" }));
  const run = async (payload) => {
    const child = spawn(process.execPath, [HOOK], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "", MOORAI_LOCAL_HOST: "http://127.0.0.1:9" } });
    let out = "";
    child.stdout.on("data", (c) => { out += c; });
    child.stderr.on("data", () => {});
    child.stdin.end(JSON.stringify(payload));
    await new Promise((r) => child.on("exit", r));
    const t = out.trim();
    const j = t ? JSON.parse(t) : null;
    return { json: j, decision: j?.hookSpecificOutput?.permissionDecision || "allow" };
  };
  const prompt = (session, text) => run({ hook_event_name: "UserPromptSubmit", session_id: session, prompt: text, source: "user" });
  const mcp = (session, tool, input) => run({ hook_event_name: "PreToolUse", session_id: session, tool_name: tool, tool_input: input });
  try { await fn({ prompt, mcp, alerts: con.alerts, home }); } finally { con.close(); rmTree(home); }
}
function allFiles(dir) {
  const out = [];
  for (const n of readdirSync(dir)) { const p = join(dir, n); if (statSync(p).isDirectory()) out.push(...allFiles(p)); else out.push(p); }
  return out;
}

test("hook MCP path: cut(hand) under \"cut the apple\" asks (intentAlignment ask), cut(apple) and a benign call allow; no task is silent", async () => {
  await withHook({ intentAlignment: "ask", ...ROBOT }, async ({ prompt, mcp, alerts, home }) => {
    await prompt("s1", TASK);
    const bad = await mcp("s1", "mcp__robot__cut", { target: "hand" });
    assert.equal(bad.decision, "ask");
    assert.match(bad.json.hookSpecificOutput.permissionDecisionReason, /object your request never named/);
    assert.equal((await mcp("s1", "mcp__robot__cut", { target: "apple" })).decision, "allow");
    assert.equal((await mcp("s1", "mcp__weather__get_forecast", { city: "Paris" })).decision, "allow");
    assert.equal((await mcp("s-none", "mcp__robot__cut", { target: "hand" })).decision, "allow", "no task captured: the hook never judges against nothing");
    assert.deepEqual(alerts.filter((a) => a.category === CATEGORY).map((a) => a.intent.class), ["object-not-in-task"]);
    noLeak(alerts, "apple");
    for (const f of allFiles(home)) assert.equal(readFileSync(f).includes(Buffer.from(SECRET)), false, `${f} holds prompt text`);
  });
});

test("hook MCP path: block denies cut(hand); report only alerts", async () => {
  await withHook({ intentAlignment: "block", ...ROBOT }, async ({ prompt, mcp }) => {
    await prompt("s1", TASK);
    assert.equal((await mcp("s1", "mcp__robot__cut", { target: "hand" })).decision, "deny");
  });
  await withHook(ROBOT, async ({ prompt, mcp, alerts }) => {
    await prompt("s1", TASK);
    assert.equal((await mcp("s1", "mcp__robot__cut", { target: "hand" })).decision, "allow");
    assert.equal(alerts.filter((a) => a.category === CATEGORY).length, 1);
  });
});

test("hook MCP path: a keyword allowlist entry denies a tool outside it; an invalid policy denies and alerts", async () => {
  await withHook({ intentAlignment: "off", taskAllowlists: [{ task: "harvest", match: { keywords: ["harvest"] }, tools: { "mcp__robot__cut": { args: { target: ["apple"] } } }, default: "deny" }] }, async ({ prompt, mcp }) => {
    await prompt("s1", "harvest the orchard");
    assert.equal((await mcp("s1", "mcp__robot__cut", { target: "apple" })).decision, "allow");
    assert.equal((await mcp("s1", "mcp__robot__cut", { target: "hand" })).decision, "deny");
    assert.equal((await mcp("s1", "mcp__robot__open_gate", {})).decision, "deny");
    assert.equal((await mcp("s2", "mcp__robot__open_gate", {})).decision, "allow", "no task: no keyword entry applies");
  });
  await withHook({ taskAllowlists: [{ task: "harvest", match: "harvest", tools: {} }] }, async ({ mcp, alerts }) => {
    assert.equal((await mcp("s9", "mcp__weather__get_forecast", { city: "Paris" })).decision, "deny", "an unreadable match covers every session");
    assert.ok(alerts.some((a) => a.category === "Task-bound policy invalid"));
  });
});
