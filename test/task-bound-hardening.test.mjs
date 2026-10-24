// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/task-bound-hardening.test.mjs
//
// Task-bound hardening (data/task-bound.js, data/intent-server.mjs, cli/task-bound-hook.mjs, model-proxy):
//   1. an allowlist entry a task selects cannot be lost: matched entries are recorded at capture from the WHOLE
//      prompt (a 1 MB prompt, a long earlier prompt), and the hook's state is HMAC'd with a key derived from the
//      device signing key — a missing, unreadable or edited state fails closed for the tools an allowlist covers;
//   2. argument keys are read the way a tool could read them: a key equal to a listed key only after folding
//      case, `_` and `-` is a collision, a dotted key is read both literally and nested, and arguments an entry
//      does not list are held by default (unlistedArgs "deny"). The object check reads every folded / nested
//      value too.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import * as tb from "../data/task-bound.js";
import { createIntentStore } from "../data/intent-server.mjs";
import { createProxy } from "../model-proxy/server.mjs";
import { startFakeProvider, sendJson, anthropicMessage } from "../model-proxy/test/fake-provider.mjs";
import { request } from "../model-proxy/test/harness.mjs";
import { SESSION_ID_HEADER } from "../model-proxy/intent.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HARVEST = { task: "harvest", match: { keywords: ["harvest"] }, tools: { cut: { args: { target: ["apple"] } } }, default: "deny" };
const FILLER = "lorem ipsum dolor sit amet ".repeat(40000); // ~1 MB
const outcome = (entry, tool, input) => {
  const [e] = tb.resolveTaskBound({ taskAllowlists: [entry] }).lists;
  return tb.entryOutcome(e, tool, input);
};
const objects = (task, tool, input, intentArgs) => {
  const terms = new Set(tb.taskTerms(task));
  const checks = tb.objectChecks(tool, input, tb.resolveTaskBound({ intentArgs }).args);
  return tb.judgeObjects(checks, (t) => terms.has(t)).aligned;
};

// ---- 2. argument keys ----

test("allowlist: a key equal to a listed key only after folding case, _ and - is a collision", () => {
  assert.deepEqual(outcome(HARVEST, "cut", { target: "apple" }), { outcome: "allow", reason: "" });
  assert.equal(outcome(HARVEST, "cut", { target: "apple", Target: "hand" }).reason, "argument-key-collision");
  assert.equal(outcome(HARVEST, "cut", { target: "apple", "tar-get": "hand" }).reason, "argument-key-collision");
  assert.equal(outcome(HARVEST, "cut", { TARGET: "apple" }).reason, "argument-key-collision", "even alone");
});

test("allowlist: a dotted key is read both literally and nested; both must be absent or allowed", () => {
  const e = { ...HARVEST, tools: { cut: { args: { "arm.target": ["apple"] } } } };
  assert.equal(outcome(e, "cut", { arm: { target: "apple" } }).outcome, "allow");
  assert.equal(outcome(e, "cut", { "arm.target": "apple" }).outcome, "allow");
  assert.equal(outcome(e, "cut", { "arm.target": "apple", arm: { target: "hand" } }).reason, "argument-not-allowed");
  assert.equal(outcome(e, "cut", { arm: { target: "apple" }, "arm.target": "hand" }).reason, "argument-not-allowed");
  assert.equal(outcome(e, "cut", { arm: { target: "apple", Target: "hand" } }).reason, "argument-key-collision");
  assert.equal(outcome(e, "cut", { ARM: { target: "hand" } }).reason, "argument-key-collision");
});

test("allowlist: unlistedArgs — an argument the tool spec does not list is held by default; \"allow\" lets it through", () => {
  assert.equal(outcome(HARVEST, "cut", { target: "apple", force: 900 }).reason, "argument-not-listed");
  assert.equal(outcome({ ...HARVEST, default: "ask" }, "cut", { target: "apple", force: 900 }).outcome, "ask", "an ask entry asks");
  assert.equal(outcome({ ...HARVEST, unlistedArgs: "allow" }, "cut", { target: "apple", force: 900 }).outcome, "allow");
  assert.equal(outcome({ ...HARVEST, unlistedArgs: "allow" }, "cut", { target: "apple", Target: "hand" }).reason, "argument-key-collision", "a collision is held either way");
  assert.equal(outcome({ ...HARVEST, unlistedArgs: "maybe" }, "cut", { target: "apple" }).reason, "invalid-policy");
  const nested = { ...HARVEST, tools: { cut: { args: { "arm.target": ["apple"] } } } };
  assert.equal(outcome(nested, "cut", { arm: { target: "apple", speed: 9 } }).reason, "argument-not-listed", "under a listed dotted path too");
  assert.equal(outcome({ ...HARVEST, tools: { cut: true } }, "cut", { anything: 1 }).outcome, "allow", "true still takes any arguments");
});

test("object check: every folded and nested value of an object field must be named", () => {
  assert.equal(objects("cut the apple", "cut", { target: "apple", Target: "hand" }, { cut: ["target"] }), false);
  assert.equal(objects("cut the apple", "cut", { "arm.target": "apple", arm: { target: "hand" } }, { cut: ["arm.target"] }), false);
  assert.equal(objects("cut the apple", "cut", { arm: { target: "apple" } }, { cut: ["arm.target"] }), true);
  assert.equal(objects("email the report to bob@corp.example", "send_email", { to: "bob@corp.example", To: "eve@evil.example" }, undefined), false, "a built-in field");
});

// ---- 1. selection cannot be lost ----

test("matched entries come from the whole prompt: a 1 MB prompt names its keyword at the very end", () => {
  assert.equal(typeof tb.entriesNamedIn, "function");
  const lists = tb.resolveTaskBound({ taskAllowlists: [HARVEST] }).lists;
  assert.deepEqual(tb.entriesNamedIn(lists, `${FILLER} now harvest the orchard`).map((e) => e.task), ["harvest"]);
  const s = createIntentStore({});
  s.captureTask("s1", `${FILLER} now harvest the orchard`, "", { bound: { policy: { taskAllowlists: [HARVEST] } } });
  assert.equal(s.judgeBound("s1", "open_gate", {}, { policy: { taskAllowlists: [HARVEST] } }).allowlist?.decision, "deny");
});

let fp;
before(async () => { fp = await startFakeProvider(); });
after(async () => { await fp?.close(); });

test("model proxy: a keyword past the first 20,000 characters of the person's turn still selects its entry", async () => {
  const px = await createProxy({ port: 0, mode: "enforce", policy: { taskAllowlists: [HARVEST] }, routes: { "/anthropic": fp.url }, systemConfig: null, env: {} });
  try {
    fp.on((r, res) => sendJson(res, anthropicMessage({ tools: [{ name: "open_gate", input: {} }] })));
    const body = { model: "m", max_tokens: 8, tools: [{ name: "open_gate", input_schema: { type: "object" } }], messages: [{ role: "user", content: `${"lorem ipsum ".repeat(3000)} harvest the orchard` }] };
    const r = await request(px.url, "/anthropic/v1/messages", { body, headers: { "anthropic-version": "2023-06-01", [SESSION_ID_HEADER]: "long-1" } });
    assert.equal(r.status, 403);
  } finally { await px.close(); }
});

test("Agent SDK: a 1 MB prompt with the keyword at its end selects the entry", async () => {
  const { moorAIHooks } = await import(pathToFileURL(join(ROOT, "packages", "agent-sdk", "src", "index.mjs")).href);
  const hooks = moorAIHooks({ policy: { captureTier: "content-free", taskAllowlists: [HARVEST] }, fetch: async () => ({ ok: true, status: 201 }), console: { serverUrl: "http://console.invalid", tenant: "t", installToken: "tok-tb-hard-1" } });
  const call = (event, input) => hooks[event][0].hooks[0]({ session_id: "s1", transcript_path: "", cwd: ROOT, permission_mode: "default", ...input, hook_event_name: event }, "tu", { signal: AbortSignal.timeout(20000) });
  await call("UserPromptSubmit", { prompt: `${FILLER} now harvest the orchard` });
  const v = await call("PreToolUse", { tool_name: "open_gate", tool_input: {} });
  assert.equal(v.hookSpecificOutput?.permissionDecision, "deny");
});

// ---- the hook ----

const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
async function withHook(policy, fn) {
  const alerts = [];
  const srv = http.createServer((q, r) => {
    let b = ""; q.on("data", (d) => (b += d));
    q.on("end", () => {
      if (q.url.startsWith("/api/policy")) { r.writeHead(200, { "Content-Type": "application/json" }); r.end(JSON.stringify({ captureTier: "content-free", ...policy })); return; }
      if (q.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } }
      r.writeHead(201); r.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const home = mkdtempSync(join(tmpdir(), "moorai-tb-hard-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${srv.address().port}`, tenant: "acme", installToken: "tok-tb-hard" }));
  const run = async (payload) => {
    const child = spawn(process.execPath, [HOOK], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "", MOORAI_LOCAL_HOST: "http://127.0.0.1:9" } });
    let out = "";
    child.stdout.on("data", (c) => { out += c; });
    child.stderr.on("data", () => {});
    child.stdin.end(JSON.stringify(payload));
    await new Promise((r) => child.on("exit", r));
    const t = out.trim();
    return t ? JSON.parse(t).hookSpecificOutput?.permissionDecision || "allow" : "allow";
  };
  const prompt = (session, text) => run({ hook_event_name: "UserPromptSubmit", session_id: session, prompt: text, source: "user" });
  const mcp = (session, tool, input) => run({ hook_event_name: "PreToolUse", session_id: session, tool_name: tool, tool_input: input });
  const state = join(home, ".moorai", "task-terms.json");
  try { await fn({ prompt, mcp, alerts, state, home }); } finally { srv.close(); rmTree(home); }
}
const MCP_HARVEST = { taskAllowlists: [{ ...HARVEST, tools: { "mcp__robot__cut": { args: { target: ["apple"] } } } }] };
const tamperAlerts = (alerts) => alerts.filter((a) => a.category === "Task-bound state tampered");

test("hook: a 1 MB prompt with the keyword at its end, and a keyword after a long earlier prompt, both select the entry", async () => {
  await withHook(MCP_HARVEST, async ({ prompt, mcp }) => {
    await prompt("s1", `${FILLER} now harvest the orchard`);
    assert.equal(await mcp("s1", "mcp__robot__open_gate", {}), "deny");
    assert.equal(await mcp("s1", "mcp__robot__cut", { target: "apple" }), "allow");
    const many = Array.from({ length: 3000 }, (_, i) => `w${i}x`).join(" ");
    await prompt("s2", many);
    await prompt("s2", "harvest the orchard");
    assert.equal(await mcp("s2", "mcp__robot__open_gate", {}), "deny", "the long first prompt cannot crowd out the second's keyword");
    await prompt("s3", "harvest the orchard");
    await prompt("s3", FILLER);
    assert.equal(await mcp("s3", "mcp__robot__open_gate", {}), "deny", "a 1 MB later prompt cannot evict the selecting terms");
  });
});

test("hook: an earlier prompt's phrases cannot crowd a later prompt's words out of the object check", async () => {
  await withHook({ intentAlignment: "ask", intentArgs: { cut: ["target"] } }, async ({ prompt, mcp }) => {
    await prompt("s1", Array.from({ length: 400 }, (_, i) => `w${i}x`).join(" "));
    await prompt("s1", "now cut the apple");
    assert.equal(await mcp("s1", "mcp__robot__cut", { target: "apple" }), "allow");
    assert.equal(await mcp("s1", "mcp__robot__cut", { target: "hand" }), "ask");
  });
});

test("hook: a deleted, edited or unreadable state fails closed for covered tools, with a content-free alert", async () => {
  await withHook(MCP_HARVEST, async ({ prompt, mcp, alerts, state }) => {
    await prompt("s1", "harvest the orchard");
    assert.ok(existsSync(state));
    rmSync(state);
    assert.equal(await mcp("s1", "mcp__robot__open_gate", {}), "deny", "deleted");
    assert.equal(await mcp("s1", "mcp__robot__cut", { target: "apple" }), "allow", "a call every entry allows is not held");
    assert.ok(tamperAlerts(alerts).length >= 1);
    assert.ok(!JSON.stringify(tamperAlerts(alerts)).includes("harvest the orchard"));
  });
  await withHook(MCP_HARVEST, async ({ prompt, mcp, alerts, state }) => {
    await prompt("s1", "harvest the orchard");
    const o = JSON.parse(readFileSync(state, "utf8"));
    o.s = {}; if (o.m) o.m = {};
    writeFileSync(state, JSON.stringify(o));
    assert.equal(await mcp("s1", "mcp__robot__open_gate", {}), "deny", "edited (the session's records removed)");
    assert.ok(tamperAlerts(alerts).length >= 1);
  });
  await withHook(MCP_HARVEST, async ({ prompt, mcp, state }) => {
    await prompt("s1", "harvest the orchard");
    writeFileSync(state, "{not json");
    assert.equal(await mcp("s1", "mcp__robot__open_gate", {}), "deny", "unreadable");
  });
});

test("hook: after a tamper, the next capture does not reopen the sessions the old state held; a fresh device is not 'tampered'", async () => {
  await withHook(MCP_HARVEST, async ({ prompt, mcp, state }) => {
    await prompt("s1", "harvest the orchard");
    rmSync(state);
    await prompt("s3", "write a poem");
    assert.equal(await mcp("s1", "mcp__robot__open_gate", {}), "deny", "s1's record was lost: still closed");
    assert.equal(await mcp("s3", "mcp__robot__open_gate", {}), "allow", "a session captured after the tamper is judged normally");
  });
  await withHook(MCP_HARVEST, async ({ mcp, alerts }) => {
    assert.equal(await mcp("s9", "mcp__robot__open_gate", {}), "allow", "never captured on this device: no task, nothing tampered");
    assert.equal(await mcp("s9", "mcp__robot__open_gate", {}), "allow", "and the judge did not create the witness key");
    assert.equal(tamperAlerts(alerts).length, 0);
  });
});
