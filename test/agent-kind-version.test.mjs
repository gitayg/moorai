// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/agent-kind-version.test.mjs
//
// Agent identity Phase 1a (docs/proposals/agent-identity.md): every alert names the agent it is about
// (`agentName`, the console's agent_name vocabulary) and, where that agent states it, the agent
// product's own version (`agentVersion`). MEASURED BEFORE THIS CHANGE: no sender put a version on an
// alert, and moorai-guard, the stdio MCP proxy and the SDK runtime surfaces sent no agentName.
//
// Version sources (cli/agent-names.mjs), each measured:
//   Claude Code  AI_AGENT=claude-code_<v-dashed>_harness in hook and stdio-MCP env (live run, 2.1.295)
//   Cursor       CURSOR_VERSION in hook env (cursor.com/docs/hooks "Always"; cursor-agent bundle)
//   Codex, Gemini, Copilot: none in payload or env, so no version is sent.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { AGENT_NAMES, AGENT_VERSION_RE, agentNameOf, cleanAgentVersion, claudeCodeVersion, cursorVersion, agentVersionFromEnv } from "../cli/agent-names.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TOKEN = "tok-agent-kind-version";
const AWS = "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const CC = "claude-code_2-1-295_harness";
const CURSOR = "2026.05.27-fe9a6e2";

async function listener() {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); res.end(); return; }
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ captureTier: "content-free" })); return; }
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => { if (req.url === "/api/alerts") { try { alerts.push(JSON.parse(body)); } catch { /* ignore */ } } res.writeHead(200); res.end("{}"); });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { alerts, url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
}

function home(url) {
  const h = mkdtempSync(join(tmpdir(), "moorai-akv-"));
  mkdirSync(join(h, ".moorai"), { recursive: true });
  writeFileSync(join(h, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "acme", installToken: TOKEN }));
  return h;
}
const envFor = (h, extra) => {
  const e = { ...process.env, HOME: h, USERPROFILE: h, MOORAI_OFFLINE_MODE: "", MOORAI_HOOK_HOST: "", MOORAI_HOOK_AGENT: "", ...extra };
  for (const k of Object.keys(e)) if (e[k] === undefined) delete e[k];
  return e;
};

async function run(args, h, extra, stdin) {
  const child = spawn(process.execPath, args, { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env: envFor(h, extra) });
  child.stdout.on("data", () => {}); child.stderr.on("data", () => {});
  child.stdin.end(stdin == null ? "" : stdin);
  await new Promise((r) => child.on("exit", r));
  await new Promise((r) => setTimeout(r, 300));
}

// One leaking Bash call through the Claude Code hook, with the given environment.
async function hookAlerts(extra) {
  const L = await listener(); const h = home(L.url);
  try {
    await run([HOOK], h, extra, JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s-akv", cwd: h, tool_name: "Bash", tool_input: { command: `echo ${AWS}` } }));
    assert.ok(L.alerts.length > 0, "the hook posted nothing");
    return L.alerts;
  } finally { L.close(); rmTree(h); }
}
const only = (alerts, key) => [...new Set(alerts.map((a) => a[key]))];

test("agent-names: the version pattern is strict and content-free", () => {
  for (const ok of ["2.1.295", CURSOR, "0.154.0", "1.0.63+build.7"]) assert.equal(cleanAgentVersion(ok), ok);
  for (const bad of ["", "a".repeat(33), "/Users/alice/x", "alice@example.com", "2.1 beta", "1.0;rm -rf", null, 7, { v: 1 }]) assert.equal(cleanAgentVersion(bad), undefined, String(bad));
  assert.equal(AGENT_VERSION_RE.source, "^[0-9A-Za-z.+-]{1,32}$");
});

test("agent-names: Claude Code's version only from the _harness AI_AGENT form", () => {
  assert.equal(claudeCodeVersion({ AI_AGENT: CC }), "2.1.295");
  assert.equal(claudeCodeVersion({ AI_AGENT: "claude-code_2-1-295_agent" }), undefined, "a Bash-tool child, not the harness");
  assert.equal(claudeCodeVersion({ AI_AGENT: "codex_1-2-3" }), undefined);
  assert.equal(claudeCodeVersion({}), undefined);
  assert.equal(cursorVersion({ CURSOR_VERSION: CURSOR }), CURSOR);
  assert.equal(cursorVersion({ CURSOR_VERSION: "1.0.0" }), undefined, "cursor-agent's no-version fallback");
  assert.equal(cursorVersion({ CURSOR_VERSION: "alice@example.com" }), undefined);
  for (const k of ["codex", "gemini", "copilot", "agent-sdk", "gateway"]) assert.equal(agentVersionFromEnv(k, { AI_AGENT: CC, CURSOR_VERSION: CURSOR }), undefined, k);
});

test("HOOK (Claude Code): agentName claude-code and agentVersion from AI_AGENT", async () => {
  const alerts = await hookAlerts({ AI_AGENT: CC, CURSOR_VERSION: CURSOR });
  assert.deepEqual(only(alerts, "agentName"), ["claude-code"]);
  assert.deepEqual(only(alerts, "agentVersion"), ["2.1.295"]);
});

test("HOOK (Claude Code): no agentVersion when AI_AGENT is a Bash-tool child's, a foreign host's, or absent", async () => {
  for (const AI_AGENT of ["claude-code_2-1-295_agent", "codex_1-2-3", undefined]) {
    const alerts = await hookAlerts({ AI_AGENT });
    assert.deepEqual(only(alerts, "agentName"), ["claude-code"]);
    assert.deepEqual(only(alerts, "agentVersion"), [undefined], `AI_AGENT=${AI_AGENT}`);
  }
});

test("HOOK (Cursor via its adapter): agentName cursor and agentVersion from CURSOR_VERSION", async () => {
  const L = await listener(); const h = home(L.url);
  try {
    const payload = { hook_event_name: "beforeShellExecution", conversation_id: "c-akv", generation_id: "g", cursor_version: CURSOR, workspace_roots: [h], user_email: "alice@example.com", command: `echo ${AWS}`, cwd: h, sandbox: false };
    await run([join(ROOT, "cli", "moorai-agent-hook.mjs"), "cursor"], h, { CURSOR_VERSION: CURSOR, AI_AGENT: CC }, JSON.stringify(payload));
    assert.ok(L.alerts.length > 0, "nothing posted");
    assert.deepEqual(only(L.alerts, "agentName"), ["cursor"]);
    assert.deepEqual(only(L.alerts, "agentVersion"), [CURSOR], "Cursor's version, never the inherited Claude Code AI_AGENT");
    assert.ok(!JSON.stringify(L.alerts).includes("alice@example.com"), "user_email never reaches the console");
  } finally { L.close(); rmTree(h); }
});

test("HOOK (Codex, Gemini, Copilot via the shim): agentName only; an inherited AI_AGENT or CURSOR_VERSION is never their version", async () => {
  for (const agent of ["codex", "gemini", "copilot"]) {
    const alerts = await hookAlerts({ MOORAI_HOOK_HOST: "shim", MOORAI_HOOK_AGENT: agent, AI_AGENT: CC, CURSOR_VERSION: CURSOR });
    assert.deepEqual(only(alerts, "agentName"), [agent]);
    assert.deepEqual(only(alerts, "agentVersion"), [undefined], agent);
  }
});

test("HOOK: a hostile CURSOR_VERSION (path, email) is dropped, not sent", async () => {
  for (const v of ["/Users/alice/secret/project", "alice@example.com"]) {
    const alerts = await hookAlerts({ MOORAI_HOOK_HOST: "shim", MOORAI_HOOK_AGENT: "cursor", CURSOR_VERSION: v });
    assert.deepEqual(only(alerts, "agentVersion"), [undefined]);
    assert.ok(!JSON.stringify(alerts).includes(v));
  }
});

async function proxyAlerts(hostArgs, extra) {
  const L = await listener(); const h = home(L.url);
  const recv = join(h, "recv.log");
  try {
    const child = spawn(process.execPath, [join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs"), "--server", "testsrv", ...hostArgs, "--", process.execPath, join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs"), recv],
      { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env: envFor(h, extra) });
    child.stderr.on("data", () => {});
    let out = "";
    child.stdout.on("data", (c) => (out += c));
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { msg: AWS } } }) + "\n");
    const deadline = Date.now() + 8000;
    while (!out.includes('"id":1') && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));
    await new Promise((r) => setTimeout(r, 1200));
    child.stdin.end(); child.kill();
    assert.ok(L.alerts.length > 0, "the proxy posted nothing");
    return L.alerts;
  } finally { L.close(); rmTree(h); }
}

test("STDIO MCP PROXY: agentName from the install's --host stamp, agentVersion only for Claude Code", async () => {
  let a = await proxyAlerts(["--host", "claude-code"], { AI_AGENT: CC });
  assert.deepEqual(only(a, "agentName"), ["claude-code"]);
  assert.deepEqual(only(a, "agentVersion"), ["2.1.295"]);
  a = await proxyAlerts(["--host", "claude-desktop"], { AI_AGENT: CC, CURSOR_VERSION: CURSOR });
  assert.deepEqual(only(a, "agentName"), ["claude-desktop"]);
  assert.deepEqual(only(a, "agentVersion"), [undefined]);
  a = await proxyAlerts(["--host", "cursor"], { CURSOR_VERSION: CURSOR });
  assert.deepEqual(only(a, "agentName"), ["cursor"]);
  assert.deepEqual(only(a, "agentVersion"), [undefined], "not verified that Cursor sets CURSOR_VERSION for MCP servers");
  for (const host of [["--host", "vscode"], []]) {
    a = await proxyAlerts(host, { AI_AGENT: CC });
    assert.deepEqual(only(a, "agentName"), [undefined], `host ${host.join(" ") || "(none)"} names no agent`);
    assert.deepEqual(only(a, "agentVersion"), [undefined]);
  }
});

test("MOORAI-GUARD: alerts name Claude Code, with no version", async () => {
  const L = await listener(); const h = home(L.url);
  try {
    await run([join(ROOT, "cli", "moorai-guard.mjs"), "--decide", "abort", `deploy with ${AWS}`], h, { AI_AGENT: CC });
    assert.ok(L.alerts.length > 0, "the guard posted nothing");
    assert.deepEqual(only(L.alerts, "agentName"), ["claude-code"]);
    assert.deepEqual(only(L.alerts, "agentVersion"), [undefined], "the guard's AI_AGENT is its parent's, not the claude it wraps");
  } finally { L.close(); rmTree(h); }
});

test("SDK RUNTIME: agentName is the surface for every MoorAI surface", async () => {
  const { createMoorAI } = await import("../packages/agent-sdk/src/runtime.mjs");
  for (const surface of ["agent-sdk", "serve", "model-proxy", "inference-hook"]) {
    const rt = await createMoorAI({ surface, policy: {}, fetch: async () => ({ ok: true }), env: { ...process.env, AI_AGENT: CC } });
    assert.equal(rt.identity.surface, surface);
    assert.equal(rt.identity.agentName, surface);
    assert.equal(rt.identity.agentVersion, undefined);
  }
  const rt = await createMoorAI({ policy: {}, fetch: async () => ({ ok: true }) });
  assert.equal(rt.identity.agentName, "agent-sdk", "the default surface");
});

test("VOCABULARY: every agentName a sender stamps is in AGENT_NAMES", async () => {
  const hook = readFileSync(HOOK, "utf8");
  const beat = JSON.parse(/const BEAT_HOSTS = (\[[^\]]*\])/.exec(hook)[1]);
  for (const n of beat) assert.ok(agentNameOf(n), `hook host ${n}`);
  assert.match(readFileSync(join(ROOT, "mcp-gateway", "report.mjs"), "utf8"), /agentName: "gateway"/);
  assert.match(readFileSync(join(ROOT, "cli", "moorai-guard.mjs"), "utf8"), /agentName: "claude-code"/);
  for (const n of ["gateway", "claude-code", "claude-desktop", "agent-sdk", "serve", "model-proxy", "inference-hook"]) assert.ok(AGENT_NAMES.includes(n), n);
});

// The console stores null for any name outside its own list, so the agent's list must be a subset.
const CONSOLE_DIR = process.env.MOORAI_CONSOLE_DIR || resolve(ROOT, "..", "RAISEME-server");
const CONSOLE_FIELDS = join(CONSOLE_DIR, "server", "siem-fields.js");
test("VOCABULARY: the agent's AGENT_NAMES and version pattern match the console's", { skip: existsSync(CONSOLE_FIELDS) ? false : `no console at ${CONSOLE_DIR} (set MOORAI_CONSOLE_DIR)` }, async () => {
  const c = await import(pathToFileURL(CONSOLE_FIELDS).href);
  for (const n of AGENT_NAMES) assert.ok(c.AGENT_NAMES.includes(n), `console AGENT_NAMES lacks ${n}`);
  assert.equal(c.AGENT_VERSION_RE.source, AGENT_VERSION_RE.source);
});
