// THE SUB-AGENT TOOL IS "Agent" NOW. Claude Code renamed its sub-agent tool from "Task" to "Agent" and
// kept "Task" only as an alias. Measured 2026-09-29:
//   code.claude.com/docs/en/hooks.md — PreToolUse "Matches on any tool name except `EndConversation`:
//   built-in tools such as `Bash`, `PowerShell`, `Edit`, `Write`, `Read`, `Glob`, `Grep`, `Agent`, …"
//   and a "##### Agent" tool-input section ("Spawns a subagent"; prompt, description, subagent_type).
//   The installed binaries 2.1.251, 2.1.263 and 2.1.265 all define the tool as name "Agent" with
//   aliases ["Task"].
// The PreToolUse #66 branch (sub-agent delegation: record the handoff, scan the delegated prompt, block
// per policy) only ever matched tool_name "Task", so on current Claude Code it never ran. The branch
// now takes both names; "Task" stays for older hosts and for the Codex/Copilot/Cursor/Gemini adapters,
// which translate their own sub-agent tools to "Task". Reports keep the label "hook:Task" so console
// views and envelope policies written against it keep matching.
//
//   node --test --import ./test/hermetic-env.mjs test/pretool-agent-name.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

function startServer(policy) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(policy)); }
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url.startsWith("/api/alerts")) { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.writeHead(200); res.end("{}"); });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, port: srv.address().port, alerts })));
}

function sandbox(port) {
  const home = mkdtempSync(join(tmpdir(), "moorai-agentname-home-"));
  const proj = mkdtempSync(join(tmpdir(), "moorai-agentname-proj-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: port ? `http://127.0.0.1:${port}` : "http://127.0.0.1:1", tenant: "acme", installToken: "tok-agent-name" }));
  return { home, proj };
}

function run(args, env, cwd, stdin) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [HOOK, ...args], { cwd, env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", () => {});
    c.on("close", (code) => resolve({ out, code }));
    if (stdin != null) c.stdin.end(stdin); else c.stdin.end();
  });
}

const pre = (tool) => JSON.stringify({
  hook_event_name: "PreToolUse", session_id: "sess-agent-name", cwd: "/tmp", tool_name: tool,
  tool_input: { description: "Find API endpoints", prompt: "Find all API endpoints in this repo", subagent_type: "Explore" }
});

async function preRun(policy, tool) {
  const { srv, port, alerts } = await startServer(policy);
  const sb = sandbox(port);
  const r = await run([], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, sb.proj, pre(tool));
  await new Promise((res) => setTimeout(res, 300));
  srv.close();
  const o = r.out.trim() ? JSON.parse(r.out).hookSpecificOutput || {} : {};
  return { code: r.code, decision: o.permissionDecision || "allow", reason: o.permissionDecisionReason || "", alerts };
}

const BLOCK_66 = { captureTier: "content-free", threatPolicy: { 66: "block" } };
const OPEN = { captureTier: "content-free", threatPolicy: {} };
const delegations = (alerts) => alerts.filter((a) => a.threatId === 66 && a.tool === "hook:Task");

test("Agent: a policy blocking #66 denies the sub-agent spawn", async () => {
  const r = await preRun(BLOCK_66, "Agent");
  assert.equal(r.code, 0);
  assert.equal(r.decision, "deny", JSON.stringify(r));
  assert.match(r.reason, /sub-agent delegation/);
});

test("Task (older hosts, the four adapters): the same policy still denies", async () => {
  const r = await preRun(BLOCK_66, "Task");
  assert.equal(r.decision, "deny", JSON.stringify(r));
  assert.match(r.reason, /sub-agent delegation/);
});

test("Agent: an allowed spawn is still recorded as a #66 delegation under the stable label hook:Task", async () => {
  const r = await preRun(OPEN, "Agent");
  assert.equal(r.decision, "allow", JSON.stringify(r));
  assert.equal(delegations(r.alerts).length, 1, JSON.stringify(r.alerts.map((a) => [a.threatId, a.tool])));
});

test("install registers PreToolUse for both Agent and Task", async () => {
  const sb = sandbox(null);
  await run(["install"], { HOME: sb.home, USERPROFILE: sb.home }, sb.proj, null);
  const s = JSON.parse(readFileSync(join(sb.home, ".claude", "settings.json"), "utf8"));
  const m = (s.hooks?.PreToolUse || []).filter((e) => JSON.stringify(e).includes("moorai-hook")).map((e) => e.matcher);
  for (const want of ["Agent", "Task"]) assert.ok(m.includes(want), `PreToolUse must cover ${want}; got ${JSON.stringify(m)}`);
});

test("an install with only the old PreToolUse list gains Agent on an ordinary call; other hooks survive", async () => {
  const { srv, port } = await startServer(OPEN);
  const sb = sandbox(port);
  const entry = (matcher) => ({ matcher, hooks: [{ type: "command", command: `node ${HOOK}` }] });
  const OLD = ["Read", "Bash", "mcp__.*", "Task", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch"];
  mkdirSync(join(sb.home, ".claude"), { recursive: true });
  writeFileSync(join(sb.home, ".claude", "settings.json"), JSON.stringify({ hooks: {
    PreToolUse: [...OLD.map(entry), { matcher: "Bash", hooks: [{ type: "command", command: "echo someone-else" }] }],
    Stop: [{ hooks: [{ type: "command", command: "echo other" }] }]
  } }));
  await run([], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, sb.proj, JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s", cwd: "/tmp", tool_name: "Bash", tool_input: { command: "ls" } }));
  srv.close();
  const s = JSON.parse(readFileSync(join(sb.home, ".claude", "settings.json"), "utf8"));
  const mine = (s.hooks?.PreToolUse || []).filter((e) => JSON.stringify(e).includes("moorai-hook")).map((e) => e.matcher);
  assert.ok(mine.includes("Agent"), `convergeHooks must add Agent; got ${JSON.stringify(mine)}`);
  assert.ok(mine.includes("Task"), "Task stays registered for older hosts");
  assert.ok((s.hooks.PreToolUse || []).some((e) => JSON.stringify(e).includes("echo someone-else")), "another tool's PreToolUse hook survives");
  assert.equal(s.hooks.Stop?.[0]?.hooks?.[0]?.command, "echo other");
});
