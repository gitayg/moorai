// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/hook-alert-identity.test.mjs
//
// Two content-free identity fields on hook alerts.
//  1. #66 `subagentType`. A custom sub-agent's type name (`.claude/agents/acme-merger-review.md`) is
//     content. MEASURED BEFORE THIS CHANGE: sent in clear (docs/proposals/agent-identity.md §8.1, §9 Q1).
//     Claude Code's built-in types stay in clear; anything else is the keyed contentHash (`h2:` + 16
//     hex, the hash SESSION uses), so it joins the handoff edge's `to: contentHash(subagent_type)`.
//  2. `agentName`. The console fills `agent_name` from it (RAISEME-server server/siem-fields.js,
//     vocabulary claude-code, codex, cursor, gemini, copilot, agent-sdk, serve, gateway). MEASURED
//     BEFORE THIS CHANGE: hook alerts carried no agentName.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import http from "node:http";
import { evaluate } from "../cli/agent-hooks/shim.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TOKEN = "tok-alert-identity";
// The keyed contentHash, recomputed independently (cli/content-hash.mjs).
const keyed = (s) => "h2:" + createHmac("sha256", createHmac("sha256", TOKEN).update("moorai/content-hash/v2", "utf8").digest()).update(String(s), "utf8").digest("hex").slice(0, 16);

function startServer() {
  const alerts = [];
  const policy = { captureTier: "content-free", threatPolicy: {} };
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(policy)); }
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url.startsWith("/api/alerts")) { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.writeHead(200); res.end("{}"); });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, port: srv.address().port, alerts })));
}

function sandbox(port) {
  const home = mkdtempSync(join(tmpdir(), "moorai-ident-home-"));
  const proj = mkdtempSync(join(tmpdir(), "moorai-ident-proj-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: TOKEN }));
  return { home, proj };
}

function runHook(env, cwd, stdin) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [HOOK], { cwd, env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "ignore"] });
    c.stdout.on("data", () => {});
    c.on("close", resolve);
    c.stdin.end(stdin);
  });
}

const spawnPayload = (type) => ({
  hook_event_name: "PreToolUse", session_id: "sess-ident", cwd: "/tmp", tool_name: "Agent",
  tool_input: { description: "Review the deal", prompt: "Summarise the open items", subagent_type: type }
});

async function alertsFor(payload, env = {}) {
  const { srv, port, alerts } = await startServer();
  const sb = sandbox(port);
  await runHook({ HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "", MOORAI_HOOK_HOST: "", MOORAI_HOOK_AGENT: "", ...env }, sb.proj, JSON.stringify(payload));
  await new Promise((r) => setTimeout(r, 200));
  srv.close();
  return alerts;
}
const delegation = (alerts) => alerts.find((a) => a.threatId === 66);

test("#66: a Claude Code built-in sub-agent type is sent in clear", async () => {
  for (const t of ["general-purpose", "Explore", "Plan"]) {
    const a = delegation(await alertsFor(spawnPayload(t)));
    assert.ok(a, `no #66 alert for ${t}`);
    assert.equal(a.subagentType, t);
  }
});

test("#66: a custom sub-agent type is the keyed contentHash, never the name", async () => {
  const alerts = await alertsFor(spawnPayload("acme-merger-review"));
  const a = delegation(alerts);
  assert.ok(a, "no #66 alert");
  assert.match(a.subagentType, /^h2:[0-9a-f]{16}$/);
  assert.equal(a.subagentType, keyed("acme-merger-review"), "the same keyed hash the handoff edge uses");
  assert.ok(!JSON.stringify(alerts).includes("acme-merger-review"), "the name appears in no alert");
});

test("agentName: a Claude Code hook alert says claude-code", async () => {
  const a = delegation(await alertsFor(spawnPayload("Explore")));
  assert.equal(a.agentName, "claude-code");
});

test("agentName: an adapter's alert names that adapter (shim path), and an unknown host names none", async () => {
  for (const agent of ["cursor", "codex", "gemini", "copilot"]) {
    const { srv, port, alerts } = await startServer();
    const sb = sandbox(port);
    evaluate({ hook_event_name: "PreToolUse", session_id: "sess-ident", cwd: sb.proj, tool_name: "Task", tool_input: { prompt: "x", subagent_type: "Explore" } },
      { env: { ...process.env, HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "", MOORAI_HOOK_AGENT: agent } });
    await new Promise((r) => setTimeout(r, 200));
    srv.close();
    const a = delegation(alerts);
    assert.ok(a, `no #66 alert via ${agent}`);
    assert.equal(a.agentName, agent);
  }
  const alerts = await alertsFor(spawnPayload("Explore"), { MOORAI_HOOK_HOST: "shim", MOORAI_HOOK_AGENT: "not-an-agent" });
  assert.equal(delegation(alerts).agentName, undefined, "no value outside the console vocabulary");
});

test("agentName: the HTTP MCP gateway stamps gateway on its identity", async () => {
  const { IDENTITY } = await import("../mcp-gateway/report.mjs");
  assert.equal(IDENTITY.agentName, "gateway");
});
