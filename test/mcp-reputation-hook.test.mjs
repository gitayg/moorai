// End to end through the real hook (cli/moorai-hook.mjs): an mcp__<label>__<tool> call resolves the
// label to its launch config, scores the server offline, reports first sight, and refuses only when the
// org policy sets mcpReputation.blockBelow on an enrolled device.
//
//   node --test test/mcp-reputation-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { REPUTATION_CATEGORY } from "../data/mcp-reputation.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const SECRET_ENV = "sk-live-reputation-hook-canary";

async function withServer(policy, fn) {
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
  try { return await fn(server.address().port, alerts); } finally { server.close(); }
}

function makeHome(port) {
  const home = mkdtempSync(join(tmpdir(), "moorai-rephook-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: "tok-rephook" }));
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: {
    squat: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesytem"], env: { API_KEY: SECRET_ENV } },
    files: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21"] }
  } }));
  return home;
}

async function runHook(home, tool) {
  const child = spawn(process.execPath, [HOOK], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" } });
  let out = "";
  child.stdout.on("data", (c) => { out += c; });
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: tool, session_id: "rephook", cwd: home, tool_input: { path: "README.md" } }));
  await new Promise((r) => child.on("exit", r));
  const t = out.trim();
  if (!t) return { decision: "allow", reason: "" };
  const o = JSON.parse(t).hookSpecificOutput || {};
  return { decision: o.permissionDecision || "allow", reason: o.permissionDecisionReason || "" };
}
const repAlerts = (alerts) => alerts.filter((a) => a.category === REPUTATION_CATEGORY);
const settle = () => new Promise((r) => setTimeout(r, 200));

test("hook e2e: a typosquatted server below the org's blockBelow is denied, and first sight is reported content-free", async () => {
  await withServer({ captureTier: "content-free", mcpReputation: { blockBelow: 60 } }, async (port, alerts) => {
    const home = makeHome(port);
    const r = await runHook(home, "mcp__squat__read_file");
    assert.equal(r.decision, "deny", JSON.stringify(r));
    assert.match(r.reason, /MCP server reputation \d+\/100/);
    await settle();
    const a = repAlerts(alerts);
    assert.equal(a.length, 1, JSON.stringify(alerts.map((x) => x.category)));
    assert.equal(a[0].decision, "block");
    assert.equal(a[0].mcpServer, "squat");
    const wire = JSON.stringify(alerts);
    assert.equal(wire.includes(SECRET_ENV), false, "an env value never leaves");
    assert.equal(wire.includes("server-filesytem"), false, "the package name never leaves");
  });
});

test("hook e2e: without blockBelow the same server is allowed and only reported, once", async () => {
  await withServer({ captureTier: "content-free" }, async (port, alerts) => {
    const home = makeHome(port);
    assert.equal((await runHook(home, "mcp__squat__read_file")).decision, "allow");
    assert.equal((await runHook(home, "mcp__squat__read_file")).decision, "allow");
    await settle();
    const a = repAlerts(alerts);
    assert.equal(a.length, 1, "the second sight is cached and not re-reported");
    assert.equal(a[0].decision, "alert");
  });
});

test("hook e2e: a well-known pinned server is allowed with no reputation alert", async () => {
  await withServer({ captureTier: "content-free", mcpReputation: { blockBelow: 60 } }, async (port, alerts) => {
    const home = makeHome(port);
    assert.equal((await runHook(home, "mcp__files__read_file")).decision, "allow");
    await settle();
    assert.equal(repAlerts(alerts).length, 0);
  });
});
