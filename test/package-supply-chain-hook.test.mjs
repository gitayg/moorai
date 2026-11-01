// Package supply chain, END TO END through the real Claude Code hook (cli/moorai-hook.mjs):
//   * a shell command that installs a known-compromised release is denied by default (cli/package-known-bad.mjs);
//   * an mcp__<label>__* call to a registry MCP server is judged by mcpPackagePolicy (cli/mcp-package-policy.mjs).
//
//   node --test test/package-supply-chain-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { KNOWN_BAD_CATEGORY } from "../data/known-bad-packages.js";
import { MCP_PACKAGE_CATEGORY, MCP_PACKAGE_HELD_CATEGORY } from "../cli/mcp-package-policy.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

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

const SERVERS = {
  loose: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem"] },
  pinned: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21"] },
  newer: { command: "npx", args: ["-y", "@modelcontextprotocol/server-everything@2025.9.1"] },
  colors: { command: "npx", args: ["-y", "chalk@5.6.1"] },
  squat: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesytem@1.0.0"] }
};

function makeHome(t, port) {
  const home = mkdtempSync(join(tmpdir(), "moorai-pkghook-"));
  t.after(() => rmTree(home));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: "tok-pkghook" }));
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: SERVERS }));
  return home;
}

async function runHook(home, tool, toolInput) {
  const child = spawn(process.execPath, [HOOK], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" } });
  let out = "";
  child.stdout.on("data", (c) => { out += c; });
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: tool, session_id: "pkghook", cwd: home, tool_input: toolInput }));
  await new Promise((r) => child.on("exit", r));
  const t = out.trim();
  if (!t) return { decision: "allow", reason: "" };
  const o = JSON.parse(t).hookSpecificOutput || {};
  return { decision: o.permissionDecision || "allow", reason: o.permissionDecisionReason || "" };
}
const bash = (home, command) => runHook(home, "Bash", { command });
const mcp = (home, label) => runHook(home, `mcp__${label}__read_file`, { path: "README.md" });
const settle = () => new Promise((r) => setTimeout(r, 200));
const of = (alerts, ...cats) => alerts.filter((a) => cats.includes(a.category));

test("hook: pip install of the compromised LiteLLM release is denied with no knownBadPackages policy", async (t) => {
  await withServer({ captureTier: "content-free" }, async (port, alerts) => {
    const home = makeHome(t, port);
    const r = await bash(home, "pip install litellm==1.107.0");
    assert.equal(r.decision, "deny", JSON.stringify(r));
    assert.match(r.reason, /known-compromised pypi release/);
    await settle();
    const a = of(alerts, KNOWN_BAD_CATEGORY);
    assert.equal(a.length, 1, JSON.stringify(alerts.map((x) => x.category)));
    assert.equal(a[0].threatId, 57);
    assert.equal(a[0].decision, "block");
    const wire = JSON.stringify(a);
    assert.equal(wire.includes("litellm"), false, "the package name never leaves");
    assert.equal(wire.includes("1.107.0"), false, "the version never leaves");
  });
});

test("hook: the same install inside bash -c, and an npm release from the 2025-09-08 compromise, are denied; a safe release is not", async (t) => {
  await withServer({ captureTier: "content-free" }, async (port, alerts) => {
    const home = makeHome(t, port);
    assert.equal((await bash(home, "cd app && bash -c 'uv add litellm==1.107.0'")).decision, "deny");
    assert.equal((await bash(home, "npm install chalk@5.6.1")).decision, "deny");
    alerts.length = 0;
    assert.equal((await bash(home, "pip install litellm==1.106.2")).decision, "allow");
    assert.equal((await bash(home, "echo 'pip install litellm==1.107.0' >> notes.txt")).decision, "allow");
    await settle();
    assert.equal(of(alerts, KNOWN_BAD_CATEGORY).length, 0);
  });
});

test("hook: knownBadPackages from the policy adds an every-version entry and can set report", async (t) => {
  await withServer({ captureTier: "content-free", knownBadPackages: { action: "report", packages: [{ ecosystem: "npm", name: "evil-helper", versions: "*" }] } }, async (port, alerts) => {
    const home = makeHome(t, port);
    assert.equal((await bash(home, "pip install litellm==1.107.0")).decision, "allow", "report: not held");
    assert.equal((await bash(home, "npx evil-helper@latest")).decision, "allow");
    await settle();
    const a = of(alerts, KNOWN_BAD_CATEGORY);
    assert.equal(a.length, 2, JSON.stringify(a));
    assert.deepEqual(a.map((x) => x.decision), ["alert", "alert"]);
    assert.deepEqual(a.map((x) => x.knownBadSource).sort(), ["policy", "shipped"]);
  });
  await withServer({ captureTier: "content-free", knownBadPackages: { packages: [{ ecosystem: "npm", name: "evil-helper", versions: "*" }] } }, async (port) => {
    const home = makeHome(t, port);
    assert.equal((await bash(home, "npx evil-helper@latest")).decision, "deny");
  });
});

test("hook MCP: an unpinned server is reported once by default and not held", async (t) => {
  await withServer({ captureTier: "content-free" }, async (port, alerts) => {
    const home = makeHome(t, port);
    assert.equal((await mcp(home, "loose")).decision, "allow");
    assert.equal((await mcp(home, "loose")).decision, "allow");
    await settle();
    const a = of(alerts, MCP_PACKAGE_CATEGORY, MCP_PACKAGE_HELD_CATEGORY);
    assert.equal(a.length, 1, JSON.stringify(a));
    assert.equal(a[0].decision, "alert");
    assert.deepEqual(a[0].packageSignals, ["unpinned-version"]);
    assert.equal(a[0].mcpServer, "loose");
    assert.equal(JSON.stringify(a).includes("server-filesystem"), false, "the package name never leaves");
  });
});

test("hook MCP: mcpPackagePolicy block denies an unpinned server and allows a pinned one", async (t) => {
  await withServer({ captureTier: "content-free", mcpPackagePolicy: "block" }, async (port, alerts) => {
    const home = makeHome(t, port);
    const r = await mcp(home, "loose");
    assert.equal(r.decision, "deny", JSON.stringify(r));
    assert.match(r.reason, /unpinned-version/);
    assert.equal((await mcp(home, "pinned")).decision, "allow");
    await settle();
    const held = of(alerts, MCP_PACKAGE_HELD_CATEGORY);
    assert.equal(held.length, 1, JSON.stringify(alerts.map((x) => x.category)));
    assert.equal(held[0].decision, "block");
  });
});

test("hook MCP: mcpPackagePolicy ask asks", async (t) => {
  await withServer({ captureTier: "content-free", mcpPackagePolicy: { action: "ask" } }, async (port) => {
    const home = makeHome(t, port);
    const r = await mcp(home, "loose");
    assert.equal(r.decision, "ask", JSON.stringify(r));
    assert.match(r.reason, /unpinned-version/);
  });
});

test("hook MCP: a version other than the policy pin is denied; the pinned version is allowed", async (t) => {
  const pins = { "npm:@modelcontextprotocol/server-everything": "2025.8.0", "npm:@modelcontextprotocol/server-filesystem": "2025.8.21" };
  await withServer({ captureTier: "content-free", mcpPackagePolicy: { action: "block", pins } }, async (port) => {
    const home = makeHome(t, port);
    const r = await mcp(home, "newer");
    assert.equal(r.decision, "deny", JSON.stringify(r));
    assert.match(r.reason, /version-not-approved/);
    assert.equal((await mcp(home, "pinned")).decision, "allow");
  });
});

test("hook MCP: a typosquatted package fails a critical check and is held under block", async (t) => {
  await withServer({ captureTier: "content-free", mcpPackagePolicy: "block" }, async (port) => {
    const home = makeHome(t, port);
    const r = await mcp(home, "squat");
    assert.equal(r.decision, "deny", JSON.stringify(r));
    assert.match(r.reason, /critical-check \(mcp-typosquat\)/);
  });
});

test("hook MCP: a server launched from a known-compromised release is denied with no mcpPackagePolicy", async (t) => {
  await withServer({ captureTier: "content-free" }, async (port) => {
    const home = makeHome(t, port);
    const r = await mcp(home, "colors");
    assert.equal(r.decision, "deny", JSON.stringify(r));
    assert.match(r.reason, /known-bad-release/);
  });
});
