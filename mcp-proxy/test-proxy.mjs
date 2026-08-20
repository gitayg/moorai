#!/usr/bin/env node
// Self-verification for the MoorAI MCP Guard — no real Claude Desktop required.
//
// Part A (proxy): spawns the guard wrapping the tiny fake MCP server, drives it over stdio, and asserts:
//   (c) initialize / tools/list pass through untouched (answered by the real server);
//   (a) a benign tools/call is forwarded and echoed back by the real server;
//   (b) a tools/call whose args match a policy deny is BLOCKED — the real server never receives it
//       (asserted against its received-log) and Claude Desktop gets a JSON-RPC error result with the
//       matching id.
//
// Part B (install): validates install.mjs's config rewrite against a fixture — wrap → idempotent
// re-wrap is a no-op → uninstall restores the original — asserting on the JSON, not a real install.

import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import os from "node:os";
import { wrapConfig, unwrapConfig, isWrapped, GUARD_PATH } from "./install.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = join(HERE, "moorai-mcp-guard.mjs");
const FAKE = join(HERE, "test-fake-mcp-server.mjs");

let failures = 0;
function ok(cond, msg) { console.log(`${cond ? "PASS" : "FAIL"}  ${msg}`); if (!cond) failures++; }
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// ---------- Part A: proxy over stdio ----------
async function testProxy() {
  console.log("\n== Part A: stdio proxy ==");
  const home = mkdtempSync(join(os.tmpdir(), "moorai-mcp-test-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  // Fresh policy cache (<60s) → the guard uses it directly and never hits the network. Deny any `echo`
  // call whose serialized args contain BLOCKME (per-tool arg rule, #18).
  writeFileSync(join(home, ".curaiq", "hook-policy.json"), JSON.stringify({ mcpToolRules: { echo: { deny: ["BLOCKME"] } }, captureTier: "content-free" }));
  const recvLog = join(home, "received.log");

  const child = spawn(process.execPath, [GUARD, "--server", "testsrv", "--", process.execPath, FAKE, recvLog], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: "http://127.0.0.1:1", MoorAI_TENANT: "test" }
  });
  child.stderr.on("data", (d) => { const s = d.toString(); if (s.trim()) process.stderr.write("[guard stderr] " + s); });

  const byId = new Map();
  let outBuf = "";
  child.stdout.on("data", (c) => {
    outBuf += c.toString();
    let nl;
    while ((nl = outBuf.indexOf("\n")) >= 0) {
      const line = outBuf.slice(0, nl); outBuf = outBuf.slice(nl + 1);
      if (!line.trim()) continue;
      try { const m = JSON.parse(line); if (m.id != null) byId.set(m.id, m); } catch {}
    }
  });

  const send = (o) => child.stdin.write(JSON.stringify(o) + "\n");
  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {} } });
  send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "echo", arguments: { msg: "hello world" } } });
  send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "echo", arguments: { msg: "please BLOCKME now" } } });

  // wait for all four ids or timeout
  const deadline = Date.now() + 4000;
  while (byId.size < 4 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));

  const r1 = byId.get(1), r2 = byId.get(2), r3 = byId.get(3), r4 = byId.get(4);

  ok(r1 && r1.result && r1.result.serverInfo && r1.result.serverInfo.name === "fake-server",
    "(c) initialize passes through untouched (answered by real server)");
  ok(r2 && r2.result && Array.isArray(r2.result.tools) && r2.result.tools[0] && r2.result.tools[0].name === "echo",
    "(c) tools/list passes through untouched");

  let benign = null; try { benign = r3 && JSON.parse(r3.result.content[0].text); } catch {}
  ok(benign && benign.from === "fake-server" && benign.echoed && benign.echoed.msg === "hello world",
    "(a) benign tools/call is forwarded and echoed by the real server");

  const blockedText = r4 && r4.result && r4.result.content && r4.result.content[0] && r4.result.content[0].text;
  ok(r4 && r4.result && r4.result.isError === true && /MoorAI blocked/i.test(String(blockedText)),
    "(b) blocked tools/call returns a JSON-RPC error RESULT with the matching id (4)");
  ok(!(blockedText && /fake-server/.test(String(blockedText))),
    "(b) blocked result did NOT come from the real server");

  const recv = existsSync(recvLog) ? readFileSync(recvLog, "utf8") : "";
  ok(/hello world/.test(recv), "(a) real server received the benign call (present in its log)");
  ok(!/BLOCKME/.test(recv), "(b) real server NEVER received the blocked call (absent from its log)");

  try { child.stdin.end(); } catch {}
  try { child.kill(); } catch {}
}

// ---------- Part B: install.mjs config rewrite ----------
function testInstall() {
  console.log("\n== Part B: install.mjs config rewrite ==");
  const original = {
    mcpServers: {
      filesystem: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/docs"], env: { FOO: "bar" } },
      git: { command: "uvx", args: ["mcp-server-git"] },
      remote: { url: "https://example.com/sse" } // transport-only (no command) — must be left untouched
    }
  };

  const wrapped = wrapConfig(original);
  const fs = wrapped.mcpServers.filesystem;
  ok(fs.command === "node" && fs.args[0] === GUARD_PATH, "wrap: filesystem now launches node <guard>");
  ok(fs.args.includes("--server") && fs.args[fs.args.indexOf("--server") + 1] === "filesystem", "wrap: --server label is the server key");
  const sep = fs.args.indexOf("--");
  ok(fs.args[sep + 1] === "npx" && eq(fs.args.slice(sep + 2), ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/docs"]),
    "wrap: original command/args preserved after --");
  ok(eq(fs.env, { FOO: "bar" }), "wrap: env preserved");
  ok(isWrapped(wrapped.mcpServers.git), "wrap: git entry wrapped");
  ok(eq(wrapped.mcpServers.remote, original.mcpServers.remote), "wrap: transport-only (url) entry left untouched");

  const rewrapped = wrapConfig(wrapped);
  ok(eq(rewrapped, wrapped), "idempotent: wrapping an already-wrapped config is a no-op");

  const restored = unwrapConfig(wrapped);
  ok(eq(restored, original), "uninstall: unwrap restores the exact original config");
}

await testProxy();
testInstall();

console.log(`\n${failures === 0 ? "ALL PASS" : failures + " FAILURE(S)"}`);
process.exit(failures === 0 ? 0 : 1);
