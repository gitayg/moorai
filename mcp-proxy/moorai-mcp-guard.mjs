#!/usr/bin/env node
// MoorAI MCP Guard for Claude Desktop — a stdio JSON-RPC proxy that inserts the SAME on-device AI Agent
// Gateway (mcpGateway) the Claude Code PreToolUse hook uses, between Claude Desktop and each MCP server.
//
// Claude Desktop has NO PreToolUse hooks (that is a Claude Code CLI feature), but it launches MCP servers
// from claude_desktop_config.json. So we guard it by spawning THIS proxy in place of the real server; the
// proxy spawns the real server as a child and pumps stdio both ways, gating every `tools/call` through
// mcpGateway (server allow-list #3 → per-tool arg rules #18 → argument content scan #2). All other
// JSON-RPC traffic (initialize, tools/list, notifications, responses) passes through verbatim.
//
// Content-free by construction: only category / risk / one-way hash / server / tool / decision may leave
// the device. Tool-call CONTENT is NEVER emitted. Governance, not a sandbox: on ANY error (bad policy,
// engine failure, unparseable line) we FAIL OPEN — the message is forwarded unchanged.
//
//   node moorai-mcp-guard.mjs [--server <label>] -- <real-server-cmd> [args...]
//
//   --server <label>   the MCP server name used for the gateway (allow-list / audit). Defaults to the
//                      basename of the real command. install.mjs passes the configured server key here.

import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import os from "node:os";
import { loadConfig } from "../cli/config.mjs";
import { buildEngine, mcpGateway } from "../cli/hook-core.mjs";
import { applyCaptureTier } from "../data/capture-tiers.js";
import { recordAction } from "../cli/signals.mjs";

// ---- argv parsing: [--server label] -- realcmd args... ----
function parseArgv(argv) {
  const sep = argv.indexOf("--");
  if (sep < 0 || sep === argv.length - 1) {
    process.stderr.write("moorai-mcp-guard: usage: node moorai-mcp-guard.mjs [--server <label>] -- <cmd> [args...]\n");
    process.exit(2);
  }
  const pre = argv.slice(0, sep);
  const rest = argv.slice(sep + 1);
  let label = "";
  for (let i = 0; i < pre.length; i++) {
    if (pre[i] === "--server" || pre[i] === "-s") { label = pre[i + 1] || ""; i++; }
  }
  const cmd = rest[0];
  const args = rest.slice(1);
  if (!label) label = basename(cmd || "mcp").replace(/\.(mjs|js|cjs|exe|sh|py)$/i, "") || "mcp";
  return { label, cmd, args };
}

const { label: SERVER, cmd: REAL_CMD, args: REAL_ARGS } = parseArgv(process.argv.slice(2));

// ---- config / identity / content-free reporting (same shape as the Claude Code hook) ----
const CONFIG = loadConfig();
function djb2(s) { let h = 5381; for (let i = 0; i < String(s).length; i++) h = ((h << 5) + h + String(s).charCodeAt(i)) >>> 0; return "h" + h.toString(16); }
const IDENTITY = { user: os.userInfo().username, device: os.hostname(), platform: os.platform(), tenant: CONFIG.tenant, actor: djb2(`${os.userInfo().username}@${os.hostname()}`) };
function post(alert) {
  try {
    return fetch(`${CONFIG.serverUrl}/api/alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {}) },
      body: JSON.stringify(alert),
      signal: AbortSignal.timeout(1500)
    }).catch(() => {});
  } catch { /* never let a network/timeout error touch the proxy path */ }
}

// ---- policy load (identical strategy to the hook: reuse the ~/.curaiq/hook-policy.json cache) ----
const CACHE = join(os.homedir(), ".curaiq", "hook-policy.json");
async function loadPolicy() {
  try { if (Date.now() - statSync(CACHE).mtimeMs < 60000) return JSON.parse(readFileSync(CACHE, "utf8")); } catch { /* stale/absent */ }
  try {
    const headers = CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {};
    const p = await fetch(`${CONFIG.serverUrl}/api/policy?tenant=${encodeURIComponent(CONFIG.tenant)}`, { headers, signal: AbortSignal.timeout(1500) }).then((r) => r.json());
    if (p) { try { mkdirSync(dirname(CACHE), { recursive: true }); writeFileSync(CACHE, JSON.stringify(p)); } catch {} return p; }
  } catch { /* offline */ }
  try { return JSON.parse(readFileSync(CACHE, "utf8")); } catch { return null; }
}

// mutable — refreshed lazily so a long-lived Claude Desktop session picks up policy changes.
let POLICY = null;
let ENGINE = null;
let LAST_POLICY_LOAD = 0;
async function ensurePolicy() {
  if (Date.now() - LAST_POLICY_LOAD < 60000 && ENGINE) return;
  try {
    POLICY = await loadPolicy();
    ENGINE = buildEngine(POLICY);
    LAST_POLICY_LOAD = Date.now();
  } catch { /* keep whatever we had; fail open below if still null */ }
}

// ---- content-free per-call audit ledger + alert ----
function auditCall(tool, decision, argsHash) {
  try {
    recordAction(applyCaptureTier({
      threatId: 0, category: "MCP tool call", riskLevel: decision === "deny" ? "Blocked" : "Info",
      stage: "mcp", tool: `desktop:${tool}`, decision, mcpServer: SERVER,
      ts: new Date().toISOString(), contentHash: argsHash, ...IDENTITY
    }, {}, (POLICY && POLICY.captureTier) || "content-free"));
  } catch { /* ledger is best-effort; never affects the decision */ }
}
function alertBlock(tool, gate, reason, argsHash) {
  const category = gate === "server" ? "MCP: unapproved server" : gate === "args" ? "MCP: denied tool argument" : "MCP: blocked tool argument";
  post({ threatId: 0, category, riskLevel: "Blocked", stage: "mcp", tool: `desktop:${tool}`, decision: "deny", mcpServer: SERVER, ts: new Date().toISOString(), contentHash: argsHash, ...IDENTITY });
}
function alertFindings(tool, findings, blocked, argsHash) {
  for (const f of findings || []) {
    post({ threatId: f.threatId, category: f.category, riskLevel: blocked ? "Blocked" : f.riskLevel, stage: "mcp", tool: `desktop:${tool}`, mcpServer: SERVER, ts: new Date().toISOString(), contentHash: djb2(f.match || ""), ...IDENTITY });
  }
}

// ---- spawn the real MCP server ----
const child = spawn(REAL_CMD, REAL_ARGS, { stdio: ["pipe", "pipe", "pipe"], env: process.env });

child.on("error", (e) => {
  // The real server could not be spawned. Fail loudly to Claude Desktop's stderr (visible in its logs)
  // and exit — there is nothing to proxy. This is a startup/config error, not a gated tool-call.
  process.stderr.write(`moorai-mcp-guard: failed to spawn '${REAL_CMD}': ${e && e.message}\n`);
  process.exit(1);
});
child.on("exit", (code, signal) => { process.exit(code == null ? (signal ? 1 : 0) : code); });

// Responses from the real server → Claude Desktop, verbatim (transparent pass-through).
child.stdout.pipe(process.stdout);
// The real server's diagnostics → our stderr (Claude Desktop surfaces these in its MCP logs).
child.stderr.pipe(process.stderr);

// ---- write a JSON-RPC MCP tool-error RESULT back to Claude Desktop (so the model sees a clean refusal,
// not a hang). We use the tool-result `isError` shape, NOT a protocol-level JSON-RPC error object. ----
function writeBlock(id, reason) {
  const msg = { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `MoorAI blocked this MCP tool call: ${reason}` }], isError: true } };
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function forward(rawLine) { child.stdin.write(rawLine + "\n"); }

// ---- gate one JSON-RPC message. tools/call is inspected; everything else is forwarded verbatim. ----
async function handleLine(rawLine) {
  const trimmed = rawLine.replace(/\r$/, "");
  if (!trimmed.trim()) { forward(rawLine); return; }
  let msg;
  try { msg = JSON.parse(trimmed); } catch { forward(rawLine); return; } // not JSON we understand → pass through

  if (!msg || msg.method !== "tools/call" || !msg.params || typeof msg.params !== "object") { forward(rawLine); return; }

  // This is a tool-call — the surface we gate.
  try {
    await ensurePolicy();
    const tool = msg.params.name || "";
    const args = JSON.stringify(msg.params.arguments == null ? {} : msg.params.arguments);
    const argsHash = djb2(args);

    if (!ENGINE) { auditCall(tool, "allow", argsHash); forward(rawLine); return; } // fail open: no engine

    const g = mcpGateway(ENGINE, POLICY, { tool, server: SERVER, args });

    if (g.decision === "deny") {
      // Blocked: do NOT forward. The real server never receives the call. Return a clean tool error.
      alertBlock(tool, g.gate, g.reason, argsHash);
      alertFindings(tool, g.findings, true, argsHash);
      auditCall(tool, "deny", argsHash);
      writeBlock(msg.id, g.reason || "policy");
      return;
    }
    // allow OR coach ("ask"): Claude Desktop has no interactive banner, so coach = allow + record.
    alertFindings(tool, g.findings, false, argsHash);
    auditCall(tool, g.decision, argsHash);
    forward(rawLine);
  } catch {
    // Governance, not a sandbox: any gate error must not drop the call — forward it unchanged.
    forward(rawLine);
  }
}

// ---- newline-delimited framing of Claude Desktop → proxy stdin. Buffer partial lines; a tool-call must
// be fully awaited before the next line is processed so ordering to the child is preserved. ----
let buf = "";
let queue = Promise.resolve();
function enqueue(line) { queue = queue.then(() => handleLine(line)); }

process.stdin.on("data", (chunk) => {
  buf += chunk.toString("utf8");
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl);
    buf = buf.slice(nl + 1);
    enqueue(line);
  }
});
process.stdin.on("end", () => {
  queue = queue.then(() => { if (buf.length) return handleLine(buf); }).then(() => { try { child.stdin.end(); } catch {} });
});

// Best-effort warm-up so the first tool-call is not delayed by the initial policy fetch.
ensurePolicy();
