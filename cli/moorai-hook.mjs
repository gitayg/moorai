#!/usr/bin/env node
// MoorAI PreToolUse hook (#1/#2/#3). Registered in the agent's settings.json for the Read, Bash, and
// mcp__* tools; runs BEFORE each matched tool call. Reads the tool input on stdin and, per policy,
// blocks (Claude Code deny) a secret/PII being read into context (#1), a secret shipped as an MCP
// tool-call argument (#2), or a call to an MCP server that isn't on the org allow-list (#3).
//
// Governance, not a sandbox: any error, missing policy, or unsupported tool → EXIT 0 (allow). Reports
// are content-free (category + risk + one-way hash), never the file/arg content or the matched span.
//
//   node moorai-hook.mjs            # hook mode (reads stdin)
//   node moorai-hook.mjs install    # register in ~/.claude/settings.json (idempotent)
//   node moorai-hook.mjs uninstall  # remove only MoorAI's entries

import { readFileSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname, basename } from "node:path";
import os from "node:os";
import { loadConfig } from "./config.mjs";
import { buildEngine, decideText, decideMcpServer, extractReadPaths } from "./hook-core.mjs";
import { recordExposure } from "./signals.mjs";

const SELF = fileURLToPath(import.meta.url);
const RANK = { allow: 1, ask: 2, deny: 3 };

// ---- install / uninstall (settings.json merge) ----
function settingsPath() { return join(os.homedir(), ".claude", "settings.json"); }
function isCuraiq(entry) { return JSON.stringify(entry).includes("moorai-hook"); }
function readSettings() { try { return JSON.parse(readFileSync(settingsPath(), "utf8")); } catch { return {}; } }
function writeSettings(s) { mkdirSync(dirname(settingsPath()), { recursive: true }); writeFileSync(settingsPath(), JSON.stringify(s, null, 2)); }

function installHooks() {
  const s = readSettings();
  s.hooks = s.hooks || {};
  const cmd = `node ${JSON.stringify(SELF)}`;
  const entry = (matcher) => ({ matcher, hooks: [{ type: "command", command: cmd }] });
  const cur = Array.isArray(s.hooks.PreToolUse) ? s.hooks.PreToolUse : [];
  s.hooks.PreToolUse = [...cur.filter((e) => !isCuraiq(e)), entry("Read"), entry("Bash"), entry("mcp__.*")];
  writeSettings(s);
  console.error(`MoorAI hooks installed in ${settingsPath()}`);
}
function uninstallHooks() {
  const s = readSettings();
  if (Array.isArray(s.hooks?.PreToolUse)) { s.hooks.PreToolUse = s.hooks.PreToolUse.filter((e) => !isCuraiq(e)); writeSettings(s); }
  console.error("MoorAI hooks removed");
}

// ---- policy load (cached; per-call HTTP would be too slow) ----
const CONFIG = loadConfig();
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

// ---- content-free reporting ----
function djb2(s) { let h = 5381; for (let i = 0; i < String(s).length; i++) h = ((h << 5) + h + String(s).charCodeAt(i)) >>> 0; return "h" + h.toString(16); }
const IDENTITY = { user: os.userInfo().username, device: os.hostname(), platform: os.platform(), tenant: CONFIG.tenant };
function post(alert) { return fetch(`${CONFIG.serverUrl}/api/alerts`, { method: "POST", headers: { "Content-Type": "application/json", ...(CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {}) }, body: JSON.stringify(alert), signal: AbortSignal.timeout(1500) }).catch(() => {}); }
function report(findings, stage, tool, blocked) {
  for (const f of findings) {
    const alert = { threatId: f.threatId, category: f.category, riskLevel: blocked ? "Blocked" : f.riskLevel, stage, tool, ts: new Date().toISOString(), contentHash: djb2(f.match || ""), ...IDENTITY };
    post(alert);            // → server → SIEM (address configured server-side, #1)
    recordExposure(alert);  // → local content-free exposure ledger (#5); ignores non-secret categories
  }
}

function readFileCapped(fp) {
  try {
    if (!fp) return "";
    const slice = readFileSync(fp).subarray(0, 262144);
    if (slice.includes(0)) return ""; // skip binary
    return slice.toString("utf8");
  } catch { return ""; }
}

function emit(decision, reason) {
  if (decision === "allow") process.exit(0);
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision === "deny" ? "deny" : "ask", permissionDecisionReason: `MoorAI: ${reason}` } }));
  process.exit(0);
}

async function readStdin() { const chunks = []; for await (const c of process.stdin) chunks.push(c); return Buffer.concat(chunks).toString("utf8"); }

async function main() {
  const cmd = process.argv[2];
  if (cmd === "install") return installHooks();
  if (cmd === "uninstall") return uninstallHooks();

  let input;
  try { input = JSON.parse((await readStdin()) || "{}"); } catch { process.exit(0); }
  const tool = input.tool_name || "";
  const ti = input.tool_input || {};
  const policy = await loadPolicy();
  if (!policy) process.exit(0); // fail open — governance, not a sandbox
  const engine = buildEngine(policy);

  if (tool === "Read") {
    const d = decideText(engine, policy, readFileCapped(ti.file_path), "file");
    report(d.findings, "file", "hook:Read", d.decision === "deny");
    return emit(d.decision, `blocked Read of ${basename(ti.file_path || "file")} — ${d.reasons.join(", ")}`);
  }
  if (tool === "Bash") {
    let dec = "allow", reasons = [], finds = [];
    for (const p of extractReadPaths(ti.command)) {
      const d = decideText(engine, policy, readFileCapped(p), "file");
      finds.push(...d.findings);
      if (RANK[d.decision] > RANK[dec]) { dec = d.decision; reasons = d.reasons; }
    }
    report(finds, "file", "hook:Bash", dec === "deny");
    return emit(dec, `blocked file read via Bash — ${reasons.join(", ")}`);
  }
  if (tool.startsWith("mcp__")) {
    const server = tool.split("__")[1] || "";
    const sd = decideMcpServer(policy, server); // #3 — allow-list first, short-circuits
    if (sd.decision === "deny") { post({ threatId: 0, category: "MCP: unapproved server", riskLevel: "Blocked", stage: "mcp", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: djb2(server), ...IDENTITY }); return emit("deny", sd.reason); }
    const d = decideText(engine, policy, JSON.stringify(ti), "prompt"); // #2 — scan args
    report(d.findings, "egress", `hook:${tool}`, d.decision === "deny");
    return emit(d.decision, `blocked ${tool} — ${d.reasons.join(", ")}`);
  }
  process.exit(0); // unknown tool → allow
}

main();
