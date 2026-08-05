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
import { buildEngine, decideText, decideMcpServer, decideMcpArgs, extractReadPaths } from "./hook-core.mjs";
import { recordExposure, recordAgentEvent, readAgentEvents, recordAction } from "./signals.mjs";
import { applyCaptureTier, commandShape } from "../data/capture-tiers.js";
import { contentTells, assessSession, assessTrifecta, trifectaLegs } from "../data/agent-behavior.js";
import { classifyLocal } from "../data/model-escalation.mjs";

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
// #10 — every emitted action carries a stable, content-free actor fingerprint (one-way hash of
// user@device) so the console can tie actions to an operator without storing raw identity as the key.
const IDENTITY = { user: os.userInfo().username, device: os.hostname(), platform: os.platform(), tenant: CONFIG.tenant, actor: djb2(`${os.userInfo().username}@${os.hostname()}`) };
function post(alert) { return fetch(`${CONFIG.serverUrl}/api/alerts`, { method: "POST", headers: { "Content-Type": "application/json", ...(CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {}) }, body: JSON.stringify(alert), signal: AbortSignal.timeout(1500) }).catch(() => {}); }
function report(findings, stage, tool, blocked, tier, extras) {
  for (const f of findings) {
    const base = { threatId: f.threatId, category: f.category, riskLevel: blocked ? "Blocked" : f.riskLevel, stage, tool, ts: new Date().toISOString(), contentHash: djb2(f.match || ""), ...IDENTITY };
    // #5 — attach only the fields the policy's capture tier permits (content-free by default). The
    // server independently re-strips above the device's stored tier, so this is one of two backstops.
    const alert = applyCaptureTier(base, { ...extras, matchText: f.match }, tier || "content-free");
    post(alert);            // → server → SIEM (address configured server-side, #1)
    recordExposure(alert);  // → local content-free exposure ledger; ignores non-secret categories
    recordAction(alert);    // → local searchable action-audit log (#5), already tier-gated
  }
}

// Autonomous-agent-behavior signature (CSA HF post-mortem §IV). Records one content-free event per
// tool call and, on a transition into the signature, emits a content-free alert (→ server → SIEM/SOC
// + timeline). Entirely side-effectful and wrapped: a failure here must never change the hook's
// allow/deny decision (governance, fail-open).
const RISK_RANK = { Low: 1, Medium: 2, High: 3, Critical: 4, Blocked: 5 };
function logBehavior(tool, identity, scannedText, d, stage) {
  try {
    const risk = (d.findings || []).reduce((m, f) => (RISK_RANK[f.riskLevel] > RISK_RANK[m] ? f.riskLevel : m), "Low");
    const flags = contentTells(scannedText || "");
    const legs = trifectaLegs(tool, stage, d.findings || [], flags); // #1 — content-free trifecta legs
    const beforeS = assessSession(readAgentEvents()), beforeT = assessTrifecta(readAgentEvents());
    recordAgentEvent({ ts: Date.now(), sig: `${tool}|${djb2(identity || tool)}`, ok: d.decision !== "deny", risk, flags, legs });
    const events = readAgentEvents(), afterS = assessSession(events), afterT = assessTrifecta(events);
    if (afterS.level === "autonomous-signature" && beforeS.level !== "autonomous-signature") {
      post({ threatId: 0, category: "Autonomous-agent behavior", riskLevel: "Critical", stage: "behavior", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "sig:" + afterS.tells.map((t) => t.id).join("."), signature: { level: afterS.level, score: afterS.score, tells: afterS.tells.map((t) => t.id), events: afterS.events }, ...IDENTITY });
    }
    // #1 — the lethal trifecta just closed in this session (all three legs now present).
    if (afterT.present && !beforeT.present) {
      post({ threatId: 59, category: "Lethal trifecta exposure", riskLevel: "High", stage: "behavior", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "trifecta:read.ingest.callout", signature: { legs: afterT.legs }, ...IDENTITY });
    }
  } catch { /* behavior signal is best-effort; never affects enforcement */ }
}

// Bold B1 / #21 — opportunistic local-model escalation. Only when the org enables it AND the regex
// pass was ambiguous (nothing already High+); consults a loopback model and emits a content-free
// second-opinion alert (#58). The text never leaves the device; a failure never changes enforcement.
async function maybeEscalate(policy, text, stage, tool, d) {
  try {
    if (!policy || !policy.modelEscalation || !text || !text.trim()) return;
    const strong = (d.findings || []).some((f) => f.riskLevel === "High" || f.riskLevel === "Critical" || f.riskLevel === "Blocked");
    if (strong) return; // regex is already confident — skip the second opinion
    const v = await classifyLocal(text);
    if (v && v.flagged && v.confidence >= 0.6) {
      post({ threatId: 58, category: `Model-flagged: ${v.category}`, riskLevel: v.confidence >= 0.85 ? "High" : "Medium", stage, tool: `escalate:${tool}`, ts: new Date().toISOString(), contentHash: djb2(text), ...IDENTITY });
    }
  } catch { /* escalation is advisory; fail-open */ }
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
    const text = readFileCapped(ti.file_path);
    const d = decideText(engine, policy, text, "file");
    report(d.findings, "file", "hook:Read", d.decision === "deny", policy.captureTier, { filePath: ti.file_path, toolName: "Read" });
    logBehavior("Read", ti.file_path || "file", text, d, "file");
    await maybeEscalate(policy, text, "file", "hook:Read", d);
    return emit(d.decision, `blocked Read of ${basename(ti.file_path || "file")} — ${d.reasons.join(", ")}`);
  }
  if (tool === "Bash") {
    let dec = "allow", reasons = [], finds = [], btext = "";
    for (const p of extractReadPaths(ti.command)) {
      const t = readFileCapped(p); btext += t + "\n";
      const d = decideText(engine, policy, t, "file");
      finds.push(...d.findings);
      if (RANK[d.decision] > RANK[dec]) { dec = d.decision; reasons = d.reasons; }
    }
    report(finds, "file", "hook:Bash", dec === "deny", policy.captureTier, { toolName: "Bash", cmdShape: commandShape(ti.command) });
    logBehavior("Bash", ti.command || "bash", btext, { decision: dec, findings: finds }, "file");
    await maybeEscalate(policy, btext, "file", "hook:Bash", { findings: finds });
    return emit(dec, `blocked file read via Bash — ${reasons.join(", ")}`);
  }
  if (tool.startsWith("mcp__")) {
    const server = tool.split("__")[1] || "";
    const sd = decideMcpServer(policy, server); // #3 — allow-list first, short-circuits
    if (sd.decision === "deny") { post({ threatId: 0, category: "MCP: unapproved server", riskLevel: "Blocked", stage: "mcp", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: djb2(server), ...IDENTITY }); return emit("deny", sd.reason); }
    const args = JSON.stringify(ti);
    const ad = decideMcpArgs(policy, tool, args); // #18 — per-tool argument allow/deny rules
    if (ad.decision === "deny") { post({ threatId: 0, category: "MCP: denied tool argument", riskLevel: "Blocked", stage: "mcp", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: djb2(args), ...IDENTITY }); return emit("deny", ad.reason); }
    const d = decideText(engine, policy, args, "prompt"); // #2 — scan args
    report(d.findings, "egress", `hook:${tool}`, d.decision === "deny", policy.captureTier, { toolName: tool, argText: args });
    logBehavior(tool, tool, args, d, "egress");
    return emit(d.decision, `blocked ${tool} — ${d.reasons.join(", ")}`);
  }
  process.exit(0); // unknown tool → allow
}

main();
