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
import { buildEngine, decideText, decideEndpoints, decideEnvelope, threatActionFor, extractReadPaths, mcpGateway, offlineMode, breakGlassActive, mcpFloor } from "./hook-core.mjs";
import { OFFLINE_DEFAULT_POLICY } from "../data/offline-default.js";
import { egressHits } from "./secret-egress.mjs";
import { recordExposure, recordAgentEvent, readAgentEvents, recordAction, rulesBaseline, setRulesBaseline, requestKill } from "./signals.mjs";
import { applyCaptureTier, commandShape } from "../data/capture-tiers.js";
import { isRulesFile, rulesFileKind } from "../data/rules-files.js";
import { signApproval, argsHash } from "../data/agency-sign.mjs";
import { contentTells, assessSession, assessTrifecta, assessCrossServerTrifecta, trifectaLegs, serverOf } from "../data/agent-behavior.js";
import { classifyOpportunistic } from "../data/model-escalation.mjs";

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
  s.hooks.PreToolUse = [...cur.filter((e) => !isCuraiq(e)), entry("Read"), entry("Bash"), entry("mcp__.*"), entry("Task")];
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
// #33 — break-glass marker (operator-created, holds an expiry) and the durable last-known posture the
// hook remembers so a fail-closed org stays fail-closed even if the policy cache is later deleted.
const BREAK_GLASS = join(os.homedir(), ".curaiq", "break-glass");
const POSTURE_SIDECAR = join(os.homedir(), ".curaiq", "offline-posture");

// Returns { policy, source } where source is:
//   "fresh"        — freshly fetched from the server (and re-cached)
//   "cache"        — served from the fresh-cache window without a fetch attempt
//   "cache-offline"— fetch FAILED, falling back to the last-known cached policy (offline; #33 point 2)
//   "none"         — no policy at all (offline AND no cache)
async function loadPolicy() {
  try { if (Date.now() - statSync(CACHE).mtimeMs < 60000) return { policy: JSON.parse(readFileSync(CACHE, "utf8")), source: "cache" }; } catch { /* stale/absent */ }
  try {
    const headers = CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {};
    const p = await fetch(`${CONFIG.serverUrl}/api/policy?tenant=${encodeURIComponent(CONFIG.tenant)}`, { headers, signal: AbortSignal.timeout(1500) }).then((r) => r.json());
    if (p) { try { mkdirSync(dirname(CACHE), { recursive: true }); writeFileSync(CACHE, JSON.stringify(p)); } catch {} return { policy: p, source: "fresh" }; }
  } catch { /* offline */ }
  try { return { policy: JSON.parse(readFileSync(CACHE, "utf8")), source: "cache-offline" }; } catch { return { policy: null, source: "none" }; }
}

// #33 — remember the org's chosen posture durably, so it survives a later cache deletion. Written every
// time a real policy loads. For an org that never set offlineMode this is "fail-open" → no-cache stays
// exit(0)/allow (unchanged default). Best-effort; a write error never affects enforcement.
function rememberPosture(policy) {
  try { mkdirSync(dirname(POSTURE_SIDECAR), { recursive: true }); writeFileSync(POSTURE_SIDECAR, offlineMode(policy)); } catch { /* best-effort */ }
}
// Durable last-known posture for the NO-policy/no-cache case: env override → sidecar → "fail-open".
function durablePosture() {
  const env = String(process.env.MOORAI_OFFLINE_MODE || "").trim();
  if (env === "fail-closed" || env === "fail-open") return env;
  try { const m = readFileSync(POSTURE_SIDECAR, "utf8").trim(); if (m === "fail-closed" || m === "fail-open") return m; } catch { /* absent */ }
  return "fail-open"; // default — never flip an org to fail-closed implicitly
}
function readBreakGlassText() { try { return readFileSync(BREAK_GLASS, "utf8"); } catch { return ""; } }
// #33 — content-free policy-posture signals (category/hash only; no file, arg, or content ever).
function postPosture(category, hash, riskLevel) { return post({ threatId: 0, category, riskLevel, stage: "policy", tool: "hook:policy", ts: new Date().toISOString(), contentHash: hash, ...IDENTITY }); }

// ---- content-free reporting ----
function djb2(s) { let h = 5381; for (let i = 0; i < String(s).length; i++) h = ((h << 5) + h + String(s).charCodeAt(i)) >>> 0; return "h" + h.toString(16); }
// #10 — every emitted action carries a stable, content-free actor fingerprint (one-way hash of
// user@device) so the console can tie actions to an operator without storing raw identity as the key.
const IDENTITY = { user: os.userInfo().username, device: os.hostname(), platform: os.platform(), tenant: CONFIG.tenant, actor: djb2(`${os.userInfo().username}@${os.hostname()}`) };
function post(alert) { return fetch(`${CONFIG.serverUrl}/api/alerts`, { method: "POST", headers: { "Content-Type": "application/json", ...(CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {}) }, body: JSON.stringify(alert), signal: AbortSignal.timeout(1500) }).catch(() => {}); }
function report(findings, stage, tool, blocked, tier, extras, agency) {
  for (const f of findings) {
    const base = { threatId: f.threatId, category: f.category, riskLevel: blocked ? "Blocked" : f.riskLevel, stage, tool, ts: new Date().toISOString(), contentHash: djb2(f.match || ""), ...IDENTITY };
    // #5 — attach only the fields the policy's capture tier permits (content-free by default). The
    // server independently re-strips above the device's stored tier, so this is one of two backstops.
    const alert = applyCaptureTier(base, { ...extras, matchText: f.match }, tier || "content-free");
    if (agency) Object.assign(alert, agency); // #20 — content-free signed approval token (metadata)
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
    const server = serverOf(tool); // which MCP server (or "local") contributed this event's legs
    const priorEvents = readAgentEvents();
    const beforeS = assessSession(priorEvents), beforeT = assessTrifecta(priorEvents), beforeX = assessCrossServerTrifecta(priorEvents);
    recordAgentEvent({ ts: Date.now(), sig: `${tool}|${djb2(identity || tool)}`, ok: d.decision !== "deny", risk, flags, legs, server });
    const events = readAgentEvents(), afterS = assessSession(events), afterT = assessTrifecta(events), afterX = assessCrossServerTrifecta(events);
    if (afterS.level === "autonomous-signature" && beforeS.level !== "autonomous-signature") {
      post({ threatId: 0, category: "Autonomous-agent behavior", riskLevel: "Critical", stage: "behavior", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "sig:" + afterS.tells.map((t) => t.id).join("."), signature: { level: afterS.level, score: afterS.score, tells: afterS.tells.map((t) => t.id), events: afterS.events }, ...IDENTITY });
    }
    // #1 — the lethal trifecta just closed in this session (all three legs now present).
    if (afterT.present && !beforeT.present) {
      post({ threatId: 59, category: "Lethal trifecta exposure", riskLevel: "High", stage: "behavior", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "trifecta:read.ingest.callout", signature: { legs: afterT.legs }, ...IDENTITY });
    }
    // Cross-server confused-deputy — the trifecta just closed across ≥2 DISTINCT servers, so no single
    // server's tool profile looks lethal. Distinct content-free alert (reuses threat 59 with its own
    // category + a signature listing the contributing servers per leg). Server identifiers may leave the
    // device; content never does. Best-effort: still inside the enforcement-neutral try/catch.
    if (afterX.crossServer && !beforeX.crossServer) {
      post({ threatId: 59, category: "Cross-server toxic flow", riskLevel: "High", stage: "behavior", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "xserver:" + afterX.servers.join("+"), signature: { crossServer: true, servers: afterX.servers, legs: afterX.legs, serversByLeg: afterX.serversByLeg }, ...IDENTITY });
    }
  } catch { /* behavior signal is best-effort; never affects enforcement */ }
}

// Bold B1 / #21 — opportunistic model escalation. Only when the org enables it AND the regex pass was
// ambiguous (nothing already High+); consults the unified opportunistic classifier (local loopback
// model first, else the agent's OWN provider when the org opted in and a device key exists) and emits
// a content-free second-opinion alert (#58). No NEW egress/third party; a failure never changes
// enforcement (fail-open).
async function maybeEscalate(policy, text, stage, tool, d) {
  try {
    if (!policy || !policy.modelEscalation || !text || !text.trim()) return;
    const strong = (d.findings || []).some((f) => f.riskLevel === "High" || f.riskLevel === "Critical" || f.riskLevel === "Blocked");
    if (strong) return; // regex is already confident — skip the second opinion
    const v = await classifyOpportunistic(text, policy);
    if (v && v.flagged && v.confidence >= 0.6) {
      post({ threatId: 58, category: `Model-flagged: ${v.category}`, riskLevel: v.confidence >= 0.85 ? "High" : "Medium", stage, tool: `escalate:${tool}`, ts: new Date().toISOString(), contentHash: djb2(text), ...IDENTITY });
    }
  } catch { /* escalation is advisory; fail-open */ }
}

// Rules-file hygiene (Backslash-inspired, content-free). A coding-agent rules/config file the agent
// auto-loads is high-value to poison — one injected directive steers every future prompt. Flags two
// things, content-free: (a) injected/hidden instructions found in the file (reuses the injection
// detectors), and (b) drift from the last-seen fingerprint. Only the file KIND and a one-way hash leave.
function reportRulesFile(path, text, d) {
  try {
    const kind = rulesFileKind(path);
    if (!kind || !text) return;
    const fp = djb2(text);
    const injected = (d.findings || []).some((f) => [3, 40, 50, 51].includes(f.threatId));
    const base = rulesBaseline();
    const drift = base[kind] != null && base[kind] !== fp;
    setRulesBaseline(kind, fp);
    if (injected || drift) {
      post({ threatId: 60, category: injected ? "Rules-file poisoning" : "Rules-file drift", riskLevel: injected ? "High" : "Medium", stage: "file", tool: `rules:${kind}`, ts: new Date().toISOString(), contentHash: fp, ...IDENTITY });
    }
  } catch { /* best-effort; never affects enforcement */ }
}

function readFileCapped(fp) {
  try {
    if (!fp) return "";
    const slice = readFileSync(fp).subarray(0, 262144);
    if (slice.includes(0)) return ""; // skip binary
    return slice.toString("utf8");
  } catch { return ""; }
}

// #3 — kill enforcement for the interactive session. A "kill" verdict still denies THIS call (below),
// but also drops a content-free sentinel the Tauri host watches for to terminate the whole agent PTY —
// detect-and-prevent, not just deny-one-call. Emits a session-kill alert (→ server/SIEM). Only the
// terminating rule ids leave the device, never the tool input.
function killSession(tool, ids, stage) {
  if (!ids || !ids.length) return;
  requestKill({ tool, ids, stage });
  post({ threatId: 0, category: "Session terminated (kill)", riskLevel: "Blocked", stage, tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "kill:" + ids.join("."), ...IDENTITY });
}

// T1-5 / #64 — report agent entitlement drift content-free (only the out-of-scope reason tokens leave)
// and return whether policy says to block it. entitlementMode: "off" (default) | "alert" | "block".
function reportEnvelope(policy, tool, ctx, stage) {
  const mode = policy?.entitlementMode || "off";
  if (mode === "off") return false;
  const d = decideEnvelope(policy, { ...ctx, actor: IDENTITY.actor }); // JIT: honor this actor's live grants
  // A live grant covered an otherwise-out-of-envelope action — log the time-boxed elevation, content-free.
  if (d.elevated) post({ threatId: 0, category: "JIT elevation used", riskLevel: "Info", stage, tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "elev:" + djb2(String(d.usedGrants)), ...IDENTITY });
  if (d.inScope) return false;
  post({ threatId: 64, category: "Agent entitlement drift", riskLevel: mode === "block" ? "Blocked" : "High", stage, tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "drift:" + djb2(d.reasons.join("|")), driftReasons: d.reasons, ...IDENTITY });
  return mode === "block";
}

// Tier-2 / #65 — local secret-value egress. Fingerprints local secrets on-device and checks the
// outbound text for a verbatim match; only the matched hashes leave. Blocks when policy #65 is block/kill.
function checkSecretEgress(policy, text, tool, stage) {
  try {
    const hits = egressHits(text);
    if (!hits.length) return false;
    const act = threatActionFor(policy, 65);
    const block = act === "block" || act === "kill";
    post({ threatId: 65, category: "Local secret value egress", riskLevel: block ? "Blocked" : "Critical", stage, tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "egress:" + hits.join("."), ...IDENTITY });
    return block;
  } catch { return false; }
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
  let { policy, source } = await loadPolicy();
  if (policy) rememberPosture(policy); // durable last-known posture survives a later cache deletion (#33)
  // #33 — break-glass / offline fail-closed. Wrapped so a bug here can never harden-then-crash: on ANY
  // error with no policy we fall through to the legacy exit(0) (fail-open), exactly as before.
  try {
    if (!policy) {
      if (durablePosture() !== "fail-closed") process.exit(0); // fail-open (default) — UNCHANGED behavior
      // Fail-closed posture with no policy: break-glass (if active) forces fail-open so an operator can
      // recover a locked-out machine; otherwise apply the conservative, reviewable built-in default.
      if (breakGlassActive(readBreakGlassText())) { await postPosture("Break-glass active (fail-open override)", "breakglass:active", "High"); process.exit(0); }
      postPosture("Offline: fail-closed default applied", "offline:fail-closed", "High");
      policy = OFFLINE_DEFAULT_POLICY;
    } else {
      // A fail-closed org can still break-glass out of its cached/live policy entirely.
      if (offlineMode(policy) === "fail-closed" && breakGlassActive(readBreakGlassText())) { await postPosture("Break-glass active (fail-open override)", "breakglass:active", "High"); process.exit(0); }
      if (source === "cache-offline") postPosture("Offline: enforcing last-known policy", "offline:last-known", "Info"); // #33 point 2
    }
  } catch { if (!policy) process.exit(0); /* preserve legacy fail-open on any error when no policy */ }
  const engine = buildEngine(policy);

  if (tool === "Read") {
    const text = readFileCapped(ti.file_path);
    const d = decideText(engine, policy, text, "file");
    report(d.findings, "file", "hook:Read", d.decision === "deny", policy.captureTier, { filePath: ti.file_path, toolName: "Read" });
    logBehavior("Read", ti.file_path || "file", text, d, "file");
    await maybeEscalate(policy, text, "file", "hook:Read", d);
    if (isRulesFile(ti.file_path)) reportRulesFile(ti.file_path, text, d);
    if (d.kill) killSession("Read", d.killIds, "file");
    let rdec = d.decision;
    if (reportEnvelope(policy, "Read", { tool: "Read", paths: [ti.file_path] }, "file") && rdec !== "deny") rdec = "deny";
    return emit(rdec, `${d.kill ? "killed session" : "blocked Read"} of ${basename(ti.file_path || "file")} — ${d.reasons.join(", ")}`);
  }
  if (tool === "Bash") {
    let dec = "allow", reasons = [], finds = [], btext = "", killIds = [];
    for (const p of extractReadPaths(ti.command)) {
      const t = readFileCapped(p); btext += t + "\n";
      const d = decideText(engine, policy, t, "file");
      finds.push(...d.findings);
      if (d.kill) killIds.push(...d.killIds);
      if (RANK[d.decision] > RANK[dec]) { dec = d.decision; reasons = d.reasons; }
      if (isRulesFile(p)) reportRulesFile(p, t, d);
    }
    // T1-2/T1-1 — scan the COMMAND itself (not just files it reads) so command-level detectors enforce:
    // typosquat/hallucinated install (#62), destructive (#43), reverse shell (#54), untrusted install (#57).
    const cmdD = decideText(engine, policy, ti.command, "prompt");
    finds.push(...cmdD.findings);
    if (cmdD.kill) killIds.push(...cmdD.killIds);
    if (RANK[cmdD.decision] > RANK[dec]) { dec = cmdD.decision; reasons = cmdD.reasons; }
    // T1-1 — model-endpoint allow-list: a base-URL override / direct call to a non-approved LLM host.
    const epD = decideEndpoints(policy, ti.command);
    if (epD.decision === "deny") { dec = "deny"; reasons = [epD.reason]; post({ threatId: 63, category: "Unapproved model endpoint", riskLevel: "Blocked", stage: "egress", tool: "hook:Bash", ts: new Date().toISOString(), contentHash: djb2(epD.hosts.join(",")), ...IDENTITY }); }
    report(finds, "file", "hook:Bash", dec === "deny", policy.captureTier, { toolName: "Bash", cmdShape: commandShape(ti.command) });
    logBehavior("Bash", ti.command || "bash", btext, { decision: dec, findings: finds }, "file");
    await maybeEscalate(policy, btext, "file", "hook:Bash", { findings: finds });
    if (killIds.length) killSession("Bash", killIds, "file");
    if (checkSecretEgress(policy, ti.command, "Bash", "egress") && dec !== "deny") { dec = "deny"; reasons = ["local secret egress"]; }
    if (reportEnvelope(policy, "Bash", { tool: "Bash", paths: extractReadPaths(ti.command) }, "file") && dec !== "deny") { dec = "deny"; reasons = ["out-of-envelope (entitlement drift)"]; }
    return emit(dec, `${killIds.length ? "killed session" : "blocked"} via Bash — ${reasons.join(", ")}`);
  }
  if (tool.startsWith("mcp__")) {
    const server = tool.split("__")[1] || "";
    const args = JSON.stringify(ti);
    const argsH = argsHash(args); // #20 — content-free hash of the args (never the args themselves)
    // On-device AI Agent Gateway: one named chokepoint for every MCP tool-call — server allow-list (#3)
    // → per-tool arg rules (#18) → argument content scan (#2), same order and short-circuits as before.
    const g = mcpGateway(engine, policy, { tool, server, args });
    // Content-free gateway ledger: record ONE audit line per MCP call (pass, coach, or block) so the
    // console can prove what every agent was allowed to do — closing the gap where denials and clean
    // passes recorded nothing locally. Best-effort; never affects the allow/deny decision.
    const audit = (decision) => { try { recordAction(applyCaptureTier({ threatId: 0, category: "MCP tool call", riskLevel: decision === "deny" ? "Blocked" : "Info", stage: "mcp", tool: `hook:${tool}`, decision, mcpServer: server, ts: new Date().toISOString(), contentHash: argsH, ...IDENTITY }, {}, policy.captureTier || "content-free")); } catch { /* ledger is best-effort */ } };
    if (g.gate === "server") { post({ threatId: 0, category: "MCP: unapproved server", riskLevel: "Blocked", stage: "mcp", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: djb2(server), ...IDENTITY, ...(signApproval(tool, argsH, "deny") || {}) }); audit("deny"); return emit("deny", g.reason); }
    if (g.gate === "args") { post({ threatId: 0, category: "MCP: denied tool argument", riskLevel: "Blocked", stage: "mcp", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: djb2(args), ...IDENTITY, ...(signApproval(tool, argsH, "deny") || {}) }); audit("deny"); return emit("deny", g.reason); }
    // T1-5 — entitlement envelope: an MCP server outside the agent's declared scope is drift.
    if (reportEnvelope(policy, tool, { tool, mcpServer: server }, "egress")) { audit("deny"); return emit("deny", `${tool} — out-of-envelope MCP server`); }
    // T1-1 — model-endpoint allow-list on the serialized args (a tool arg pointing at a rogue LLM host).
    const epD = decideEndpoints(policy, args);
    if (epD.decision === "deny") { post({ threatId: 63, category: "Unapproved model endpoint", riskLevel: "Blocked", stage: "egress", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: djb2(epD.hosts.join(",")), ...IDENTITY }); audit("deny"); return emit("deny", epD.reason); }
    // Tier-2 / #65 — a local secret value shipped as an MCP tool argument.
    if (checkSecretEgress(policy, args, tool, "egress")) { audit("deny"); return emit("deny", `${tool} — local secret egress`); }
    // #33 — fail-closed MCP floor: raise an otherwise-allowed MCP call to "ask" (justify). Inert unless
    // policy.mcpFloor is set (only the offline fail-closed default sets it), so normal policies are unaffected.
    const floored = mcpFloor(policy, g.decision);
    if (floored !== g.decision) { g.decision = floored; g.reason = g.reason || "fail-closed default: MCP requires justification"; }
    report(g.findings, "egress", `hook:${tool}`, g.decision === "deny", policy.captureTier, { toolName: tool, argText: args }, signApproval(tool, argsH, g.decision === "deny" ? "deny" : "allow"));
    logBehavior(tool, tool, args, { decision: g.decision, findings: g.findings }, "egress");
    if (g.kill) killSession(tool, g.killIds, "egress");
    audit(g.decision);
    return emit(g.decision, `${g.kill ? "killed session" : g.decision === "ask" ? "needs justification" : "blocked"} ${tool} — ${g.reason}`);
  }
  // Tier-2 / #66 — sub-agent spawn / A2A delegation (Claude Code's Task tool). Record the delegation
  // content-free, scan the delegated prompt for injection, apply the parent's entitlement envelope, and
  // block per policy. Extends blast-radius visibility to children that could otherwise bypass parent controls.
  if (tool === "Task") {
    const desc = JSON.stringify(ti);
    const act = threatActionFor(policy, 66);
    const block = act === "block" || act === "kill";
    post({ threatId: 66, category: "Sub-agent / A2A delegation", riskLevel: block ? "Blocked" : "Medium", stage: "behavior", tool: "hook:Task", ts: new Date().toISOString(), contentHash: djb2((ti.subagent_type || "") + "|" + desc), subagentType: ti.subagent_type, ...IDENTITY });
    logBehavior("Task", "Task", desc, { decision: block ? "deny" : "allow", findings: [] }, "behavior");
    const pd = decideText(engine, policy, ti.prompt || "", "prompt"); // scan the delegated prompt for injection
    report(pd.findings, "egress", "hook:Task", pd.decision === "deny", policy.captureTier, { toolName: "Task" });
    if (block || pd.decision === "deny" || reportEnvelope(policy, "Task", { tool: "Task" }, "behavior")) return emit("deny", `Task (sub-agent delegation) — ${block ? "blocked by policy" : pd.decision === "deny" ? pd.reasons.join(", ") : "out of envelope"}`);
    return emit("allow", "sub-agent delegation logged");
  }
  process.exit(0); // unknown tool → allow
}

main();
