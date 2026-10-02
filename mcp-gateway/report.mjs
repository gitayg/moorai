// Content-free reporting for the gateway — the stdio proxy's alert and ledger shapes, with the tool
// labelled "gateway:<tool>" and mcpServer set to the route's server label. Only category / risk /
// one-way hash / server / tool / decision leave; never an argument, a result, a header or a URL.
import os from "node:os";
import { loadConfig } from "../cli/config.mjs";
import { isEnrolled, literacyTouchpoint, coachMessage } from "../cli/hook-core.mjs";
import { applyCaptureTier } from "../data/capture-tiers.js";
import { recordAction } from "../cli/signals.mjs";
import { contentHash, actorHash } from "../cli/content-hash.mjs";
import { emitOtel } from "../cli/otel.mjs";
import { serverMode, serviceWho } from "../cli/server-mode.mjs";

export const CONFIG = loadConfig();
export const SERVER_MODE = serverMode();
const WHO = SERVER_MODE.active ? serviceWho(SERVER_MODE) : { user: os.userInfo().username, device: os.hostname() };
export const IDENTITY = { user: WHO.user, device: WHO.device, platform: os.platform(), tenant: CONFIG.tenant, actor: actorHash(WHO.user, WHO.device) };

let tierOf = () => "content-free";
export function setTierSource(fn) { tierOf = fn; }

export function post(alert) {
  try { emitOtel(alert, { config: CONFIG, identity: IDENTITY }); } catch { /* telemetry is never enforcement */ }
  if (!isEnrolled(CONFIG)) return;
  try {
    return fetch(`${CONFIG.serverUrl}/api/alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {}) },
      body: JSON.stringify(alert),
      signal: AbortSignal.timeout(1500)
    }).catch(() => {});
  } catch { /* never let a network error touch the request path */ }
}

function ledger(entry) {
  try { recordAction(applyCaptureTier(entry, {}, tierOf())); } catch { /* ledger is best-effort */ }
}

const REPORTED = new Set();
export function reportOnce(category, hash, riskLevel) {
  if (REPORTED.has(hash)) return;
  REPORTED.add(hash);
  post({ threatId: 0, category, riskLevel, stage: "policy", tool: "gateway:policy", ts: new Date().toISOString(), contentHash: hash, ...IDENTITY });
}

const SEEN = new Set();
export function seenOnce(token) {
  if (SEEN.has(token)) return false;
  if (SEEN.size >= 2048) SEEN.clear();
  SEEN.add(token);
  return true;
}

// The gateway's stderr is the operator's log. A coach note says what would have been blocked, never
// the content that would have been blocked.
export function coachNote(what, reason, alternatives) {
  try { process.stderr.write(`${coachMessage(`flagged ${what} — ${reason || "policy"}`, alternatives && alternatives[0])}\n`); } catch { /* a note */ }
}

const t = (tool) => `gateway:${tool}`;
const now = () => new Date().toISOString();

export function auditCall(server, tool, decision, argsHash) {
  ledger({ threatId: 0, category: "MCP tool call", riskLevel: decision === "deny" ? "Blocked" : "Info", stage: "mcp", tool: t(tool), decision, mcpServer: server, ts: now(), contentHash: argsHash, ...IDENTITY });
}

export function alertBlock(server, tool, gate, argsHash) {
  const category = gate === "server" ? "MCP: unapproved server" : gate === "args" ? "MCP: denied tool argument" : gate === "file" ? "MCP: blocked file argument" : gate === "egress" ? "MCP: local secret egress" : "MCP: blocked tool argument";
  post({ threatId: 0, category, riskLevel: "Blocked", stage: "mcp", tool: t(tool), decision: "deny", mcpServer: server, ts: now(), contentHash: argsHash, ...IDENTITY });
  try { post({ ...literacyTouchpoint({ threatId: 0, category, tool: t(tool) }), ...IDENTITY }); } catch { /* evidence */ }
}

export function alertFindings(server, tool, findings, blocked, stage = "mcp") {
  for (const f of findings || []) {
    post({ threatId: f.threatId, category: f.category, riskLevel: blocked ? "Blocked" : f.riskLevel, stage, tool: t(tool), mcpServer: server, ts: now(), contentHash: contentHash(f.match || ""), ...IDENTITY });
    if (blocked || f.riskLevel === "High" || f.riskLevel === "Critical") {
      try { post({ ...literacyTouchpoint({ threatId: f.threatId, category: f.category, tool: t(tool) }), ...IDENTITY }); } catch { /* evidence */ }
    }
  }
}

// #65 — only the one-way hashes of the matched local secrets leave, as in the hook.
export function alertEgress(server, tool, hits, blocked) {
  post({ threatId: 65, category: "Local secret value egress", riskLevel: blocked ? "Blocked" : "Critical", stage: "egress", tool: t(tool), mcpServer: server, ts: now(), contentHash: "egress:" + hits.join("."), ...IDENTITY });
}

export function alertTool(server, toolName, { category, riskLevel, threatId = 0, hash, decision = "notify" }) {
  const a = { threatId, category, riskLevel, stage: "tool", tool: t(toolName), decision, mcpServer: server, ts: now(), contentHash: hash, ...IDENTITY };
  post(a);
  if (riskLevel === "High" || riskLevel === "Critical" || riskLevel === "Blocked") {
    try { post({ ...literacyTouchpoint({ threatId, category, tool: t(toolName) }), ...IDENTITY }); } catch { /* evidence */ }
  }
  ledger(a);
}

export function alertResult(server, toolName, findings, blocked) {
  for (const f of findings || []) {
    const a = { threatId: f.threatId, category: f.category, riskLevel: blocked ? "Blocked" : f.riskLevel, stage: "result", tool: t(toolName), decision: blocked ? "deny" : "notify", mcpServer: server, ts: now(), contentHash: contentHash(f.match || ""), ...IDENTITY };
    post(a);
    if (blocked || f.riskLevel === "High" || f.riskLevel === "Critical") {
      try { post({ ...literacyTouchpoint({ threatId: f.threatId, category: f.category, tool: t(toolName) }), ...IDENTITY }); } catch { /* evidence */ }
    }
    ledger(a);
  }
}

export function alertHeadless(server, tool, alert) {
  post({ ...alert, tool: t(tool), mcpServer: server, ts: now(), ...IDENTITY });
}

export function recordLedger(entry) { ledger(entry); }
