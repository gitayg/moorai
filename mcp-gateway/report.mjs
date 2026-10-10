// Content-free reporting for the gateway — the stdio proxy's alert and ledger shapes, with the tool
// labelled "gateway:<tool>" and mcpServer set to the route's server label. Only category / risk /
// one-way hash / server / tool / decision leave; never an argument, a result, a header or a URL. A
// console alert also carries the `workload` object (container id, Kubernetes pod / namespace / node:
// cli/server-mode.mjs workloadIdentity) when one is detected — no pid, since the gateway is not the
// agent process the verdict is about. The local ledger does not get it.
// A console alert raised while the gateway handles a request that carries Mcp-Session-Id (the
// 2025-03-26 .. 2025-11-25 transport) also carries `session`: the keyed hash of that id (withSession).
// A request without one (initialize, the 2026-07-28 transport) and work outside any request (the
// reputation lookup, the usage flush) send no `session`.
import os from "node:os";
import { AsyncLocalStorage } from "node:async_hooks";
import { loadConfig } from "../cli/config.mjs";
import { isEnrolled, literacyTouchpoint, coachMessage } from "../cli/hook-core.mjs";
import { applyCaptureTier } from "../data/capture-tiers.js";
import { recordAction } from "../cli/signals.mjs";
import { contentHash, actorHash, NO_KEY } from "../cli/content-hash.mjs";
import { emitOtel } from "../cli/otel.mjs";
import { serverMode, serviceWho, workloadIdentity } from "../cli/server-mode.mjs";

export const CONFIG = loadConfig();
export const SERVER_MODE = serverMode();
const WHO = SERVER_MODE.active ? serviceWho(SERVER_MODE) : { user: os.userInfo().username, device: os.hostname() };
// agentName: the console's agent_name for this surface (RAISEME-server server/siem-fields.js AGENT_NAMES).
export const IDENTITY = { user: WHO.user, device: WHO.device, platform: os.platform(), tenant: CONFIG.tenant, actor: actorHash(WHO.user, WHO.device), agentName: "gateway" };
export const WORKLOAD = workloadIdentity();

let tierOf = () => "content-free";
export function setTierSource(fn) { tierOf = fn; }

const SESSION = new AsyncLocalStorage();
// The keyed hash of a raw MCP session id, or "" (no id, or no key: NO_KEY would merge every session).
export function sessionTag(raw) {
  if (typeof raw !== "string" || !raw) return "";
  const h = contentHash(raw);
  return h === NO_KEY ? "" : h;
}
// Runs fn with the request's session as the context every post() under it (awaits and upstream
// callbacks included) reads; a request with no session id runs with none, never an earlier request's.
export function withSession(raw, fn) { return SESSION.run(sessionTag(raw), fn); }

export function post(alert) {
  try { emitOtel(alert, { config: CONFIG, identity: IDENTITY }); } catch { /* telemetry is never enforcement */ }
  if (!isEnrolled(CONFIG)) return;
  const session = SESSION.getStore();
  try {
    return fetch(`${CONFIG.serverUrl}/api/alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {}) },
      body: JSON.stringify({ ...alert, ...(session && alert.session === undefined ? { session } : {}), ...(WORKLOAD ? { workload: WORKLOAD } : {}) }),
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
  const category = gate === "server" ? "MCP: unapproved server" : gate === "args" ? "MCP: denied tool argument" : gate === "file" ? "MCP: blocked file argument" : gate === "egress" ? "MCP: local secret egress" : gate === "index" ? "MCP: blocked vector-store write" : "MCP: blocked tool argument";
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

export function alertTool(server, toolName, { category, riskLevel, threatId = 0, hash, decision = "notify", reasonCode }) {
  const a = { threatId, category, riskLevel, stage: "tool", tool: t(toolName), decision, ...(reasonCode ? { reasonCode } : {}), mcpServer: server, ts: now(), contentHash: hash, ...IDENTITY };
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

// A tools/call refused because block-mode tool drift quarantined the tool (mcp-proxy/tool-drift.mjs).
export function alertDriftCall(server, tool, category, argsHash) {
  const a = { threatId: 0, category, riskLevel: "Blocked", stage: "mcp", tool: t(tool), decision: "deny", reasonCode: "MCP_TOOL_DRIFT", mcpServer: server, ts: now(), contentHash: argsHash, ...IDENTITY };
  post(a);
  ledger(a);
}

export function alertHeadless(server, tool, alert) {
  post({ ...alert, tool: t(tool), mcpServer: server, ts: now(), ...IDENTITY });
}

export function recordLedger(entry) { ledger(entry); }

// ---- C5 hardening verdicts (content-free: a stage, a schema-built JSON path, a limit, a duration) ----
// Each carries its provenance reasonCode (cli/provenance.mjs REASON). A refusal is riskLevel "Blocked" /
// decision "deny"; a report-only finding is "Medium" / "allow". The tool is "gateway:<tool>" when the
// message named a valid one, else "gateway:mcp". Repeats of the same finding are posted once per process
// (seenOnce) so a client sending a flood of bad messages cannot flood the console; the ledger keeps each.
export function alertSchema(server, { stage, path, header }, { direction, refused, tool = "mcp" }) {
  const a = { threatId: 0, category: "MCP gateway: invalid message", riskLevel: refused ? "Blocked" : "Medium", stage: "mcp", tool: t(tool), decision: refused ? "deny" : "allow", reasonCode: "SCHEMA_INVALID", schemaStage: stage, schemaPath: path, schemaDirection: direction, ...(header ? { schemaHeader: header } : {}), mcpServer: server, ts: now(), contentHash: `schema:${direction}:${stage}:${path}`, ...IDENTITY };
  if (seenOnce(`schema|${server}|${direction}|${stage}|${path}|${refused}`)) post(a);
  ledger(a);
}

export function alertTooLarge(server, tool, limitBytes) {
  const a = { threatId: 0, category: "MCP gateway: response too large", riskLevel: "Blocked", stage: "result", tool: t(tool), decision: "deny", reasonCode: "RESPONSE_TOO_LARGE", limitBytes, mcpServer: server, ts: now(), contentHash: `response-too-large:${limitBytes}`, ...IDENTITY };
  if (seenOnce(`too-large|${server}|${tool}`)) post(a);
  ledger(a);
}

// A workload-profile alert from cli/workload-profile.mjs (PROFILE_DRIFT with driftKind / driftItem /
// profileId, or the malformed-profile notice), as the hook posts it, with the gateway's tool and server.
export function alertProfile(server, tool, alert) {
  const a = { ...alert, tool: t(tool), mcpServer: server, ts: now(), ...IDENTITY };
  post(a);
  ledger(a);
}

// Posted once when a client ENTERS a cool-down, not for every request refused during it.
export function alertCooldown(server, cooldownSeconds) {
  const a = { threatId: 0, category: "MCP gateway: client cool-down", riskLevel: "Blocked", stage: "mcp", tool: t("mcp"), decision: "deny", reasonCode: "CLIENT_COOLDOWN", cooldownSeconds, mcpServer: server, ts: now(), contentHash: `client-cooldown:${server}`, ...IDENTITY };
  post(a);
  ledger(a);
}
