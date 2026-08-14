// #1/#2/#3 — shared, side-effect-free core for the MoorAI PreToolUse hook. Kept separate from the
// stdin/stdout entrypoint (moorai-hook.mjs) so the decision logic is unit-testable without spawning a
// process. Governance, not a sandbox: on any error or missing policy the caller fails OPEN (allows).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { extractEndpointHosts, endpointApproved } from "../data/model-endpoints.js";
import { TIER_OF } from "../data/data-tiers.js";
import { APPROVAL_THREATS } from "../data/human-approval.js";
import { compilePacks } from "../data/detector-packs.js";
import { DetectionEngine } from "../src/engine.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

export function buildEngine(policy) {
  const threatData = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const engine = new DetectionEngine(threatData, DETECTORS, CONTENT_RULES);
  try { engine.applyPacks(compilePacks(policy?.detectorPacks)); } catch { /* packs optional */ }
  return engine;
}

// Resolve the action for a threat exactly like the app/guard: per-threat → data-tier → approval-set
// → notify. So a secret in a read file defaults to "notify" (report, don't block) unless an admin
// explicitly escalates it — the safe default that keeps false positives from blocking work.
export function threatActionFor(policy, id) {
  const explicit = policy?.threatPolicy?.[id];
  if (explicit) return explicit;
  const tier = TIER_OF[id];
  const tierAct = tier && policy?.tierPolicy?.[tier];
  if (tierAct) return tierAct;
  if (APPROVAL_THREATS.has(id)) return "justify";
  return "notify";
}

const RANK = { allow: 1, ask: 2, deny: 3 };

// #10 — context-aware severity. The same pattern is more critical by WHERE it was caught: a secret
// read into an agent's context (stage "file") or shipped as an MCP tool-call argument (stage "mcp"/
// "egress") is worse than one typed into a prompt the user can still edit before sending. Label-only:
// this adjusts the reported riskLevel, never the allow/ask/deny decision.
const LEVELS = ["Low", "Medium", "High", "Critical"];
const SECRET_RE = /secret|credential|api[\s-]?key|token|password|private key/i;
export function isSecretCategory(category) { return SECRET_RE.test(String(category || "")); }
export function calibrateRisk(base, { stage, category } = {}) {
  if (!isSecretCategory(category)) return base;
  const i = LEVELS.indexOf(base);
  if (i < 0) return base;
  if (stage === "file" || stage === "mcp" || stage === "egress") return LEVELS[Math.min(i + 1, LEVELS.length - 1)];
  return base;
}

// Scan text and reduce all findings to a single decision (deny > ask > allow) plus content-free
// findings for reporting. Only "block" → deny; "justify" → ask; "notify"/"alert" → allow-but-report.
export function decideText(engine, policy, text, stage) {
  const out = { decision: "allow", reasons: [], findings: [], kill: false, killIds: [] };
  if (!text || !text.trim()) return out;
  const bump = (d) => { if (RANK[d] > RANK[out.decision]) out.decision = d; };
  for (const f of engine.scan(text, stage)) {
    const act = threatActionFor(policy, f.threat.id);
    if (act === "disabled") continue;
    const level = calibrateRisk(f.threat.riskLevel, { stage, category: f.threat.category });
    out.findings.push({ threatId: f.threat.id, category: f.threat.category, riskLevel: level, match: f.match });
    // #3 — "kill" terminates the whole session, not just this call. It still denies the call (Claude
    // Code only knows allow/ask/deny); the kill signal is carried out-of-band via out.kill for the host.
    // killOnCritical promotes any Critical block to a kill without per-threat config.
    const kill = act === "kill" || (policy?.killOnCritical && act === "block" && level === "Critical");
    if (act === "block" || act === "kill") { bump("deny"); out.reasons.push(`#${f.threat.id} ${f.threat.category}`); }
    else if (act === "justify") { bump("ask"); out.reasons.push(`#${f.threat.id} ${f.threat.category} (needs sign-off)`); }
    if (kill) { out.kill = true; out.killIds.push(f.threat.id); }
  }
  const cp = policy?.contentPolicy || {};
  const enabled = Object.keys(cp).filter((id) => cp[id] && cp[id] !== "disabled");
  if (enabled.length) for (const c of engine.scanContent(text, enabled)) {
    const act = cp[c.ruleId] || "disabled";
    if (act === "disabled") continue;
    out.findings.push({ threatId: 0, category: `Content: ${c.label}`, riskLevel: act === "block" ? "Blocked" : "High", match: c.match });
    if (act === "block") { bump("deny"); out.reasons.push(`content: ${c.label}`); }
    else if (act === "justify") bump("ask");
  }
  return out;
}

// #3 — MCP server allow/deny. Enforce only when an allow-list is set; otherwise report-only (preserve
// today's behavior). A denied server short-circuits before the arg scan.
export function decideMcpServer(policy, serverName) {
  const allow = policy?.mcpAllow;
  if (!Array.isArray(allow) || !allow.length) return { decision: "allow" };
  if (allow.includes(serverName)) return { decision: "allow" };
  return { decision: "deny", reason: `MCP server '${serverName}' is not on your organization's allow-list.` };
}

// #18 — per-tool MCP argument rules. policy.mcpToolRules[tool] = { deny:[regex], allow:[regex] }.
// A deny pattern matched in the serialized args → deny. If an allow-list is set for the tool, at least
// one allow pattern must match or it's denied. No rule for the tool → allow (unchanged behavior).
export function decideMcpArgs(policy, tool, argsText) {
  const rules = policy?.mcpToolRules?.[tool];
  if (!rules) return { decision: "allow" };
  const text = String(argsText || "");
  const mk = (p) => { try { return new RegExp(p, "i"); } catch { return null; } };
  if (Array.isArray(rules.deny)) for (const p of rules.deny) { const re = mk(p); if (re && re.test(text)) return { decision: "deny", reason: `${tool} argument matches a denied pattern` }; }
  if (Array.isArray(rules.allow) && rules.allow.length) {
    const ok = rules.allow.some((p) => { const re = mk(p); return re && re.test(text); });
    if (!ok) return { decision: "deny", reason: `${tool} argument is not on the allow-list` };
  }
  return { decision: "allow" };
}

// T1-1 / #63 — model-endpoint allow-list. Enforce only when policy.endpointAllow is set; a referenced
// LLM endpoint host (base-URL override target or direct provider call) not on the list → deny. Loopback
// (local models) is always allowed. Content-free: operates on hosts, never content.
export function decideEndpoints(policy, text) {
  const allow = policy?.endpointAllow;
  if (!Array.isArray(allow) || !allow.length) return { decision: "allow", hosts: [] };
  const bad = extractEndpointHosts(text).filter((h) => !endpointApproved(h, allow));
  if (bad.length) return { decision: "deny", hosts: bad, reason: `model endpoint(s) not on the allow-list: ${bad.join(", ")}` };
  return { decision: "allow", hosts: [] };
}

// T1-5 / #64 — agent entitlement envelope. policy.entitlements = { tools:[], paths:[], mcp:[] } declares
// the agent's authorized surface; an observed tool / path-prefix / MCP server outside it is "drift".
// Returns the out-of-scope reasons (empty = in scope). Enforcement strictness is policy.entitlementMode
// ("off" | "alert" | "block"). Content-free: names/paths only. An empty/absent envelope → always in scope.
export function decideEnvelope(policy, { tool, paths = [], mcpServer, actor } = {}) {
  const env = policy?.entitlements;
  if (!env || typeof env !== "object") return { inScope: true, reasons: [], elevated: false };
  const reasons = [];
  if (Array.isArray(env.tools) && env.tools.length && tool && !env.tools.includes(tool)) reasons.push(`tool:${tool}`);
  if (Array.isArray(env.mcp) && env.mcp.length && mcpServer && !env.mcp.includes(mcpServer)) reasons.push(`mcp:${mcpServer}`);
  if (Array.isArray(env.paths) && env.paths.length) {
    for (const p of paths) { if (p && !env.paths.some((a) => String(p).startsWith(a))) reasons.push(`path:${p}`); }
  }
  // JIT elevation: an out-of-envelope reason covered by a live, non-expired grant for THIS actor is
  // allowed (time-boxed) rather than flagged. Grants are exact for tool:/mcp:, prefix for path:.
  const grants = (Array.isArray(policy?.elevations) ? policy.elevations : []).filter((g) => !actor || g.actor === actor);
  const covered = (r) => grants.some((g) => g.capability === r ||
    (g.capability.startsWith("path:") && r.startsWith("path:") && r.slice(5).startsWith(g.capability.slice(5))));
  const remaining = reasons.filter((r) => !covered(r));
  return { inScope: remaining.length === 0, reasons: remaining, elevated: remaining.length < reasons.length, usedGrants: reasons.length - remaining.length };
}

// Conservative file-path extraction from a Bash command — only for unambiguous leading file-readers.
// Anything with a pipe/redirect/subshell is left alone (fail-open); the strong guarantee is on Read.
export function extractReadPaths(command) {
  const cmd = String(command || "").trim();
  if (!cmd || /[|><`$(){}]|&&|\|\|/.test(cmd)) return [];
  const m = cmd.match(/^(?:cat|head|tail|less|bat|xxd|nl|more)\s+(.+)$/);
  if (!m) return [];
  return m[1].split(/\s+/).filter((t) => t && !t.startsWith("-")).slice(0, 8);
}
