// #1/#2/#3 — shared, side-effect-free core for the MoorAI PreToolUse hook. Kept separate from the
// stdin/stdout entrypoint (moorai-hook.mjs) so the decision logic is unit-testable without spawning a
// process. Governance, not a sandbox: on any error or missing policy the caller fails OPEN (allows).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
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
  const out = { decision: "allow", reasons: [], findings: [] };
  if (!text || !text.trim()) return out;
  const bump = (d) => { if (RANK[d] > RANK[out.decision]) out.decision = d; };
  for (const f of engine.scan(text, stage)) {
    const act = threatActionFor(policy, f.threat.id);
    if (act === "disabled") continue;
    out.findings.push({ threatId: f.threat.id, category: f.threat.category, riskLevel: calibrateRisk(f.threat.riskLevel, { stage, category: f.threat.category }), match: f.match });
    if (act === "block") { bump("deny"); out.reasons.push(`#${f.threat.id} ${f.threat.category}`); }
    else if (act === "justify") { bump("ask"); out.reasons.push(`#${f.threat.id} ${f.threat.category} (needs sign-off)`); }
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

// Conservative file-path extraction from a Bash command — only for unambiguous leading file-readers.
// Anything with a pipe/redirect/subshell is left alone (fail-open); the strong guarantee is on Read.
export function extractReadPaths(command) {
  const cmd = String(command || "").trim();
  if (!cmd || /[|><`$(){}]|&&|\|\|/.test(cmd)) return [];
  const m = cmd.match(/^(?:cat|head|tail|less|bat|xxd|nl|more)\s+(.+)$/);
  if (!m) return [];
  return m[1].split(/\s+/).filter((t) => t && !t.startsWith("-")).slice(0, 8);
}
