// The portable subset of a MoorAI policy: the part a host's own settings file can carry. Pure.
//
//   portableIntent(policy) -> { tools: { deny, ask, allowOnly }, mcp: { allowOnly }, egress: { entries, dflt, list }, unexpressed }
//
// Sources (each read with the same meaning MoorAI's own check gives it):
//   tagActions        data/tool-tags.js tagActionsFrom. "block" -> deny, "ask" -> ask, for the built-in tools
//                     whose tag is fixed (BUILTIN_TOOL_TAGS). "alert"/"allow" let the call through: nothing.
//   entitlements      cli/hook-core.mjs decideEnvelope, only with entitlementMode "block": tools -> an allow-only
//                     tool list, mcp -> narrows the MCP allow-list. "alert" mode allows, so nothing is compiled.
//   mcpAllow/mcpGate  cli/hook-core.mjs decideMcpServer: gate on -> the list (empty = none); gate off -> a
//                     non-empty list, or no list at all.
//   egressRules/egressDefault  cli/egress-rules.mjs, validated by validateEgressRule; each host maps them.
// Tool names are Claude Code's, the names every MoorAI host adapter translates into (cli/agent-hooks/*).
//
// unexpressed lines: { source, item?|index?|id?, tool?, effect, reason } — the same effects as
// cli/sandbox-policy.mjs (omitted, coarsened, narrowed, approximated, may-be-inert, invalid). Content-free:
// sources, tag names, tool names, rule indexes and the egress rule id the admin wrote (printed as written),
// never a rule's host, a path or a server name.

import { BUILTIN_TOOL_TAGS, tagActionsFrom } from "../../data/tool-tags.js";
import { validateEgressRule, validEgressDefault } from "../egress-rules.mjs";

export const CANON_TOOLS = Object.freeze(["Bash", "Edit", "Glob", "Grep", "LS", "Monitor", "MultiEdit", "NotebookEdit", "NotebookRead", "PowerShell", "Read", "Task", "WebFetch", "WebSearch", "Write"]);
const MAX_RULES = 512;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const sortU = (a) => [...new Set(a)].sort();
const strList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string" && x) : []);
const toolsWithTag = (tag) => Object.keys(BUILTIN_TOOL_TAGS).filter((t) => BUILTIN_TOOL_TAGS[t].includes(tag));

function tools(policy, out) {
  const deny = [], ask = [];
  const { actions, rejected } = tagActionsFrom({ policy });
  for (const r of rejected) out.push({ source: "tagActions", ...(r.tag ? { item: r.tag } : {}), effect: "invalid", reason: "invalid-tag-action" });
  for (const tag of Object.keys(actions).sort()) {
    const act = actions[tag];
    if (act !== "block" && act !== "ask") continue;
    if (tag === "read-private") { out.push({ source: "tagActions", item: tag, effect: "omitted", reason: "tag-decided-from-content" }); continue; }
    (act === "block" ? deny : ask).push(...toolsWithTag(tag));
    // The tag also lands on MCP tools (declared or by name) and on shell commands parsed as reading,
    // writing or reaching the network: a tool-name rule covers the built-in tools only.
    out.push({ source: "tagActions", item: tag, effect: "coarsened", reason: "tag-beyond-builtin-tools" });
  }
  const exc = Array.isArray(policy.exceptions) ? policy.exceptions : [];
  for (const tag of Object.keys(actions).sort()) {
    if (!["block", "ask"].includes(actions[tag]) || tag === "read-private") continue;
    if (exc.some((e) => e && e.rule === `tag:${tag}`)) out.push({ source: "exceptions", item: tag, effect: "narrowed", reason: "tag-exception-not-native" });
  }
  let allowOnly = null;
  const env = policy.entitlements;
  if (policy.entitlementMode === "block" && env && typeof env === "object" && strList(env.tools).length) {
    allowOnly = sortU(strList(env.tools));
    if (Array.isArray(policy.elevations) && policy.elevations.some((g) => g && typeof g.capability === "string" && g.capability.startsWith("tool:"))) {
      out.push({ source: "elevations", effect: "narrowed", reason: "jit-elevation-not-native" });
    }
  }
  const askOnly = sortU(ask).filter((t) => !deny.includes(t));
  return { deny: sortU(deny), ask: askOnly, allowOnly };
}

function mcp(policy, out) {
  const list = strList(policy.mcpAllow);
  let allowOnly = null;
  if (policy.mcpGate === true) allowOnly = sortU(list);
  else if (list.length) allowOnly = sortU(list);
  const env = policy.entitlements;
  if (policy.entitlementMode === "block" && env && typeof env === "object" && strList(env.mcp).length) {
    const e = sortU(strList(env.mcp));
    allowOnly = allowOnly === null ? e : allowOnly.filter((s) => e.includes(s));
    if (Array.isArray(policy.elevations) && policy.elevations.some((g) => g && typeof g.capability === "string" && g.capability.startsWith("mcp:"))) {
      out.push({ source: "elevations", effect: "narrowed", reason: "jit-elevation-not-native" });
    }
  }
  return { allowOnly };
}

// Egress entries in policy order. kind: name | ip4 | ip6 | suffix; cond: the request fields a host's
// domain list cannot see (binary, method, path).
function egress(policy, out) {
  const raw = policy.egressRules;
  const entries = [];
  if (raw !== undefined && raw !== null) {
    if (!Array.isArray(raw)) out.push({ source: "egressRules", index: -1, effect: "invalid", reason: "not-a-list" });
    else {
      raw.slice(0, MAX_RULES).forEach((r, index) => {
        const v = validateEgressRule(r);
        const id = r && typeof r.id === "string" && ID_RE.test(r.id) ? r.id : undefined;
        if (v.error) { out.push({ source: "egressRules", index, ...(id ? { id } : {}), effect: "invalid", reason: "invalid-rule" }); return; }
        const h = v.rule.host;
        const host = h.suffix ? h.suffix.slice(1) : h.exact;
        const kind = h.suffix ? "suffix" : host.startsWith("[") ? "ip6" : /^\d+\.\d+\.\d+\.\d+$/.test(host) ? "ip4" : "name";
        entries.push({
          index, ...(id ? { id } : {}), action: r.action, allow: r.action !== "block", kind, host,
          ports: v.rule.port ? [...new Set(v.rule.port)].sort((a, b) => a - b) : null,
          cond: ["binary", "method", "path"].filter((k) => r[k] !== undefined)
        });
      });
      if (raw.length > MAX_RULES) out.push({ source: "egressRules", index: MAX_RULES, effect: "invalid", reason: "too-many-rules" });
    }
  }
  let dflt = "allow";
  if (policy.egressDefault !== undefined && policy.egressDefault !== null) {
    if (validEgressDefault(policy.egressDefault)) dflt = policy.egressDefault === "block" ? "block" : "allow";
    else out.push({ source: "egressDefault", effect: "invalid", reason: "invalid-default" });
  }
  return { entries, dflt, set: entries.length > 0 || dflt === "block" };
}

export function portableIntent(policy) {
  const p = policy && typeof policy === "object" && !Array.isArray(policy) ? policy : {};
  const unexpressed = [];
  const t = tools(p, unexpressed);
  const m = mcp(p, unexpressed);
  const e = egress(p, unexpressed);
  return { tools: t, mcp: m, egress: e, unexpressed };
}

// The deny set a host compiles: tag denies, plus every built-in not on an allow-only list.
export function effectiveDeny(intent) {
  const d = new Set(intent.tools.deny);
  if (intent.tools.allowOnly) for (const t of CANON_TOOLS) if (!intent.tools.allowOnly.includes(t)) d.add(t);
  return [...d].sort();
}
