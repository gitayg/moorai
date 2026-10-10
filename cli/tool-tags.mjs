// Capability tags for one tool call, the session's tag record, and the two policy controls built on them
// (data/tool-tags.js has the tag names, the classifiers and the rule grammar):
//
//   tagActions  a static action per tag      { exec: "block", network: "block", write: "ask" }
//   tagRules    a session-conditional rule   [{ if: { sessionHas: ["read-private"] }, deny: ["network"], action: "block" }]
//
// SOURCES. The verified org policy and the root-owned machine-wide config (/etc/moorai/config.json,
// %ProgramData%\MoorAI\config.json) — the same two the workload profile and egress rules read. A repo
// file, a user-scope file or an environment variable is never one.
//
// THE SESSION RECORD (~/.moorai/session-tags.json, mode 0600, via cli/session-state.mjs): per keyed session
// id (HMAC with the device session.key, as fetch-exec.json), the tag NAMES of every call of that session
// that ran (a call the hook denied ran nothing and adds nothing), and the ids of alert-only rules already
// reported for it. 32 sessions, 24 h. NEVER STORED: a path, a host, a command or an argument.
//
// WHAT THIS DOES NOT DEFEND: the agent runs as the same user and can delete or edit the session record,
// clearing its own read-private tag (the same boundary every ~/.moorai session file has). The static
// tagActions read nothing from it.
import os from "node:os";
import { readSessionState, writeSessionState, sessionKeyedHash } from "./session-state.mjs";
import { extractReadPaths } from "./hook-core.mjs";
import { netDestinations, urlDestinations } from "../data/net-exec.js";
import { TAGS, BUILTIN_TOOL_TAGS, PRIVATE_FINDING_IDS, isCredentialPath, shellWrites, shellNetworks, shellReads, mcpToolTags, tagRulesFrom, evaluateTagRules, tagActionsFrom, evaluateTagActions } from "../data/tool-tags.js";

export const SESSION_TAGS_FILE = "session-tags.json";
export const SESSION_TAGS_LIMITS = Object.freeze({ sessions: 32, ttlMs: 24 * 3600 * 1000 });
const RANK = { allow: 1, ask: 2, deny: 3 };
const ordered = (set) => TAGS.filter((t) => set.has(t));

// This call's tags. findingIds: threat ids of the findings reported for content the call READ (stage
// "file": a Read, the files a shell command or an MCP file argument names). meta: an MCP tool's `_meta`.
// Returns { tags, inferred } — inferred ⊆ tags, the ones resting only on an MCP tool's name.
export function callTags({ tool = "", toolInput, cwd = "", home = os.homedir(), findingIds = [], meta } = {}) {
  const ti = toolInput && typeof toolInput === "object" ? toolInput : {};
  const tags = new Set(BUILTIN_TOOL_TAGS[tool] || []);
  const inferred = new Set();
  const priv = (findingIds || []).filter((id) => PRIVATE_FINDING_IDS.includes(id));
  try {
    if (tool === "Read" || tool === "NotebookRead") {
      if (isCredentialPath(ti.file_path || ti.notebook_path) || priv.length) tags.add("read-private");
    } else if (tool === "Bash" || tool === "PowerShell") {
      const cmd = typeof ti.command === "string" ? ti.command : "";
      const ps = tool === "PowerShell";
      const paths = extractReadPaths(cmd, { ...(ps ? { shell: "powershell" } : {}), env: process.env, home, insensitive: process.platform === "win32" });
      if (paths.length || shellReads(cmd)) tags.add("read");
      if (paths.some(isCredentialPath) || priv.includes(55) || (tags.has("read") && priv.length)) { tags.add("read"); tags.add("read-private"); }
      if (shellWrites(cmd)) tags.add("write");
      if (netDestinations(cmd, { ps }).length || urlDestinations(cmd).length || shellNetworks(cmd)) tags.add("network");
    } else if (tool.startsWith("mcp__")) {
      const m = mcpToolTags(tool, meta || (ti._meta && typeof ti._meta === "object" ? ti._meta : null));
      for (const t of m.declared) tags.add(t);
      for (const t of m.inferred) { tags.add(t); inferred.add(t); }
      if (priv.length) { tags.add("read"); tags.add("read-private"); inferred.delete("read"); inferred.delete("read-private"); }
    }
  } catch { /* a parse failure tags less, never throws */ }
  if (tags.has("read-private")) tags.add("read");
  return { tags: ordered(tags), inferred: ordered(inferred) };
}

// ---- the session record ----
const live = (rec, now) => rec && typeof rec === "object" && typeof rec.at === "number" && now - rec.at <= SESSION_TAGS_LIMITS.ttlMs && rec.at <= now + 60000;
const sessionKey = (sessionId) => (sessionId ? sessionKeyedHash(`tags:${sessionId}`) : null);
export function sessionTagsOf({ sessionId, now = Date.now() } = {}) {
  try {
    const sk = sessionKey(sessionId);
    const st = readSessionState(SESSION_TAGS_FILE);
    const rec = sk && st ? st[sk] : null;
    if (!live(rec, now)) return { tags: [], fired: [] };
    return { tags: (Array.isArray(rec.t) ? rec.t : []).filter((t) => TAGS.includes(t)), fired: Array.isArray(rec.f) ? rec.f.filter((x) => typeof x === "string") : [] };
  } catch { return { tags: [], fired: [] }; }
}
export function recordSessionTags({ sessionId, tags = [], fired = [], now = Date.now() } = {}) {
  try {
    const sk = sessionKey(sessionId);
    if (!sk || (!tags.length && !fired.length)) return;
    const st = readSessionState(SESSION_TAGS_FILE) || {};
    const prev = live(st[sk], now) ? st[sk] : { t: [], f: [] };
    // Nothing new and refreshed within the hour: no write (most calls of a session repeat its tags).
    if (prev.at && now - prev.at < 3600000 && tags.every((x) => (prev.t || []).includes(x)) && fired.every((x) => (prev.f || []).includes(x))) return;
    const t = ordered(new Set([...(prev.t || []), ...tags].filter((x) => TAGS.includes(x))));
    const f = [...new Set([...(prev.f || []), ...fired])].slice(-64);
    const out = {};
    for (const [k, v] of Object.entries(st)) if (k !== sk && live(v, now)) out[k] = v;
    out[sk] = { t, f, at: now };
    const keys = Object.keys(out).filter((k) => k !== sk).sort((a, b) => out[a].at - out[b].at);
    for (const k of keys.slice(0, Math.max(0, keys.length + 1 - SESSION_TAGS_LIMITS.sessions))) delete out[k];
    writeSessionState(SESSION_TAGS_FILE, out);
  } catch { /* best-effort; costs one observation */ }
}

// ---- the gate ----
//
// One verdict from tagActions and tagRules for a call whose tags are known. exceptedRules: rule ids a
// live exception covers for this call (a tag rule's id, or "tag:<tag>" for a tag action). Returns
//   { decision: "allow" | "ask" | "deny", reason, hits: [{ kind, id, action, tags, inferred }], rejected }
// rules: false evaluates the tag actions only (a caller with no session record, the Agent SDK).
// Content-free: tag names and rule ids only.
export function tagGate({ policy = null, system = null, tags = [], inferred = [], sessionTags = [], exceptedRules = [], rules = true } = {}) {
  const ex = new Set(exceptedRules);
  const ta = tagActionsFrom({ policy, system }), tr = tagRulesFrom({ policy, system });
  const inf = new Set(inferred);
  const hits = [];
  for (const a of evaluateTagActions(ta.actions, tags)) {
    if (ex.has(`tag:${a.tag}`)) continue;
    hits.push({ kind: "tagAction", id: `tag:${a.tag}`, action: a.action, tags: [a.tag], inferred: inf.has(a.tag) ? [a.tag] : [] });
  }
  for (const r of rules ? evaluateTagRules(tr.rules, sessionTags, tags) : []) {
    if (ex.has(r.id)) continue;
    hits.push({ kind: "tagRule", id: r.id, source: r.source, action: r.action, sessionHas: r.sessionHas, tags: r.matched, inferred: r.matched.filter((t) => inf.has(t)) });
  }
  const rejected = [...ta.rejected, ...tr.rejected];
  const blocks = hits.filter((h) => h.action === "block"), asks = hits.filter((h) => h.action === "ask");
  const decision = blocks.length ? "deny" : asks.length ? "ask" : "allow";
  return { decision, reason: decision === "allow" ? "" : gateReason(blocks.length ? blocks : asks), hits, rejected };
}
function gateReason(hits) {
  const acts = hits.filter((h) => h.kind === "tagAction"), rules = hits.filter((h) => h.kind === "tagRule");
  const parts = [];
  if (acts.length) {
    const ts = acts.map((h) => h.tags[0]);
    const many = ts.length > 1;
    const verb = acts[0].action === "block" ? (many ? "are blocked" : "is blocked") : (many ? "need sign-off" : "needs sign-off");
    parts.push(`${many ? "capabilities" : "capability"} ${ts.join(", ")} ${verb} by policy (tagActions)${acts.some((h) => h.inferred.length) ? ", inferred from the tool name" : ""}`);
  }
  for (const r of rules) parts.push(`tag rule "${r.id}": this session has ${r.sessionHas.join(" + ")} and this call has ${r.tags.join(" + ")}${r.inferred.length ? " (inferred from the tool name)" : ""}`);
  return parts.join("; ");
}

// Merge the gate into a verdict the caller already reached: the stricter one wins, never downgrading.
export function applyTagGate({ decision, reason, alternatives = [] }, gate) {
  if (!gate || RANK[gate.decision] <= RANK[decision]) return { decision, reason, alternatives, changed: false };
  return { decision: gate.decision, reason: gate.reason, alternatives: [], changed: true };
}

// The content-free alert body for one gate hit (the caller adds tool, ts and identity).
export function tagHitAlert(h) {
  const blocked = h.action === "block";
  return {
    threatId: 0,
    category: h.kind === "tagAction" ? "Capability tag action" : "Capability tag rule",
    riskLevel: blocked ? "Blocked" : h.action === "ask" ? "High" : "Medium",
    stage: "behavior",
    contentHash: `${h.kind}:${h.id}`,
    tagRule: { kind: h.kind, id: h.id, action: h.action, tags: h.tags, ...(h.sessionHas ? { sessionHas: h.sessionHas } : {}), ...(h.source ? { source: h.source } : {}), ...(h.inferred.length ? { inferred: h.inferred } : {}) }
  };
}
