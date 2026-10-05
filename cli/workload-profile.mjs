// Declared workload / repo profile: the baseline an operator writes down for an agent — the tools, MCP
// servers and destination hosts it is expected to use — and the drift from it on each tool call. The
// learned baseline (data/learned-drift.js) answers "has this agent done THAT before"; this answers "did
// the operator say this workload may do THAT", the way a container's behaviour is compared with its image.
//
// POLICY SHAPE (frozen, CONTRACT C3):
//   workloadProfiles: [{ id, match: { serviceId?, repo? }, tools?, mcpServers?, hosts?, action? }]
//   * match needs at least one key; both keys present means both must match; first matching profile wins.
//   * tools / mcpServers / hosts are allow-lists with `*` globs. An OMITTED list does not constrain. A
//     present but EMPTY list allows nothing (the operator declared "none").
//   * action "report" (default) posts a PROFILE_DRIFT alert; "block" denies. An unenrolled device never
//     blocks (the caller passes coach and gets a coach-only result).
//
// WHERE A PROFILE MAY COME FROM. Only the verified console policy and the root-owned machine-wide config
// (/etc/moorai/config.json, read by the caller with readRootOwned). Never a file in the repository, a
// settings-file `env` block, ~/.moorai/config.json or any environment variable: a repository must not be
// able to declare its own baseline, for the same reason a settings file cannot plant a trust anchor
// (cli/server-mode.mjs). profilesFrom() takes exactly those two inputs and nothing else.
//
// MATCHING.
//   serviceId — exact match against the server-mode workload name (cli/server-mode.mjs serviceId:
//               MOORAI_SERVICE_ID or github:<repo>:<workflow>:<job>). A laptop has none.
//   repo      — the normalised git remote of the session cwd, read from .git/config by drift-state.mjs
//               repoIdentity (no git process; at most 64 directory levels and 64 KB of config), cached per
//               cwd. https / ssh / scp spellings collapse to github:owner/name, gitlab:group/name,
//               bitbucket:owner/name or <host>:<path>. The remote is in the agent's write scope (it can
//               edit .git/config), so a repo match is a convenience scope, not an identity: serviceId is
//               the one an operator should rely on for a block.
//
// DRIFT KINDS and their items, named as the hook already names them:
//   tool       the tool name (Bash, Read, mcp__github__create_issue) — in clear, as every alert carries it
//   mcpServer  the MCP server label (the second segment of mcp__<server>__<tool>) — in clear, as today
//   host       destination hosts from data/model-endpoints.js extractHosts over the same text the
//              destination map reads (Bash/PowerShell command, WebFetch url, MCP arguments) — host only,
//              never a path or query, as the destination map reports it. Loopback is always in profile.
//
// Pure: every input (policy, system config, serviceId, cwd, tool call) and every lookup (repo discovery,
// host extraction) is injectable. evaluateProfile() never throws: any error is fail-open (allow, no
// alert) and comes back as `error` so a caller can count it.
import { extractHosts as defaultExtractHosts } from "../data/model-endpoints.js";
import { normalizeRemote } from "../data/learned-drift.js";
import { serverOf } from "../data/agent-behavior.js";
import { repoIdentity as defaultRepoIdentity } from "./drift-state.mjs";

export const PROFILE_DRIFT = "PROFILE_DRIFT";
export const DRIFT_KINDS = Object.freeze(["tool", "mcpServer", "host"]);
export const PROFILE_ACTIONS = Object.freeze(["report", "block"]);
export const DRIFT_CATEGORY = "Workload profile drift";
export const REJECT_CATEGORY = "Workload profile ignored (malformed)";
const LIST_KEYS = { tools: "tool", mcpServers: "mcpServer", hosts: "host" };
const KNOWN_KEYS = new Set(["id", "match", "tools", "mcpServers", "hosts", "action", "description", "name"]);
const MATCH_KEYS = new Set(["serviceId", "repo"]);
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const TOOL_RE = /^[A-Za-z0-9_*.:-]{1,256}$/;
const HOST_RE = /^(\*|(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*\.?)$/;
const MAX_PROFILES = 256, MAX_ENTRIES = 512, MAX_ID = 128;
const SHELL_TOOLS = new Set(["Bash", "PowerShell"]);
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
const FORGES = { "github.com": "github", "gitlab.com": "gitlab", "bitbucket.org": "bitbucket" };

// ---- repo identity ----

// A remote URL, or an operator's `github:owner/name` / `host:path` spelling, in one canonical form. ""
// when there is no host (a local-path remote cannot be matched).
export function normalizeRepo(value) {
  const s = String(value || "").trim();
  if (!s) return "";
  const short = s.match(/^(github|gitlab|bitbucket):(?!\/\/)(.+)$/i);
  if (short) {
    const path = short[2].replace(/\\/g, "/").replace(/\/+$/, "").replace(/\.git$/i, "").replace(/^\/+/, "");
    return path ? `${short[1].toLowerCase()}:${path.toLowerCase()}` : "";
  }
  const n = normalizeRemote(s);
  if (!n) return "";
  // normalizeRemote returns "<host>/<path>" for a remote with a host and a bare path otherwise.
  const hasHost = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) || /^(?:[^@\s/]+@)?[A-Za-z0-9.-]+:(?!\/\/)/.test(s) && !/^[A-Za-z]:[\\/]/.test(s);
  if (!hasHost) return "";
  const slash = n.indexOf("/");
  if (slash <= 0) return "";
  const host = n.slice(0, slash), path = n.slice(slash + 1);
  if (!path) return "";
  return `${FORGES[host] || host}:${path}`;
}

const REPO_CACHE = new Map();
const REPO_CACHE_MAX = 32;
// The normalised remote of the repository containing cwd, cached per cwd for the life of the process
// (one hook invocation, or a long-lived SDK service / sidecar).
export function repoOf(cwd, { repoIdentity = defaultRepoIdentity, cache = REPO_CACHE } = {}) {
  if (typeof cwd !== "string" || !cwd) return "";
  if (cache.has(cwd)) return cache.get(cwd);
  const id = repoIdentity(cwd);
  const repo = id && id.remote ? normalizeRepo(id.remote) : "";
  if (cache.size >= REPO_CACHE_MAX) cache.delete(cache.keys().next().value);
  cache.set(cwd, repo);
  return repo;
}
export function _resetRepoCacheForTests() { REPO_CACHE.clear(); }

// ---- validation ----

function globRe(pattern) {
  return new RegExp(`^${pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
}
function list(raw, key) {
  if (!Array.isArray(raw)) return { error: `${key} is not a list` };
  if (raw.length > MAX_ENTRIES) return { error: `${key} has more than ${MAX_ENTRIES} entries` };
  const out = [];
  for (const e of raw) {
    if (typeof e !== "string" || !e.trim()) return { error: `${key} has a non-string or empty entry` };
    const v = key === "hosts" ? e.trim().toLowerCase().replace(/\.$/, "") : e.trim();
    if (key === "hosts" ? !HOST_RE.test(v) : !TOOL_RE.test(v)) return { error: `${key} entry is not a ${key === "hosts" ? "host name or *.suffix" : "name or * glob"}` };
    out.push(v);
  }
  return { value: out };
}

// One profile → { profile } (normalised, globs compiled) or { error } (the reason; never the value).
export function validateProfile(p) {
  if (!p || typeof p !== "object" || Array.isArray(p)) return { error: "not an object" };
  if (typeof p.id !== "string" || !ID_RE.test(p.id)) return { error: "id missing or not a short slug" };
  const unknown = Object.keys(p).filter((k) => !KNOWN_KEYS.has(k));
  if (unknown.length) return { error: "unknown key" };
  const m = p.match;
  if (!m || typeof m !== "object" || Array.isArray(m)) return { error: "match missing" };
  // An unknown match key would be ignored and so widen the match beyond what the operator wrote.
  if (Object.keys(m).some((k) => !MATCH_KEYS.has(k))) return { error: "unknown match key" };
  const match = {};
  if (m.serviceId !== undefined) {
    if (typeof m.serviceId !== "string" || !m.serviceId.trim() || m.serviceId.length > MAX_ID) return { error: "match.serviceId is not a workload name" };
    match.serviceId = m.serviceId.trim();
  }
  if (m.repo !== undefined) {
    const r = typeof m.repo === "string" ? normalizeRepo(m.repo) : "";
    if (!r) return { error: "match.repo is not a remote (github:owner/name, gitlab:group/name or host:path)" };
    match.repo = r;
  }
  if (!Object.keys(match).length) return { error: "match has no key" };
  const action = p.action === undefined ? "report" : p.action;
  if (!PROFILE_ACTIONS.includes(action)) return { error: "action is not report or block" };
  const profile = { id: p.id, match, action, allow: {} };
  for (const [key, kind] of Object.entries(LIST_KEYS)) {
    if (p[key] === undefined) continue;
    const l = list(p[key], key);
    if (l.error) return { error: l.error };
    profile.allow[kind] = { entries: l.value, res: l.value.map(globRe) };
  }
  return { profile };
}

// The profiles in force, from the only two trusted sources, in order: the verified console policy, then
// the root-owned machine-wide config. Malformed and duplicate-id entries are dropped and listed.
export function profilesFrom({ policy = null, system = null } = {}) {
  const profiles = [], rejected = [], ids = new Set();
  const sources = [["policy", policy], ["system", system]];
  for (const [source, doc] of sources) {
    const raw = doc && typeof doc === "object" ? doc.workloadProfiles : undefined;
    if (raw === undefined || raw === null) continue;
    if (!Array.isArray(raw)) { rejected.push({ source, index: -1, reason: "workloadProfiles is not a list" }); continue; }
    raw.slice(0, MAX_PROFILES).forEach((p, index) => {
      const v = validateProfile(p);
      const id = p && typeof p.id === "string" && ID_RE.test(p.id) ? p.id : undefined;
      if (v.error) { rejected.push({ source, index, ...(id ? { id } : {}), reason: v.error }); return; }
      if (ids.has(v.profile.id)) { rejected.push({ source, index, id, reason: "duplicate id" }); return; }
      ids.add(v.profile.id);
      profiles.push({ ...v.profile, source });
    });
    if (raw.length > MAX_PROFILES) rejected.push({ source, index: MAX_PROFILES, reason: `more than ${MAX_PROFILES} profiles` });
  }
  return { profiles, rejected };
}

// Validated once per (policy, system) object pair: a long-lived SDK service or sidecar keeps one policy
// object between refreshes, so it compiles the globs once rather than per call.
const PROFILE_CACHE = new WeakMap();
const NO_DOC = {};
function cachedProfiles(policy, system) {
  const k1 = policy && typeof policy === "object" ? policy : NO_DOC, k2 = system && typeof system === "object" ? system : NO_DOC;
  let inner = PROFILE_CACHE.get(k1);
  if (!inner) PROFILE_CACHE.set(k1, (inner = new WeakMap()));
  let r = inner.get(k2);
  if (!r) inner.set(k2, (r = profilesFrom({ policy, system })));
  return r;
}

// ---- matching and drift ----

// First match wins. `repo` is a thunk so the .git/config read happens only when a profile asks for it.
export function matchProfile(profiles, { serviceId = "", repo = () => "" } = {}) {
  let repoVal;
  const getRepo = () => (repoVal === undefined ? (repoVal = typeof repo === "function" ? repo() : repo || "") : repoVal);
  for (const p of profiles || []) {
    if (p.match.serviceId !== undefined && p.match.serviceId !== serviceId) continue;
    if (p.match.repo !== undefined && (!getRepo() || p.match.repo !== getRepo())) continue;
    return p;
  }
  return null;
}

// What one tool call uses: its name, its MCP server, and the hosts it points at.
export function profileSubject(tool, toolInput, { extractHosts = defaultExtractHosts } = {}) {
  const t = String(tool || "");
  const ti = toolInput && typeof toolInput === "object" ? toolInput : {};
  const mcpServer = t.startsWith("mcp__") ? serverOf(t) : "";
  const text = SHELL_TOOLS.has(t) ? ti.command : t === "WebFetch" ? ti.url : mcpServer ? JSON.stringify(ti) : "";
  const hosts = typeof text === "string" && text ? [...new Set(extractHosts(text))] : [];
  return { tool: t, mcpServer, hosts };
}

const inList = (a, v) => a.res.some((re) => re.test(v));
function hostIn(a, h) {
  if (LOOPBACK.has(h)) return true;
  return a.entries.some((e) => e === "*" || e === h || (e.startsWith("*.") && h.endsWith(e.slice(1))));
}
// [{ kind, item }] — one per out-of-profile value, in kind order.
export function driftOf(profile, subject) {
  const out = [];
  const a = profile.allow;
  if (a.tool && subject.tool && !inList(a.tool, subject.tool)) out.push({ kind: "tool", item: subject.tool });
  if (a.mcpServer && subject.mcpServer && !inList(a.mcpServer, subject.mcpServer)) out.push({ kind: "mcpServer", item: subject.mcpServer });
  if (a.host) for (const h of subject.hosts) if (!hostIn(a.host, h)) out.push({ kind: "host", item: h });
  return out;
}

// The reason a host sees on a block: the profile id and the kinds only, never the item or any content.
export function blockReason(profileId, kinds) {
  return `outside the declared workload profile "${profileId}" (${kinds.join(", ")} not in the profile)`;
}

// Content-free alerts, one per drift kind (the first item of that kind names it). The caller adds tool,
// ts and identity. decision: what the host was told for this drift ("deny" | "allow" | "coach").
export function driftAlerts(profile, drifts, { decision }) {
  const seen = new Set(), out = [];
  for (const d of drifts) {
    if (seen.has(d.kind)) continue;
    seen.add(d.kind);
    const blocked = decision === "deny";
    out.push({
      threatId: 0,
      category: DRIFT_CATEGORY,
      riskLevel: blocked ? "Blocked" : "Medium",
      stage: "behavior",
      decision,
      reasonCode: PROFILE_DRIFT,
      ...(decision === "coach" ? { enforcement: "LIMITED" } : {}),
      driftKind: d.kind,
      driftItem: d.item,
      profileId: profile.id,
      profileAction: profile.action,
      profileSource: profile.source,
      contentHash: `profile-drift:${profile.id}:${d.kind}:${d.item}`
    });
  }
  return out;
}

// One tool call against the profiles in force. Never throws.
//   policy, system   the verified policy and the root-owned machine-wide config (parsed) — nothing else
//   serviceId        the server-mode workload name, "" on a laptop
//   cwd              the session cwd (repo match)
//   tool, toolInput  the call
//   coach            unenrolled device: a block becomes a coach-only report
//   deps             { repoIdentity, extractHosts, cache } for tests
// Returns { decision: "allow"|"deny", reason, profile, drifts, alerts, rejected, error? }.
export function evaluateProfile({ policy = null, system = null, serviceId = "", cwd = "", tool = "", toolInput = {}, coach = false, deps = {} } = {}) {
  const none = { decision: "allow", reason: "", profile: null, drifts: [], alerts: [], rejected: [] };
  try {
    const hasAny = (d) => d && typeof d === "object" && d.workloadProfiles !== undefined && d.workloadProfiles !== null;
    if (!hasAny(policy) && !hasAny(system)) return none;
    const { profiles, rejected } = cachedProfiles(policy, system);
    const profile = matchProfile(profiles, { serviceId: typeof serviceId === "string" ? serviceId : "", repo: () => repoOf(cwd, deps) });
    if (!profile) return { ...none, rejected };
    const drifts = driftOf(profile, profileSubject(tool, toolInput, deps));
    if (!drifts.length) return { ...none, profile, rejected };
    const kinds = [...new Set(drifts.map((d) => d.kind))];
    const block = profile.action === "block";
    const decision = block && !coach ? "deny" : "allow";
    const alerts = driftAlerts(profile, drifts, { decision: block ? (coach ? "coach" : "deny") : "allow" });
    return { decision, reason: block ? blockReason(profile.id, kinds) : "", profile, drifts, kinds, alerts, rejected, ...(block && coach ? { coach: blockReason(profile.id, kinds) } : {}) };
  } catch (e) {
    return { ...none, error: String((e && e.message) || e).slice(0, 200) };
  }
}

// The content-free alert for malformed profiles: where, which index and id, and why — never a value.
export function rejectedAlert(rejected) {
  if (!rejected || !rejected.length) return null;
  const items = rejected.slice(0, 16).map((r) => ({ source: r.source, index: r.index, ...(r.id ? { id: r.id } : {}), reason: r.reason }));
  return { threatId: 0, category: REJECT_CATEGORY, riskLevel: "Medium", stage: "policy", reasonCode: "OBSERVATION_ONLY", profileRejected: items, contentHash: `profile-rejected:${items.map((r) => `${r.source}.${r.index}`).join(",")}` };
}
