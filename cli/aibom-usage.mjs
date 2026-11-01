// Installed vs actually used — a collector for the AIBOM (cli/moorai-aibom.mjs). The AIBOM says what is
// CONFIGURED on this device; this joins each entry to the on-device records of what was USED, so a
// configured-but-idle MCP server, model or agent host reads as a removal candidate.
//
// Every AIBOM component gets three fields:
//   lastUsed     "YYYY-MM-DD" (UTC) of the newest use on record, or null
//   calls30d     calls in the last USAGE_WINDOW_DAYS days (today included), or null when MoorAI does not
//                count uses of that kind of asset
//   usageStatus  "used"            a use is on record (lastUsed set)
//                "never-seen"      a MoorAI surface watches this entry (MCP) or records this kind (models,
//                                  agent hosts) and no use names it
//                "not-observable"  nothing MoorAI runs or records covers this entry on this device
// Not observable is never reported as 0 or as never seen.
//
// Sources (all local, all content-free: names, counts and times; nothing here is posted anywhere):
//   MCP servers  Observable per entry, by the surfaces that watch it (watchedBy): "hook:<host>" when the
//                MoorAI hook is registered in the host whose config declares the server (the host's hook
//                file as moorai-doctor reads it; Claude Code also managed settings or the moorai plugin),
//                "guard" when the entry launches through the stdio guard (moorai-mcp-guard.mjs), "gateway"
//                when its URL is the gateway on loopback at its default port 8848. No watcher → not
//                observable, whatever the records hold. Registration only: a stale or broken install still
//                counts as watched (moorai-doctor reports those).
//                ~/.moorai/destinations.jsonl  one row per MCP call the hook saw (kind "mcp", the server
//                                             name, a timestamp); 90 days, at most 2000 rows of any kind
//                ~/.moorai/mcp-usage.json      per-day call counts per server from the hook, the stdio guard
//                                             and the HTTP gateway (cli/mcp-usage-beat.mjs); 14 days
//                One call can be counted by more than one surface (the hook and the guard both see a
//                Claude Code call to a guarded server), so for each server and UTC day the count is the
//                LARGEST any one surface recorded, never their sum: calls30d is a floor. Server names
//                match the way Claude Code builds its mcp__<server>__ tool names (characters outside
//                [A-Za-z0-9_-] become "_"), case-insensitively; two configs naming the same server share
//                its record.
//   models       ~/.moorai/token-usage-transcript.json  hourly request counts per model id from Claude
//                Code's own transcripts (cli/transcript-usage.mjs; enrolled devices; 40 days). Only the
//                model Claude Code is configured for is matched: the exact id, the id plus a date or
//                "-latest" ("claude-opus-4-5" matches "claude-opus-4-5-20251101"; "claude-opus-4" does
//                not), or a family alias (opus, sonnet,
//                haiku; opusplan = opus or sonnet; a "[1m]" suffix ignored). Other models, local ones
//                included, are not observable: the model proxy keeps its counts in memory and sends them
//                to the console.
//   agent hosts  the host's own session store, newest mtime (cli/agent-posture.mjs lastActive): lastUsed
//                only, calls30d null. Hosts without a known session store (aider, kiro) are not observable.
//   editor extensions, skills: not observable.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { readTally } from "./mcp-usage-beat.mjs";
import { TRANSCRIPT_STATE } from "./transcript-usage.mjs";
import { lastActive, SESSION_DIRS } from "./agent-posture.mjs";
import { hostTable, readJson, ourSurface, pluginInstall, readManagedSettings, checkManaged } from "./doctor-hosts.mjs";
import { unwrapGuard } from "./mcp-package/resolve.mjs";
import { DEFAULT_PORT as GATEWAY_PORT, isLoopbackHost } from "../mcp-gateway/config.mjs";

export const USAGE_WINDOW_DAYS = 30;
export const USAGE_STATUSES = ["used", "never-seen", "not-observable"];
const DAY_MS = 86400000;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const dayOf = (v) => { const s = typeof v === "string" ? v.slice(0, 10) : ""; return DAY_RE.test(s) ? s : null; };
const windowStart = (now) => new Date(now - (USAGE_WINDOW_DAYS - 1) * DAY_MS).toISOString().slice(0, 10);
const NOT_OBSERVABLE = Object.freeze({ lastUsed: null, calls30d: null, usageStatus: "not-observable" });

// Claude Code's server-name normalisation for mcp__<server>__<tool>, then case-folded.
export function mcpKey(name) { return String(name || "").replace(/[^A-Za-z0-9_-]/g, "_").toLowerCase(); }

// AIBOM MCP scope (the config the server was read from) → the hook host id that runs inside it.
export const SCOPE_HOST = { claude: "claude-code", cursor: "cursor", antigravity: "antigravity", windsurf: "windsurf", kiro: "kiro", cline: "cline" };

// The hosts MoorAI's hook is registered in, read the way moorai-doctor reads them (cli/doctor-hosts.mjs)
// without running the installers: MoorAI entries in the host's hook file; for Claude Code also managed
// settings or an installed moorai plugin. → Set of host ids.
export function hookedHosts({ home, env = process.env, managedSources } = {}) {
  const out = new Set();
  let managed = { managedHooks: null, managedPlugins: [] };
  try { managed = checkManaged(managedSources ?? readManagedSettings()); } catch { /* unreadable: no managed hook */ }
  for (const h of hostTable(home, env)) {
    try {
      const { data: raw } = h.read ? h.read() : readJson(h.file, { comments: h.comments });
      const data = raw && h.view ? h.view(raw) : raw;
      let on = !!data && Object.keys(ourSurface(data, h.ours)).length > 0;
      if (!on && h.id === "claude-code") on = !!managed.managedHooks || !!(pluginInstall(data, { home, env, managedPlugins: managed.managedPlugins || [] }) || {}).installPath;
      if (on) out.add(h.id);
    } catch { /* unreadable host file: not watched */ }
  }
  return out;
}

// The surfaces an MCP config entry itself routes through: the stdio guard (cli/mcp-package/resolve.mjs
// unwrapGuard finds moorai-mcp-guard.mjs in the launch argv) and the gateway (loopback, default port).
export function configSurfaces(cfg = {}) {
  const out = [];
  const argv = [cfg.command, ...(Array.isArray(cfg.args) ? cfg.args : [])].filter((x) => x != null).map(String);
  if (argv.length && unwrapGuard(argv) !== argv) out.push("guard");
  if (typeof cfg.url === "string") {
    try { const u = new URL(cfg.url); if (isLoopbackHost(u.hostname) && Number(u.port) === GATEWAY_PORT) out.push("gateway"); } catch { /* not a URL */ }
  }
  return out;
}

// The AIBOM agent names → the agent-posture host ids whose session stores say when they were last used.
export const AGENT_HOST = { claude: "claude-code", codex: "codex", antigravity: "antigravity", windsurf: "windsurf", cline: "cline" };

function readJsonl(p) {
  let t;
  try { t = readFileSync(p, "utf8"); } catch { return []; }
  const out = [];
  for (const l of t.split("\n")) { if (!l.trim()) continue; try { const o = JSON.parse(l); if (o && typeof o === "object") out.push(o); } catch { /* torn line */ } }
  return out;
}

// The raw local records, read once. Missing or unreadable files read as absent, never as an error.
export function readUsageSources({ stateDir = STATE_DIR } = {}) {
  let transcript = null;
  try {
    const o = JSON.parse(readFileSync(join(stateDir, TRANSCRIPT_STATE), "utf8"));
    if (o && o.v === 1 && Array.isArray(o.buckets)) transcript = o.buckets;
  } catch { transcript = null; }
  return { destinations: readJsonl(join(stateDir, "destinations.jsonl")), tally: readTally(stateDir), transcript };
}

// → { recorded, since, byServer: Map<mcpKey, Map<day, calls>> } where calls is the largest count any
// one surface recorded for that server on that day.
export function mcpUsageIndex({ destinations = [], tally = { days: {} } } = {}) {
  const per = new Map(); // mcpKey → Map<day, Map<surface, calls>>
  const bump = (name, day, surface, n) => {
    const k = mcpKey(name);
    if (!k || !day) return;
    if (!per.has(k)) per.set(k, new Map());
    const d = per.get(k);
    if (!d.has(day)) d.set(day, new Map());
    d.get(day).set(surface, (d.get(day).get(surface) || 0) + n);
  };
  let since = null;
  const seenDay = (day) => { if (day && (!since || day < since)) since = day; };
  for (const r of destinations) {
    const day = dayOf(r && r.ts);
    seenDay(day);
    if (r.kind === "mcp" && r.name) bump(r.name, day, "destinations", 1);
  }
  for (const day of Object.keys(tally.days || {})) {
    if (!DAY_RE.test(day)) continue;
    seenDay(day);
    for (const key of Object.keys(tally.days[day])) {
      const path = key.split("|")[0]; // hosts on one path are different clients: their calls add up
      for (const [label, n] of Object.entries(tally.days[day][key])) if (Number.isInteger(n) && n > 0) bump(label, day, `tally:${path}`, n);
    }
  }
  const byServer = new Map();
  for (const [k, days] of per) {
    const m = new Map();
    for (const [day, surfaces] of days) m.set(day, Math.max(...surfaces.values()));
    byServer.set(k, m);
  }
  return { recorded: since != null, since, byServer };
}

function fromDays(days, now) {
  if (!days || !days.size) return { lastUsed: null, calls30d: 0, usageStatus: "never-seen" };
  const from = windowStart(now);
  let last = null, calls = 0;
  for (const [day, n] of days) { if (!last || day > last) last = day; if (day >= from) calls += n; }
  return { lastUsed: last, calls30d: calls, usageStatus: "used" };
}

// Claude Code model setting → a predicate over the model ids its transcripts carry.
const ALIASES = { opus: ["opus"], sonnet: ["sonnet"], haiku: ["haiku"], opusplan: ["opus", "sonnet"] };
export function modelMatcher(configured) {
  const c = String(configured || "").replace(/\[1m\]$/i, "").trim().toLowerCase();
  if (!c) return null;
  const fams = ALIASES[c];
  if (fams) return (id) => fams.some((f) => id.startsWith(`claude-${f}`) || id.includes(`-${f}-`));
  return (id) => id === c || (id.startsWith(c) && /^-(\d{8}|latest)$/.test(id.slice(c.length)));
}

// → { observable, since, buckets }
export function modelUsageIndex({ transcript = null } = {}) {
  if (!Array.isArray(transcript)) return { observable: false, since: null, buckets: [] };
  const buckets = transcript.filter((b) => b && dayOf(b.hour) && typeof b.model === "string" && Number.isInteger(b.requests) && b.requests > 0);
  let since = null;
  for (const b of buckets) { const d = dayOf(b.hour); if (!since || d < since) since = d; }
  return { observable: true, since, buckets };
}

function modelUse(name, idx, now) {
  const match = modelMatcher(name);
  if (!match) return { ...NOT_OBSERVABLE };
  const days = new Map();
  for (const b of idx.buckets) if (match(b.model.toLowerCase())) { const d = dayOf(b.hour); days.set(d, (days.get(d) || 0) + b.requests); }
  return fromDays(days, now);
}

function agentUse(name, { home, env }) {
  const host = AGENT_HOST[name];
  if (!host || !SESSION_DIRS[host]) return { ...NOT_OBSERVABLE };
  const last = lastActive(host, { home, env });
  return { lastUsed: last ? last.slice(0, 10) : null, calls30d: null, usageStatus: last ? "used" : "never-seen" };
}

// Adds lastUsed / calls30d / usageStatus to every component and MCP server entry of an AIBOM (in place)
// and returns the evidence summary: per kind, whether it is observable, the oldest day on record, and
// what was read. `sources` defaults to the local records; `home`/`env` feed the agent session stores and
// the hook registrations; `hooks` (a Set of host ids) replaces the registration read. An MCP entry
// ({ name, scope, watchedBy: configSurfaces(cfg) }) gets watchedBy with its hook host prepended.
export function annotateUsage(bom, { sources = readUsageSources(), now = Date.now(), home, env = process.env, hooks } = {}) {
  const mcp = mcpUsageIndex(sources);
  const models = modelUsageIndex(sources);
  const hooked = hooks || hookedHosts({ home, env });
  const mcpUse = (s) => {
    const host = SCOPE_HOST[s.scope];
    const own = (Array.isArray(s.watchedBy) ? s.watchedBy : []).filter((w) => w === "guard" || w === "gateway");
    s.watchedBy = [...(host && hooked.has(host) ? [`hook:${host}`] : []), ...own];
    return s.watchedBy.length ? fromDays(mcp.byServer.get(mcpKey(s.name)), now) : { ...NOT_OBSERVABLE };
  };
  // Only the model Claude Code is configured for is in the transcripts.
  const claudeModels = new Set((bom.providers || []).filter((p) => p.agent === "claude" && p.model).map((p) => p.model));
  for (const c of bom.components || []) {
    let u;
    if (c.type === "mcp-server") u = mcpUse(c);
    else if (c.type === "model") u = models.observable && !c.local && claudeModels.has(c.name) ? modelUse(c.name, models, now) : { ...NOT_OBSERVABLE };
    else if (c.type === "agent") u = agentUse(c.name, { home, env });
    else u = { ...NOT_OBSERVABLE };
    Object.assign(c, u);
  }
  for (const s of bom.mcpServers || []) Object.assign(s, mcpUse(s));
  return {
    windowDays: USAGE_WINDOW_DAYS,
    mcpServers: { recorded: mcp.recorded, since: mcp.since, hookedHosts: [...hooked].sort(), sources: ["destinations.jsonl", "mcp-usage.json"], observableWhen: "a hook host, the stdio guard or the gateway watches the entry", countRule: "per server and UTC day, the largest count one surface recorded" },
    models: { observable: models.observable, since: models.since, sources: ["token-usage-transcript.json"], scope: "the model Claude Code is configured for" },
    agents: { observable: true, sources: ["host session stores (mtime only)"], hosts: Object.values(AGENT_HOST), calls: "not counted" },
    notObservable: ["editor-extension", "skill", "local and non-Claude-Code models"]
  };
}

// Entries configured but not used in the last `days` days. A never-seen entry is a candidate only when
// the evidence for its kind reaches back `days` days; otherwise it is `undecided` (MoorAI has not watched
// long enough to say). Not-observable entries are never candidates.
export function unusedCandidates(bom, days, evidence, now = Date.now()) {
  const cut = new Date(now - days * DAY_MS).toISOString().slice(0, 10);
  const sinceOf = (type) => (type === "mcp-server" ? evidence.mcpServers.since : type === "model" ? evidence.models.since : null);
  const candidates = [], undecided = [];
  // One row per type + name, over its observable entries only: same-named MCP entries share one record,
  // so their use is the same; scopes and watchers are those of the entries that are watched.
  const groups = new Map();
  for (const c of bom.components || []) {
    if (c.usageStatus === "not-observable") continue;
    const k = `${c.type}|${c.name}`;
    if (!groups.has(k)) groups.set(k, { c, scopes: [], watched: new Set() });
    const g = groups.get(k);
    if (c.scope && !g.scopes.includes(c.scope)) g.scopes.push(c.scope);
    for (const w of c.watchedBy || []) g.watched.add(w);
  }
  for (const { c, scopes, watched } of groups.values()) {
    const isMcp = c.type === "mcp-server";
    const row = { type: c.type, name: c.name, ...(isMcp ? { scopes, watchedBy: [...watched] } : {}), lastUsed: c.lastUsed, calls30d: c.calls30d };
    const by = isMcp ? ` (watched by ${[...watched].join(", ")})` : "";
    if (c.lastUsed && c.lastUsed >= cut) continue;
    if (c.lastUsed) { candidates.push({ ...row, reason: `configured; last used ${c.lastUsed}, nothing since${by}` }); continue; }
    const since = sinceOf(c.type);
    if (c.type === "agent") candidates.push({ ...row, reason: "configured; its session store holds no session" });
    else if (since && since <= cut) candidates.push({ ...row, reason: `configured; no call on record since ${since}${by}` });
    else undecided.push({ ...row, reason: (since ? `no call on record, but the record only starts ${since}` : "no call on record, and the record is empty") + by });
  }
  const order = { "mcp-server": 0, model: 1, agent: 2 };
  const by = (a, b) => (order[a.type] ?? 9) - (order[b.type] ?? 9) || String(a.lastUsed || "").localeCompare(String(b.lastUsed || "")) || a.name.localeCompare(b.name);
  return { unusedDays: days, candidates: candidates.sort(by), undecided: undecided.sort(by) };
}

// Sort key for --sort used|unused: not-observable always last; then calls30d, then lastUsed.
export function byUse(dir) {
  const rank = (c) => (c.usageStatus === "not-observable" ? 1 : 0);
  return (a, b) => rank(a) - rank(b)
    || dir * (((b.calls30d ?? -1) - (a.calls30d ?? -1)) || String(b.lastUsed || "").localeCompare(String(a.lastUsed || "")))
    || String(a.name).localeCompare(String(b.name));
}
