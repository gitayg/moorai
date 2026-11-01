// MCP data harvesting: reads from ONE MCP server, counted per session (SAF-T1801, T1803, T1804).
//
// The session-risk mass read (data/session-risk.js) counts distinct local files. A harvest through MCP reads
// no local file: it pages through a server's records (get_customer 1..n, list_rows with a cursor, a query per
// table) or its resources (resources/read). This module counts those reads per session and per server:
//
//   reads   distinct read calls to one server inside `windowMin` minutes. A read call is a resources/read, or
//           a tools/call whose class (cli/mcp-tool-class.mjs: override, annotation, name) is read or
//           detokenize, or an unknown-class tool whose name says it queries (query, sql, select, fetch,
//           export, dump, download, retrieve, lookup). Distinct = a different keyed hash of the tool and its
//           arguments (or the resource URI), so a repeated call is one read and every page of a cursor walk
//           is another.
//   bytes   the size of the results those read calls returned from that server inside the window.
//   dump    a read call whose arguments ask the server for a bulk export: COPY ... TO, SELECT ... INTO
//           OUTFILE / DUMPFILE, BACKUP DATABASE, pg_dump, mysqldump, mongodump, mongoexport, sqlite .dump.
//
// policy.mcpHarvest = { mode, reads, bytes, windowMin }, signed policy only:
//   mode "report" (default)   an alert the first time a server crosses a budget (or a dump call is seen) in a
//                             window; no decision changes.
//   mode "ask" | "block"      also every read call to that server while it is over budget, and a dump call,
//                             takes ask / deny (the stdio guard has no approver: an ask is forwarded and recorded).
//   mode "off"                nothing is counted.
// Defaults: 100 distinct reads or 5 MiB of results from one server in 30 minutes. Not measured against real
// traffic; an organisation that enforces should set its own.
//
// Pure: keys in (the caller hashes the session, the server and each read with a device key), counts out. No
// tool name, argument, URI or byte of a result is stored or returned.
import { classifyMcpTool, nameTokens } from "./mcp-tool-class.mjs";
import { canonicalJson } from "./canonical-json.mjs";

export const MCP_HARVEST_DEFAULTS = Object.freeze({ mode: "report", reads: 100, bytes: 5 * 1024 * 1024, windowMin: 30 });
export const HARVEST_MODES = ["off", "report", "ask", "block"];
export const HARVEST_THREAT = 59;
const MAX_KEYS = 64;
const posNum = (v, d) => (Number.isFinite(v) && v > 0 ? v : d);

export function mcpHarvestConfig(policy) {
  const p = policy && policy.mcpHarvest && typeof policy.mcpHarvest === "object" && !Array.isArray(policy.mcpHarvest) ? policy.mcpHarvest : {};
  return {
    mode: HARVEST_MODES.includes(p.mode) ? p.mode : MCP_HARVEST_DEFAULTS.mode,
    reads: Math.floor(posNum(p.reads, MCP_HARVEST_DEFAULTS.reads)),
    bytes: Math.floor(posNum(p.bytes, MCP_HARVEST_DEFAULTS.bytes)),
    windowMin: posNum(p.windowMin, MCP_HARVEST_DEFAULTS.windowMin)
  };
}

const QUERY = new Set(["query", "queries", "sql", "select", "fetch", "export", "dump", "download", "retrieve", "lookup"]);
// Is this MCP call a read? `method` "resources/read" always is; a tools/call is classed by name, the admin's
// override and (on the guard) the tool's annotation.
export function isMcpRead(policy, { method = "tools/call", server = "", tool = "", annotation = null } = {}) {
  if (method === "resources/read") return true;
  if (method !== "tools/call" || !tool) return false;
  const { toolClass } = classifyMcpTool(policy, { server, tool, annotation });
  if (toolClass === "read" || toolClass === "detokenize") return true;
  return toolClass === "unknown" && nameTokens(tool.startsWith("mcp__") ? tool.split("__").slice(2).join("__") : tool).some((t) => QUERY.has(t));
}

// The text a read call is keyed on (the caller hashes it): server, tool (or resources/read) and the canonical
// arguments (or the URI).
export function readIdentity(server, tool, args) {
  let a;
  try { a = canonicalJson(args == null ? {} : args).slice(0, 65536); } catch { a = ""; }
  return `${server}\n${tool}\n${a}`;
}

const DUMP = /\bcopy\b[\s\S]{0,400}?\bto\s+(?:'|"|stdout\b|program\b)|\binto\s+(?:outfile|dumpfile)\b|\bbackup\s+database\b|(?<![\w-])(?:pg_dump|pg_dumpall|mysqldump|mongodump|mongoexport)(?![\w-])|(?:^|\s)\.dump\b/i;
// The string leaves of a call's arguments ask for a bulk export. Bounded: 256 leaves, 16 KB each.
export function dumpShaped(args) {
  const stack = [[args, 0]];
  let n = 0;
  while (stack.length && n < 256) {
    const [v, d] = stack.pop();
    if (typeof v === "string") { n++; if (DUMP.test(v.slice(0, 16384))) return true; continue; }
    if (!v || typeof v !== "object" || d >= 6) continue;
    for (const x of Array.isArray(v) ? v : Object.values(v)) stack.push([x, d + 1]);
  }
  return false;
}

const num = (v) => typeof v === "number" && Number.isFinite(v);
const obj = (v) => v && typeof v === "object" && !Array.isArray(v);

function clean(state, now, win, keep) {
  const out = { v: 1, s: {} };
  const ss = obj(state) && obj(state.s) ? state.s : {};
  for (const [k, e] of Object.entries(ss)) {
    if (!obj(e) || !num(e.last) || now - e.last > win) continue;
    const r = {};
    if (obj(e.r)) for (const [rk, t] of Object.entries(e.r)) if (num(t) && now - t <= win) r[rk] = t;
    const ks = Object.keys(r);
    if (ks.length > keep) for (const x of ks.sort((a, b) => r[a] - r[b]).slice(0, ks.length - keep)) delete r[x];
    const b = Array.isArray(e.b) ? e.b.filter((x) => Array.isArray(x) && x.length === 2 && num(x[0]) && num(x[1]) && now - x[0] <= win).slice(-1024) : [];
    const al = {};
    if (obj(e.al)) for (const [ak, t] of Object.entries(e.al)) if (num(t) && now - t <= win) al[ak] = t;
    out.s[k] = { last: e.last, r, b, al };
  }
  const ks = Object.keys(out.s);
  if (ks.length > MAX_KEYS) for (const x of ks.sort((a, b) => out.s[a].last - out.s[b].last).slice(0, ks.length - MAX_KEYS)) delete out.s[x];
  return out;
}

// One observation for one (session, server) key.
//   ev.readKey  keyed hash of a read call (PreToolUse / the request); counts toward `reads`
//   ev.bytes    size of a read call's result (PostToolUse / the response)
//   ev.dump     the read call is dump-shaped
//   ev.pre      this is the call itself (a level can apply), not its result
// → { state, over: [kind], fresh: [kind], reads, bytes, level: "allow" | "ask" | "block" }
//   over   the budgets this key is over now (and "dump" for a dump call); fresh: the ones not yet alerted in
//   this window (the caller alerts them). level: the verdict for this call under mode ask / block.
export function assessHarvest(state, key, ev, now, cfg = mcpHarvestConfig(null)) {
  const win = cfg.windowMin * 60000;
  const st = clean(state, now, win, Math.min(4096, Math.max(512, cfg.reads + 1)));
  const none = { state: st, over: [], fresh: [], reads: 0, bytes: 0, level: "allow" };
  if (cfg.mode === "off" || typeof key !== "string" || !key) return none;
  const e = ev && typeof ev === "object" ? ev : {};
  const s = st.s[key] || (st.s[key] = { last: now, r: {}, b: [], al: {} });
  s.last = now;
  if (typeof e.readKey === "string" && e.readKey) s.r[e.readKey] = now;
  if (num(e.bytes) && e.bytes > 0) { s.b.push([now, Math.round(e.bytes)]); s.b = s.b.slice(-1024); }
  const reads = Object.keys(s.r).length;
  const bytes = s.b.reduce((t, x) => t + x[1], 0);
  const over = [];
  if (reads >= cfg.reads) over.push("reads");
  if (bytes >= cfg.bytes) over.push("bytes");
  if (e.pre && e.dump) over.push("dump");
  const fresh = over.filter((k) => !(k in s.al));
  for (const k of fresh) s.al[k] = now;
  // Only a read call (the request) can be held; a result is past holding, and a non-read call is not judged.
  const held = e.pre && typeof e.readKey === "string" && e.readKey && over.length > 0;
  const level = held && (cfg.mode === "ask" || cfg.mode === "block") ? cfg.mode : "allow";
  return { state: st, over, fresh, reads, bytes, level };
}

export const HARVEST_REASON = {
  reads: "many distinct reads from one MCP server in this session",
  bytes: "a large volume of results from one MCP server in this session",
  dump: "a bulk database export through an MCP tool"
};
export function harvestReason(over) { return `MCP data harvesting — ${over.map((k) => HARVEST_REASON[k]).join(", ")}`; }

// The content-free alert for one budget crossed. `decision`: what the call got (allow, ask, deny, coach).
export function harvestAlert(kind, { server, tool, reads, bytes, cfg, decision }) {
  return {
    threatId: HARVEST_THREAT,
    category: kind === "dump" ? "MCP: bulk database export through a tool" : "MCP: data harvesting from one server",
    riskLevel: decision === "deny" ? "Blocked" : "High",
    stage: "behavior", tool, decision, reasonCode: "BEHAVIOR_SIGNAL",
    ...(server ? { mcpServer: server } : {}),
    contentHash: `mcp-harvest:${kind}`,
    signature: { kind, reads, bytes, windowMin: cfg.windowMin, thresholds: { reads: cfg.reads, bytes: cfg.bytes }, mode: cfg.mode }
  };
}
