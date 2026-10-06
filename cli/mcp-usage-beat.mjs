// MCP usage tally — the SENDER side of the console's proxy-vs-hook cross-check.
//
// Three surfaces can see an MCP tools/call: the agent hook's mcp__ branch (cli/moorai-hook.mjs, path
// "hook"), the stdio proxy (mcp-proxy/moorai-mcp-guard.mjs, path "proxy") and the HTTP MCP gateway
// (mcp-gateway/, path "gateway", host always "gateway"). Each counts its calls here, per UTC day / path /
// host / server label, and a COMPLETED day is posted once to
//
//   POST <serverUrl>/api/mcp-usage   (X-Install-Token, as /api/agent-posture)
//   { user, device, platform, actor?, day: "YYYY-MM-DD", path: "hook"|"proxy"|"gateway", host,
//     servers: [{ label, calls, tools?: [{ name, calls }], toolsTruncated?: true }] }
//
// so the console can compare what each path saw for the same server and day. Content-free: a server
// label (the same string alerts carry as mcpServer), a count, and — only on the paths in TOOL_PATHS
// (the gateway today; CONTRACT C4) — the MCP tool NAME as called with its own count. A tool name is
// accepted only if it matches TOOL_NAME_RE; arguments and results are never accepted by recordMcpCall,
// so neither can reach the file or the post. On the hook and proxy paths a tool name passed in is
// ignored, exactly as before. At most MAX_TOOLS tools per server go in a post (the busiest), with
// `toolsTruncated: true` when more were seen; at most MAX_TOOLS_STORED are kept per server and day.
//
// WHY COMPLETED DAYS ONLY. A day's tally is posted once, after the day is over (day < today, UTC), so
// each (device, day, path, host) is sent exactly once and the console never has to decide whether a
// second post replaces or adds to the first. The cost is that a day is reported the next time that
// path/host runs on a later day.
//
// Scheduling follows the coverage heartbeat (cli/moorai-hook.mjs maybePostureBeat): nothing is posted
// when the device is not enrolled; the day is stamped sent only after a 2xx; a failed post is retried
// after RETRY_MS, not on every call. The pending mark is an O_EXCL lock file per path/host holding its
// claim time, so several proxy processes (one per wrapped server, same host) post a day once between
// them. recordMcpCall is synchronous and fail-open; flushing never runs on a tool call's path — the
// hook hands it to a detached worker (scheduleMcpUsageFlush), the proxy runs it off its stdio path.
//
// Files (STATE_DIR = ~/.moorai, all 0600):
//   mcp-usage.json                          { v, days: { day: { "path|host": { label: calls } } },
//                                             tools: { day: { "path|host": { label: { c: { name: calls }, x?: 1 } } } } }
//   mcp-usage-<path>-<host>.sent.json       { day }  the last day posted for that path/host
//   mcp-usage-<path>-<host>.lock            claim time (ms); present = a post is pending or failed
//
//   node cli/mcp-usage-beat.mjs flush <path> <host> [claimed]   # the detached worker
import { readFileSync, writeFileSync, renameSync, mkdirSync, openSync, writeSync, closeSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import os from "node:os";
import { STATE_DIR } from "./state-dirs.mjs";
import { isEnrolled } from "../data/enforcement.js";
import { serverMode, serviceWho } from "./server-mode.mjs";
import { actorHash } from "./content-hash.mjs";
import { loadConfig } from "./config.mjs";

export const USAGE_PATHS = ["hook", "proxy", "gateway"];
export const USAGE_HOSTS = ["claude-code", "codex", "cursor", "gemini", "copilot", "claude-desktop", "vscode", "unknown"];
// The gateway is its own host: it is not inside any one MCP client (CONTRACT C4: host "gateway").
export const GATEWAY_HOST = "gateway";
// The paths whose tally carries per-tool counts. The hook and the proxy may join later (C4).
export const TOOL_PATHS = ["gateway"];
export const TOOL_NAME_RE = /^[A-Za-z0-9_.:\/-]{1,128}$/;
export const MAX_TOOLS = 64;
export const MAX_TOOLS_STORED = 256;
export const MAX_SERVERS = 64;
export const MAX_LABEL = 64;
export const MAX_DAYS = 14;
export const MAX_CALLS = 1e9;
export const RETRY_MS = 10 * 60 * 1000;
export const TALLY_FILE = "mcp-usage.json";

const SELF = fileURLToPath(import.meta.url);
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const dayOf = (now) => new Date(now).toISOString().slice(0, 10);
const keyOf = (path, host) => `${path}|${host}`;
const sentFile = (dir, path, host) => join(dir, `mcp-usage-${path}-${host}.sent.json`);
const lockFile = (dir, path, host) => join(dir, `mcp-usage-${path}-${host}.lock`);

export function usageHost(v) { return USAGE_HOSTS.includes(v) ? v : "unknown"; }
// The host a path reports: the gateway path always reports "gateway"; the others the client vocabulary.
export function hostForPath(path, v) { return path === "gateway" ? GATEWAY_HOST : usageHost(v); }
const validKey = (path, host) => USAGE_PATHS.includes(path) && (path === "gateway" ? host === GATEWAY_HOST : USAGE_HOSTS.includes(host));
export function validToolName(v) { return typeof v === "string" && TOOL_NAME_RE.test(v); }
export function sanitizeLabel(v) {
  return typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, MAX_LABEL) : "";
}

// Parse and re-bound whatever is on disk into null-prototype maps, so a label such as "__proto__" is
// a key like any other and a hand-edited or corrupt file can only shrink to valid entries.
export function readTally(dir = STATE_DIR) {
  const days = Object.create(null);
  const tools = Object.create(null);
  let raw;
  try { raw = JSON.parse(readFileSync(join(dir, TALLY_FILE), "utf8")); } catch { return { v: 1, days, tools }; }
  const src = raw && typeof raw.days === "object" && raw.days ? raw.days : {};
  for (const day of Object.keys(src)) {
    if (!DAY_RE.test(day) || !src[day] || typeof src[day] !== "object") continue;
    for (const key of Object.keys(src[day])) {
      const [path, host, extra] = key.split("|");
      if (extra !== undefined || !validKey(path, host)) continue;
      const m = src[day][key];
      if (!m || typeof m !== "object") continue;
      for (const label of Object.keys(m).slice(0, MAX_SERVERS)) {
        const n = m[label];
        if (!Number.isInteger(n) || n < 1 || sanitizeLabel(label) !== label || !label) continue;
        ((days[day] ||= Object.create(null))[key] ||= Object.create(null))[label] = Math.min(n, MAX_CALLS);
      }
    }
  }
  // Per-tool counts: only for a day/key/label the server tally holds, only on a TOOL_PATHS key, only
  // names that pass TOOL_NAME_RE, at most MAX_TOOLS_STORED per server.
  const tsrc = raw && typeof raw.tools === "object" && raw.tools ? raw.tools : {};
  for (const day of Object.keys(tsrc)) {
    if (!days[day] || !tsrc[day] || typeof tsrc[day] !== "object") continue;
    for (const key of Object.keys(tsrc[day])) {
      if (!days[day][key] || !TOOL_PATHS.includes(key.split("|")[0])) continue;
      const bySrv = tsrc[day][key];
      if (!bySrv || typeof bySrv !== "object") continue;
      for (const label of Object.keys(bySrv)) {
        if (days[day][key][label] === undefined) continue;
        const e = bySrv[label];
        if (!e || typeof e !== "object" || !e.c || typeof e.c !== "object") continue;
        const c = Object.create(null);
        let k = 0;
        for (const name of Object.keys(e.c)) {
          const n = e.c[name];
          if (!validToolName(name) || !Number.isInteger(n) || n < 1) continue;
          if (k >= MAX_TOOLS_STORED) break;
          c[name] = Math.min(n, MAX_CALLS); k++;
        }
        const entry = { c };
        if (e.x === 1 || Object.keys(e.c).length > MAX_TOOLS_STORED) entry.x = 1;
        ((tools[day] ||= Object.create(null))[key] ||= Object.create(null))[label] = entry;
      }
    }
  }
  return { v: 1, days, tools };
}

function writeAtomic(file, text) {
  const tmp = `${file}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  try { renameSync(tmp, file); } catch (e) { try { unlinkSync(tmp); } catch { /* gone */ } throw e; }
}

// One call seen. Synchronous, cheap, and never throws. Extra fields (arguments, results) are ignored by
// construction; `tool` (the MCP tool name) is counted only on a TOOL_PATHS path and only when it passes
// TOOL_NAME_RE — elsewhere it is ignored, as it always was. → true when the server call was counted.
export function recordMcpCall({ path, host, label, tool } = {}, { dir = STATE_DIR, now = Date.now() } = {}) {
  try {
    if (!USAGE_PATHS.includes(path)) return false;
    const l = sanitizeLabel(label);
    if (!l) return false;
    const key = keyOf(path, hostForPath(path, host));
    const day = dayOf(now);
    const tally = readTally(dir);
    const m = ((tally.days[day] ||= Object.create(null))[key] ||= Object.create(null));
    if (m[l] === undefined && Object.keys(m).length >= MAX_SERVERS) return false;
    m[l] = Math.min((m[l] || 0) + 1, MAX_CALLS);
    if (TOOL_PATHS.includes(path) && validToolName(tool)) {
      const e = (((tally.tools[day] ||= Object.create(null))[key] ||= Object.create(null))[l] ||= { c: Object.create(null) });
      if (e.c[tool] !== undefined || Object.keys(e.c).length < MAX_TOOLS_STORED) e.c[tool] = Math.min((e.c[tool] || 0) + 1, MAX_CALLS);
      else e.x = 1;
    }
    for (const old of Object.keys(tally.days).sort().reverse().slice(MAX_DAYS)) delete tally.days[old];
    for (const old of Object.keys(tally.tools)) if (!tally.days[old]) delete tally.tools[old];
    if (!Object.keys(tally.tools).length) delete tally.tools;
    mkdirSync(dir, { recursive: true });
    writeAtomic(join(dir, TALLY_FILE), JSON.stringify(tally));
    return true;
  } catch { return false; }
}

function readSent(dir, path, host) {
  try { const o = JSON.parse(readFileSync(sentFile(dir, path, host), "utf8")); return o && DAY_RE.test(o.day) ? o.day : ""; } catch { return ""; }
}

// The completed, not-yet-posted days for one path/host, oldest first, each with its servers ranked
// busiest first and capped at MAX_SERVERS. A server with per-tool counts carries `tools` (busiest
// first, then by name; at most MAX_TOOLS) and `toolsTruncated: true` when any were left out.
export function dueDays({ path, host }, { dir = STATE_DIR, now = Date.now() } = {}) {
  const key = keyOf(path, host);
  const today = dayOf(now);
  const sent = readSent(dir, path, host);
  const tally = readTally(dir);
  const out = [];
  for (const day of Object.keys(tally.days).sort()) {
    if (day >= today || (sent && day <= sent)) continue;
    const m = tally.days[day][key];
    if (!m) continue;
    const tm = tally.tools[day] && tally.tools[day][key];
    const servers = Object.keys(m).map((label) => ({ label, calls: m[label] }))
      .sort((a, b) => b.calls - a.calls || (a.label < b.label ? -1 : a.label > b.label ? 1 : 0))
      .slice(0, MAX_SERVERS)
      .map((s) => {
        const e = tm && tm[s.label];
        if (!e) return s;
        const all = Object.keys(e.c).map((name) => ({ name, calls: e.c[name] }))
          .sort((a, b) => b.calls - a.calls || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
        if (!all.length) return s;
        return { ...s, tools: all.slice(0, MAX_TOOLS), ...(all.length > MAX_TOOLS || e.x === 1 ? { toolsTruncated: true } : {}) };
      });
    if (servers.length) out.push({ day, servers });
  }
  return out;
}

function keysIn(dir) {
  const keys = new Set();
  for (const day of Object.values(readTally(dir).days)) for (const k of Object.keys(day)) keys.add(k);
  return [...keys].map((k) => { const [path, host] = k.split("|"); return { path, host }; });
}

// The pending mark. Taken with O_EXCL; a mark older than RETRY_MS (a failed post, or a worker that
// died) is taken over by renaming it aside first, so only one of several racing processes wins.
function claim(dir, path, host, now) {
  const f = lockFile(dir, path, host);
  const create = () => {
    try { mkdirSync(dir, { recursive: true }); const fd = openSync(f, "wx", 0o600); try { writeSync(fd, String(now)); } finally { closeSync(fd); } return true; } catch { return false; }
  };
  if (create()) return true;
  let at = 0;
  try { at = Number(readFileSync(f, "utf8")) || 0; } catch { return create(); }
  if (now - at < RETRY_MS && at <= now) return false;
  const aside = `${f}.${process.pid}.${Math.random().toString(36).slice(2)}`;
  try { renameSync(f, aside); } catch { return false; }
  try { unlinkSync(aside); } catch { /* gone */ }
  return create();
}
function release(dir, path, host) { try { unlinkSync(lockFile(dir, path, host)); } catch { /* gone */ } }

export function usageBody({ identity = {}, day, path, host, servers }) {
  return {
    user: identity.user, device: identity.device, platform: identity.platform,
    ...(identity.actor ? { actor: identity.actor } : {}),
    day, path, host, servers
  };
}

// Post every completed, unsent day for one path/host (or, with neither given, for every path/host in
// the tally). One body per day, oldest first; stops at the first failure and leaves the pending mark,
// so the next try is RETRY_MS away. Never throws.
export async function flushMcpUsage({ config, identity, path, host, dir = STATE_DIR, now = Date.now(), fetchImpl = fetch, claimed = false, timeoutMs = 5000 } = {}) {
  const res = { posted: [], failed: false, skipped: "" };
  try {
    if (!isEnrolled(config)) { if (claimed && path) release(dir, path, hostForPath(path, host)); res.skipped = "unenrolled"; return res; }
    const targets = path ? [{ path, host: hostForPath(path, host) }] : keysIn(dir);
    for (const t of targets) {
      if (!USAGE_PATHS.includes(t.path)) continue;
      const due = dueDays(t, { dir, now });
      if (!due.length) { if (claimed) release(dir, t.path, t.host); res.skipped ||= "nothing"; continue; }
      if (!claimed && !claim(dir, t.path, t.host, now)) { res.skipped ||= "pending"; continue; }
      let ok = true;
      for (const { day, servers } of due) {
        try {
          const r = await fetchImpl(`${config.serverUrl}/api/mcp-usage`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...(config.installToken ? { "X-Install-Token": config.installToken } : {}) },
            body: JSON.stringify(usageBody({ identity, day, path: t.path, host: t.host, servers })),
            signal: AbortSignal.timeout(timeoutMs)
          });
          ok = !!(r && r.ok);
        } catch { ok = false; }
        if (!ok) break;
        try { writeAtomic(sentFile(dir, t.path, t.host), JSON.stringify({ day })); } catch { /* re-sent next time */ }
        res.posted.push(day);
      }
      if (ok) release(dir, t.path, t.host); else res.failed = true;
    }
  } catch { res.failed = true; }
  return res;
}

// The hook's entry point, on its hot path: synchronous, a few small reads, and at most one detached
// worker per path/host per day (or per RETRY_MS after a failure). The claim is taken here, before the
// spawn, so a burst of tool calls cannot spawn a burst of workers.
export function scheduleMcpUsageFlush({ config, path, host, dir = STATE_DIR, now = Date.now() } = {}) {
  try {
    const h = hostForPath(path, host);
    if (!isEnrolled(config) || !USAGE_PATHS.includes(path)) return false;
    if (!dueDays({ path, host: h }, { dir, now }).length) return false;
    if (!claim(dir, path, h, now)) return false;
    spawn(process.execPath, [SELF, "flush", path, h, "claimed"], { detached: true, stdio: "ignore" }).unref();
    return true;
  } catch { return false; }
}

// The identity the usage post carries: exactly the hook's (cli/moorai-hook.mjs IDENTITY) — a workload
// name in server mode (serviceWho), user@host otherwise — so hook and proxy rows for one device pair.
export function usageIdentity() {
  const sm = serverMode();
  const who = sm.active ? serviceWho(sm) : { user: os.userInfo().username, device: os.hostname() };
  return { user: who.user, device: who.device, platform: os.platform(), actor: actorHash(who.user, who.device) };
}

if (process.argv[1] === SELF && process.argv[2] === "flush") {
  try {
    await flushMcpUsage({ config: loadConfig(), identity: usageIdentity(), path: process.argv[3], host: process.argv[4], claimed: process.argv[5] === "claimed" });
  } catch { /* evidence, never enforcement */ }
  process.exit(0);
}
