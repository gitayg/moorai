// On-device state and keyed hashing for the two per-session signals: session-level escalation
// (data/session-risk.js) and the runaway circuit breaker (data/circuit-breaker.js).
//
// WHAT IS STORED, AND WHERE (~/.moorai, every file mode 0600):
//   session.key           32 random bytes (hex), created on first use. The HMAC key for every hash
//                         below. Device-local rather than the tenant key (cli/content-hash.mjs): these
//                         hashes never leave the device, and an unenrolled device has no tenant key, so
//                         without its own key every unenrolled session would collapse into one.
//   session-risk.json     per hashed session id: score, taint window, flagged steps (call number,
//                         time, class bits), hashed hosts and read paths with times, small-transfer
//                         sizes, alert flags; the origin-taint window and its source (source kind, app
//                         name, keyed host hash) and hashed paths that inherit an outside origin.
//                         32 sessions (least recently active evicted), 24 h TTL. Plus `oc`, the
//                         file-origin cache (cli/file-origin.mjs): hashed (dev, ino, mtime, size) ->
//                         { source, app, keyed host hash } or null, 512 entries, 24 h.
//   circuit-breaker.json  per hashed session + sub-agent id: the last 64 calls as (time, hash of tool +
//                         arguments, hash of the result), call times of the last minute, pause state.
//                         32 sessions, 24 h TTL.
// NEVER STORED: a command, a path, a host, an argument or a byte of output — only keyed hashes.
//
// Fail-open: a missing, oversized or unparsable file reads as empty, every write error is swallowed, and
// every exported step catches its own errors and returns "nothing to do". Writes are atomic (temp file +
// rename); parallel hook calls can lose one another's update, which costs one observation.
//
// WHAT THIS DOES NOT DEFEND: the agent runs as the same user. It can read session.key and delete or edit
// either state file — clearing its own taint or its own loop history. Same trust boundary as every
// other ~/.moorai file.
import { createHmac, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, renameSync, mkdirSync, statSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { win32, posix } from "node:path";
import os from "node:os";
import { classifyEvent, assessSessionRisk, sessionRiskConfig, cleanOriginCache, sessionOriginMarks } from "../data/session-risk.js";
import { fileOrigin } from "./file-origin.mjs";
import { assessCall, recordOutcome, circuitConfig } from "../data/circuit-breaker.js";

export const SESSION_KEY_FILE = "session.key";
export const SESSION_RISK_FILE = "session-risk.json";
export const CIRCUIT_FILE = "circuit-breaker.json";
const MAX_BYTES = 1 << 20;

let _key;
function key() {
  if (_key) return _key;
  const p = join(STATE_DIR, SESSION_KEY_FILE);
  try { const k = readFileSync(p, "utf8").trim(); if (/^[0-9a-f]{64}$/.test(k)) return (_key = Buffer.from(k, "hex")); } catch { /* absent */ }
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    writeFileSync(p, randomBytes(32).toString("hex"), { mode: 0o600, flag: "wx" });
  } catch { /* a parallel hook created it first, or the directory is unwritable */ }
  try { const k = readFileSync(p, "utf8").trim(); if (/^[0-9a-f]{64}$/.test(k)) return (_key = Buffer.from(k, "hex")); } catch { /* unusable */ }
  return null;
}
function h(s, len = 16) { const k = key(); return k ? createHmac("sha256", k).update(String(s)).digest("hex").slice(0, len) : null; }
// The same device-keyed hash, for other per-session records (cli/fetch-exec-state.mjs).
export const sessionKeyedHash = h;

export function readSessionState(name) {
  try {
    const p = join(STATE_DIR, name);
    if (statSync(p).size > MAX_BYTES) return null;
    const o = JSON.parse(readFileSync(p, "utf8"));
    return o && typeof o === "object" && !Array.isArray(o) ? o : null;
  } catch { return null; }
}
export function writeSessionState(name, obj) {
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    const p = join(STATE_DIR, name);
    const tmp = `${p}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(obj), { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, p);
  } catch { /* best-effort; never affects the decision */ }
}

// Stable text for a tool input: object keys sorted, capped, so the same call hashes the same.
function canon(v, depth = 0) {
  if (depth > 8) return "…";
  if (Array.isArray(v)) return `[${v.slice(0, 256).map((x) => canon(x, depth + 1)).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().slice(0, 256).map((k) => `${JSON.stringify(k)}:${canon(v[k], depth + 1)}`).join(",")}}`;
  return JSON.stringify(v === undefined ? null : v);
}
const callSig = (tool, input) => h(`call:${tool}\n${canon(input || {}).slice(0, 65536)}`);
const circuitKey = (sessionId, agentId) => h(`cb:${sessionId || ""}|${agentId || ""}`);

// ---- origin taint: which paths of this call came from outside ----
//
// A path as one comparable string: absolute (against the agent's cwd), `~` expanded, `/` separators, lowercased
// on Windows and macOS (case-insensitive by default).
function normAbs(p, { cwd = "", home = os.homedir(), platform = process.platform } = {}) {
  let s = String(p || "");
  if (!s || s.length > 4096 || /[\0\r\n]/.test(s)) return "";
  if (s === "~" || s.startsWith("~/") || s.startsWith("~\\")) s = home + s.slice(1);
  const abs = platform === "win32" ? win32.resolve(cwd || home, s) : posix.resolve(cwd || home, s);
  const out = abs.replace(/\\/g, "/");
  return platform === "win32" || platform === "darwin" ? out.toLowerCase() : out;
}
// The keyed hashes a path is marked under: itself and every ancestor directory.
function markKeys(n) {
  const keys = [];
  let p = n;
  for (let i = 0; i < 64 && p; i++) {
    keys.push(h(`om:${p}`));
    const j = p.lastIndexOf("/");
    if (j <= 0) { if (p !== "/") keys.push(h("om:/")); break; }
    p = p.slice(0, j);
  }
  return keys;
}
const SPAWN_BUDGET_MS = 1500;
function absPath(p, cwd, platform, home = os.homedir()) {
  const s = String(p).replace(/^~(?=[\/\\]|$)/, home);
  return platform === "win32" ? win32.resolve(cwd || home, s) : posix.resolve(cwd || home, s);
}
// fileOrigin over a state's cache: get/set by keyed hash of the file identity.
function cacheOver(oc, now) {
  return { get: (k) => { const e = oc[h(`oc:${k}`)]; return e ? e.m : undefined; }, set: (k, m) => { oc[h(`oc:${k}`)] = { m: m ? { s: m.s, a: m.a ?? null, h: m.h ?? null } : null, t: now }; } };
}

// One path's origin, from PreToolUse or PostToolUse, with the persistent cache in session-risk.json. Returns
// fileOrigin's shape (null | { source, app, hostHash }). For callers outside sessionRiskStep (a reader that
// wants to know before the agent sees the file). Never throws.
export function originOf(path, { cwd = "", now = Date.now(), platform = process.platform } = {}) {
  try {
    const raw = readSessionState(SESSION_RISK_FILE) || { v: 1, sessions: {} };
    raw.oc = cleanOriginCache(raw.oc, now);
    const before = JSON.stringify(raw.oc);
    const o = typeof path === "string" && path ? fileOrigin(absPath(path, cwd, platform), { cache: cacheOver(raw.oc, now), platform, deadline: performance.now() + SPAWN_BUDGET_MS }) : null;
    if (JSON.stringify(raw.oc) !== before) writeSessionState(SESSION_RISK_FILE, raw);
    return o;
  } catch { return null; }
}

// One tool call into the session-risk state. `identity`/`text`/`findings`/`stage` are what the hook's
// behaviour log already has for the call. `admin` is the root-owned admin binding. `origin` (PreToolUse only)
// holds what this call does with files, for origin taint (data/origin-taint.js):
//   reads    paths it reads (the Read path, the Bash read paths, an MCP read tool's files)
//   exec     paths it runs (data/net-exec.js fetchExecFacts)
//   extract  [{ archive, dest }] archives it unpacks (data/net-exec.js unpackFacts)
//   gates    gated action classes other than "outbound" and "exec-outside"
//   strip    the call removes an origin mark; stripTargets: the literal paths it names
//   cwd      the agent's working directory, for relative paths
// Returns { alerts: [alert body], escalate: null | { kind, reason }, origin: null | { level, action, reason, … },
// score }. Escalation is returned in mode "ask", and when the device coaches (where the hook turns it into coach
// text, never a prompt). `origin` is returned whenever a gated action falls inside an origin-taint window; the
// hook applies its level ("notify": the alert only).
export function sessionRiskStep({ policy, admin = null, sessionId, event, tool, identity, text, findings, stage, coach = false, origin: oin = null, now = Date.now(), platform = process.platform }) {
  const none = { alerts: [], escalate: null, score: 0 };
  try {
    const cfg = sessionRiskConfig(policy, { admin });
    const originOn = cfg.originTaint !== "off" || Object.values(cfg.originGates).some((v) => v !== "off");
    // mode "off": the content-based signals are off and nothing they count accrues. Origin taint acts only on
    // PreToolUse, so with mode "off" a PostToolUse call (or origin taint off as well) does nothing at all.
    const off = cfg.mode === "off";
    if (off && (!originOn || event === "PostToolUse")) return none;
    const sk = h(`sr:${sessionId || ""}`);
    if (!sk) return none;
    const ev = classifyEvent({ event, tool: tool === "PowerShell" ? "PowerShell" : tool, identity, textLen: typeof text === "string" ? text.length : 0, findings, stage });
    ev.hostKeys = ev.hosts.map((x) => h(`host:${x}`));
    ev.readKey = ev.read && identity ? h(`path:${identity}`) : null;
    if (off) { ev.weight = 0; ev.taint = false; ev.taintIds = []; ev.read = false; }
    const raw = readSessionState(SESSION_RISK_FILE) || { v: 1, sessions: {} };
    if (originOn && oin && typeof oin === "object" && event !== "PostToolUse") Object.assign(ev, originFacts(raw, sk, oin, now, platform));
    const run = coach && cfg.mode === "report" ? { ...cfg, mode: "ask" } : { ...cfg };
    if (coach && run.originTaint === "notify") run.originTaint = "ask"; // an unenrolled device has no console: coach text instead
    const r = assessSessionRisk(raw, sk, ev, now, run);
    if (r.dirty) writeSessionState(SESSION_RISK_FILE, r.state);
    const alerts = r.alerts.map((a) => ({ ...a.alert, sessionRisk: { ...a.alert.sessionRisk, mode: cfg.mode } }));
    return { alerts, escalate: off ? null : r.escalate, origin: r.origin, score: off ? 0 : r.score };
  } catch { return none; }
}

// The origin half of a call's event: { origin, originGates, originMarks, originStrip }. Mutates raw.oc (the cache).
function originFacts(raw, sk, oin, now, platform) {
  const home = os.homedir();
  const cwd = typeof oin.cwd === "string" ? oin.cwd : "";
  raw.oc = cleanOriginCache(raw.oc, now);
  const cache = cacheOver(raw.oc, now);
  const deadline = performance.now() + SPAWN_BUDGET_MS;
  const marks = sessionOriginMarks(raw, sk, now);
  const list = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string" && x).slice(0, 16) : []);
  const absOf = (p) => absPath(p, cwd, platform);
  // The file's own mark, else a mark this session recorded on it or a directory above it.
  const originAt = (p) => {
    const o = fileOrigin(absOf(p), { cache, platform, home, deadline });
    if (o) return o;
    const n = normAbs(p, { cwd, home, platform });
    if (!n) return null;
    for (const k of markKeys(n)) if (k && marks[k]) { const m = marks[k]; return { source: m.source, app: m.app, hostHash: m.hostHash }; }
    return null;
  };
  const out = { origin: null, originGates: list(oin.gates), originMarks: [], originStrip: !!oin.strip };
  for (const p of list(oin.reads)) { const o = originAt(p); if (o) { out.origin = o; break; } }
  for (const p of list(oin.exec)) {
    const o = originAt(p);
    if (o) { out.origin = out.origin || o; out.originGates.push("exec-outside"); break; }
  }
  for (const x of Array.isArray(oin.extract) ? oin.extract.slice(0, 8) : []) {
    if (!x || typeof x.archive !== "string") continue;
    const o = originAt(x.archive);
    if (!o) continue;
    out.origin = out.origin || o;
    const n = typeof x.dest === "string" ? normAbs(x.dest, { cwd, home, platform }) : "";
    if (n) out.originMarks.push({ key: h(`om:${n}`), src: o });
  }
  if (out.originStrip) for (const p of list(oin.stripTargets)) { const n = normAbs(p, { cwd, home, platform }); if (n) out.originMarks.push({ key: h(`om:${n}`), src: { source: "mark-removed", app: null, hostHash: null } }); }
  return out;
}

// One PreToolUse call into the circuit breaker. Returns { alerts: [alert body], deny: null | { reason } }.
// `deny` is set in mode "deny" while the session is tripped, and (coach text, once per trip kind) on the
// tripping call of a coached device.
export function circuitStep({ policy, sessionId, agentId, tool, toolInput, coach = false, now = Date.now() }) {
  const none = { alerts: [], deny: null };
  try {
    const cfg = circuitConfig(policy);
    if (cfg.mode === "off") return none;
    const sk = circuitKey(sessionId, agentId), sig = callSig(tool, toolInput);
    if (!sk || !sig) return none;
    const r = assessCall(readSessionState(CIRCUIT_FILE), sk, sig, now, cfg);
    if (r.dirty) writeSessionState(CIRCUIT_FILE, r.state);
    const deny = r.deny ? { reason: r.deny.reason } : coach && r.trip && r.alerts.length ? { reason: `runaway-agent circuit breaker: ${r.why}` } : null;
    return { alerts: r.alerts.map((a) => a.alert), deny };
  } catch { return none; }
}

// A call's result (PostToolUse) or failure (PostToolUseFailure), so a repeat whose result changes counts
// as progress. Only a keyed hash of the result is kept.
export function circuitOutcome({ policy, sessionId, agentId, tool, toolInput, responseText, failed = false, now = Date.now() }) {
  try {
    if (circuitConfig(policy).mode === "off") return;
    const sk = circuitKey(sessionId, agentId), sig = callSig(tool, toolInput);
    const out = failed ? "F" : h(`out:${String(responseText ?? "").slice(0, 65536)}`, 12);
    if (!sk || !sig || !out) return;
    const state = readSessionState(CIRCUIT_FILE);
    if (!state) return;
    const r = recordOutcome(state, sk, sig, out, now);
    if (r.dirty) writeSessionState(CIRCUIT_FILE, r.state);
  } catch { /* best-effort */ }
}
