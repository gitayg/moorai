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
//                         sizes, alert flags. 32 sessions (least recently active evicted), 24 h TTL.
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
import { classifyEvent, assessSessionRisk, sessionRiskConfig } from "../data/session-risk.js";
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

// One tool call into the session-risk state. `identity`/`text`/`findings`/`stage` are what the hook's
// behaviour log already has for the call. Returns { alerts: [alert body], escalate: null | { kind,
// reason }, score }. Escalation is returned in mode "ask", and when the device coaches (where the hook
// turns it into coach text, never a prompt).
export function sessionRiskStep({ policy, sessionId, event, tool, identity, text, findings, stage, coach = false, now = Date.now() }) {
  const none = { alerts: [], escalate: null, score: 0 };
  try {
    const cfg = sessionRiskConfig(policy);
    if (cfg.mode === "off") return none;
    const sk = h(`sr:${sessionId || ""}`);
    if (!sk) return none;
    const ev = classifyEvent({ event, tool: tool === "PowerShell" ? "PowerShell" : tool, identity, textLen: typeof text === "string" ? text.length : 0, findings, stage });
    ev.hostKeys = ev.hosts.map((x) => h(`host:${x}`));
    ev.readKey = ev.read && identity ? h(`path:${identity}`) : null;
    const run = coach && cfg.mode === "report" ? { ...cfg, mode: "ask" } : cfg;
    const r = assessSessionRisk(readSessionState(SESSION_RISK_FILE), sk, ev, now, run);
    if (r.dirty) writeSessionState(SESSION_RISK_FILE, r.state);
    const alerts = r.alerts.map((a) => ({ ...a.alert, sessionRisk: { ...a.alert.sessionRisk, mode: cfg.mode } }));
    return { alerts, escalate: r.escalate, score: r.score };
  } catch { return none; }
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
