// Operator stop, fast path: how an administrator's stop reaches a running agent in under a second instead of on the
// hook's next policy fetch (cli/session-stop.mjs: at most once a minute, and only when the agent calls a tool).
//
// A console that serves the stop channel names it in the signed policy (`stopChannel`). While it does, the hook
// keeps one stop watcher per device user running (cli/stop-watch.mjs, spawned detached, one at a time by its lock
// file) and records which agent process runs each session (once per session). The watcher holds a long-poll to the
// console's stop channel; when a stop is created or lifted the console answers it at once with the actor's SIGNED stop
// document. The watcher verifies it with the device's policy anchor or pin, writes it to STOP_FILE (removes the file
// when it holds no stop), and sends SIGTERM to the agent process of every live session the stop names (macOS and
// Linux), so an idle agent ends too.
//
// TRUST MODEL. STOP_FILE, the watcher, its lock and the session records are in the user's own state directory and
// run as the user, so the governed agent can delete, rewrite or kill every one of them. They can therefore only ever
// ADD stops, never remove one:
//   * the hook reads STOP_FILE on every PreToolUse and UserPromptSubmit and applies its stops only when the document's
//     signature verifies under the same keys as the policy (anchor, else pin), names this tenant and this actor, and
//     was issued after the policy being enforced; it never removes or shortens a stop the verified policy carries;
//   * a stop is lifted only by the signed policy: a document older than the policy is ignored, so a stale file left
//     by a dead watcher stops applying at the next policy fetch;
//   * the document is signed in its own form ("moorai-stops|v1|..."), so it can never be read as a policy (which
//     would be a downgrade) and a policy can never be read as one.
// What a same-user process CAN do is take the fast path away: kill the watcher or delete the file. The stop then
// reaches the agent the old way, on the first hook call after the 60 s policy cache (with that path's own limits,
// README "Operator stop"). The root-owned helper (moorai-guardd) is where a tamper-proof channel belongs.
import { readFileSync, writeFileSync, renameSync, mkdirSync, statSync, existsSync, rmSync } from "node:fs";
import { createHash, verify as cryptoVerify } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "./canonical-json.mjs";
import { STATE_DIR } from "./state-dirs.mjs";
import { agentStops, findAgentPid } from "./session-stop.mjs";

export const STOP_DOC_VERSION = 1;
export const STOP_CHANNEL_PATH = "/api/agents/stop-channel";
export const STOP_FILE = "stop-channel.json";
export const WATCH_LOCK = "stop-watch.lock";
export const SESSIONS_DIR = "stop-sessions";
// The watcher touches its lock at least every HEARTBEAT_MS; a lock older than STALE_MS is a dead watcher.
export const HEARTBEAT_MS = 10000;
export const STALE_MS = 45000;
export const WATCH_SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "stop-watch.mjs");
const ACTOR_RE = /^h2:[0-9a-f]{16,64}$/;
const SESSION_RE = /^h2:[0-9a-f]{16}$/;

const sha256 = (s) => createHash("sha256").update(s).digest("hex");
// The signed bytes: a wire format shared with the console (server/stop-channel.js), pinned literally in both tests.
export const stopDocCanonical = (s) => `moorai-stops|v${s.v}|${s.tenant}|${s.iat}|${s.digest}`;
export function stopDocDigest(doc) {
  const { sig: _sig, ...body } = doc || {};
  return sha256(canonicalJson(body));
}

// → { ok: true, stops, signed } or { ok: false, status }. keys: the device's policy keys (anchor, else pin). With no
// key the document is taken unverified (signed: false), exactly as an unpinned device takes its policy: it can only
// add stops. The watcher signals a process only for a signed document.
export function verifyStopDoc(doc, { keys = [], tenant = "", actor = "" } = {}) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return { ok: false, status: "malformed" };
  if (doc.v !== STOP_DOC_VERSION || typeof doc.sig !== "string" || !doc.sig || !Number.isFinite(Date.parse(doc.iat)) || !Array.isArray(doc.agentStops)) return { ok: false, status: "malformed" };
  if (String(doc.tenant) !== String(tenant)) return { ok: false, status: "mismatch" };
  if (!ACTOR_RE.test(String(actor)) || doc.actor !== actor) return { ok: false, status: "actor" };
  let signed = false;
  if (keys.length) {
    const msg = Buffer.from(stopDocCanonical({ v: STOP_DOC_VERSION, tenant: String(doc.tenant), iat: String(doc.iat), digest: stopDocDigest(doc) }));
    let sig;
    try { sig = Buffer.from(doc.sig, "base64"); } catch { return { ok: false, status: "malformed" }; }
    if (!keys.some((k) => { try { return cryptoVerify(null, msg, k, sig); } catch { return false; } })) return { ok: false, status: "untrusted" };
    signed = true;
  }
  return { ok: true, stops: agentStops({ agentStops: doc.agentStops }), signed };
}

const iatMs = (p) => { const t = Date.parse(p && p.policySig && p.policySig.iat); return Number.isFinite(t) ? t : -Infinity; };

// The stops a verified stop document adds to the policy being enforced ([] in the normal state: no file).
export function fastStops({ policy, keys = [], tenant = "", actor = "", stateDir = STATE_DIR } = {}) {
  let doc;
  try { doc = JSON.parse(readFileSync(join(stateDir, STOP_FILE), "utf8")); } catch { return []; }
  const v = verifyStopDoc(doc, { keys, tenant, actor });
  if (!v.ok || Date.parse(doc.iat) <= iatMs(policy)) return [];
  return v.stops;
}

// The policy with extra stops added in front (a stop already in the policy is not repeated). Never removes one.
export function withFastStops(policy, extra) {
  const own = Array.isArray(policy && policy.agentStops) ? policy.agentStops : [];
  const ids = new Set(own.map((s) => s && s.id));
  return { ...(policy || {}), agentStops: [...extra.filter((s) => !ids.has(s.id)), ...own] };
}

// Write (or, with no stop, remove) the stop file. raw: the console's bytes as received.
export function writeStopFile(raw, hasStops, stateDir = STATE_DIR) {
  const p = join(stateDir, STOP_FILE);
  if (!hasStops) { rmSync(p, { force: true }); return; }
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, raw, { mode: 0o600 });
  renameSync(tmp, p);
}

export function watcherFresh(stateDir = STATE_DIR, now = Date.now()) {
  try { return now - statSync(join(stateDir, WATCH_LOCK)).mtimeMs < STALE_MS; } catch { return false; }
}

const startWatcher = () => spawn(process.execPath, [WATCH_SCRIPT], { detached: true, stdio: "ignore", env: process.env, windowsHide: true }).unref();
// Start the watcher when the verified policy names the stop channel, the device is enrolled and no watcher touched the
// lock lately. → true when one was started.
export function ensureWatcher({ policy, enrolled, stateDir = STATE_DIR, start = startWatcher, now = Date.now() } = {}) {
  if (!policy || !policy.stopChannel || !enrolled || watcherFresh(stateDir, now)) return false;
  try { start(); return true; } catch { return false; }
}

// Start time and name of a process, so a pid the session record names is signalled only while it is still that
// process (never a reused pid). "" when it cannot be read.
export function processIdentity(pid, { platform = process.platform, run = (a) => execFileSync("/bin/ps", a, { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"] }), read = (p) => readFileSync(p, "utf8") } = {}) {
  if (!(pid > 1)) return "";
  try {
    if (platform === "linux") {
      const st = read(`/proc/${pid}/stat`);
      const close = st.lastIndexOf(")");
      return `${st.slice(st.indexOf("(") + 1, close)}|${st.slice(close + 2).split(" ")[19]}`;
    }
    if (platform === "darwin") return String(run(["-o", "lstart=,comm=", "-p", String(pid)])).trim().replace(/\s+/g, " ");
  } catch { /* gone or unreadable */ }
  return "";
}

export const sessionFile = (tag, stateDir = STATE_DIR) => join(stateDir, SESSIONS_DIR, `${tag.slice(3)}.json`);
// Once per session: record the agent process that runs it (cli/session-stop.mjs findAgentPid; macOS and Linux, pid 0
// elsewhere), so the watcher can end the session's agent while it is idle. → true when a record was written.
export function registerSession({ sessionTag = "", startPid = process.ppid, shim = false, stateDir = STATE_DIR, find = findAgentPid, identity = processIdentity, now = Date.now() } = {}) {
  if (!SESSION_RE.test(sessionTag)) return false;
  const p = sessionFile(sessionTag, stateDir);
  if (existsSync(p)) return false;
  try {
    const pid = find({ startPid, shim });
    mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
    writeFileSync(p, JSON.stringify({ v: 1, session: sessionTag, pid, id: pid ? identity(pid) : "", t: now }), { mode: 0o600 });
    return true;
  } catch { return false; }
}

// The hook's step on PreToolUse and UserPromptSubmit: nothing unless the verified policy names the stop channel.
// → the stops a verified, newer stop document adds ([] normally).
export function stopChannelStep({ policy, keys = [], config = {}, actor = "", sessionTag = "", startPid, shim = false, stateDir = STATE_DIR, start } = {}) {
  if (!policy || !policy.stopChannel) return [];
  try {
    ensureWatcher({ policy, enrolled: !!config.installToken, stateDir, ...(start ? { start } : {}) });
    registerSession({ sessionTag, startPid, shim, stateDir });
    return fastStops({ policy, keys, tenant: config.tenant, actor, stateDir });
  } catch { return []; }
}
