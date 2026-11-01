#!/usr/bin/env node
// The stop watcher (cli/stop-channel.mjs has the design and the trust model). One per device user, started detached by
// the hook while the verified policy names the console's stop channel. It holds a long-poll to
//   GET <serverUrl>/api/agents/stop-channel?actor=<h2:>&known=<state>&wait=25   (X-Install-Token)
// and on each signed stop document: writes it to ~/.moorai/stop-channel.json (removes the file when the document holds
// no stop), then, for every stop, sends SIGTERM to the recorded agent process of each live session it names (a device
// stop names every session; macOS and Linux; only while the pid is still the process recorded, and only for a document
// whose signature verified under the device's anchor or pin), posts one content-free SESSION_KILL acknowledgement per
// session it signalled, and for a device stop drops the desktop host's kill-session sentinel.
// It exits when its lock is taken by another watcher, when the console answers 401 or 404 (not enrolled, or no stop
// channel), and once no recorded agent process has been alive for IDLE_EXIT_MS.
import os from "node:os";
import { openSync, writeSync, closeSync, readFileSync, readdirSync, rmSync, utimesSync, mkdirSync, statSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { loadConfig } from "./config.mjs";
import { actorHash } from "./content-hash.mjs";
import { currentPolicyTrust } from "./hook-core.mjs";
import { STATE_DIR } from "./state-dirs.mjs";
import { STOP_CATEGORY } from "./session-stop.mjs";
import { requestKill } from "./signals.mjs";
import { STOP_CHANNEL_PATH, WATCH_LOCK, SESSIONS_DIR, HEARTBEAT_MS, STALE_MS, verifyStopDoc, writeStopFile, processIdentity } from "./stop-channel.mjs";

export const WAIT_SEC = 25;
export const IDLE_EXIT_MS = 10 * 60 * 1000;
// A session recorded with no pid (Windows, or no agent process found) counts as active this long after it was recorded.
export const NO_PID_ACTIVE_MS = 12 * 3600 * 1000;
const BACKOFF_CAP_MS = 30000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === "EPERM"; } };

// Take the lock: create it, or replace one whose watcher is gone (dead pid, or no heartbeat for STALE_MS).
export function takeLock(stateDir = STATE_DIR, pid = process.pid, now = Date.now()) {
  const p = join(stateDir, WATCH_LOCK);
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  for (let i = 0; i < 2; i++) {
    try { const fd = openSync(p, "wx", 0o600); writeSync(fd, `${pid}\n`); closeSync(fd); return true; } catch (e) { if (e.code !== "EEXIST") return false; }
    let held = 0, fresh = false;
    try { held = Number(readFileSync(p, "utf8").trim()); fresh = now - statSync(p).mtimeMs < STALE_MS; } catch { /* vanished */ }
    if (held > 1 && held !== pid && alive(held) && fresh) return false;
    rmSync(p, { force: true });
  }
  return false;
}

export function ownsLock(stateDir = STATE_DIR, pid = process.pid) {
  try { return Number(readFileSync(join(stateDir, WATCH_LOCK), "utf8").trim()) === pid; } catch { return false; }
}

// The recorded sessions (cli/stop-channel.mjs registerSession). Records of dead processes, and records with no pid
// older than NO_PID_ACTIVE_MS, are removed.
export function readSessions(stateDir = STATE_DIR, { isAlive = alive, now = Date.now() } = {}) {
  const dir = join(stateDir, SESSIONS_DIR);
  const out = [];
  let names = [];
  try { names = readdirSync(dir).filter((n) => /^[0-9a-f]{16}\.json$/.test(n)); } catch { return out; }
  for (const n of names) {
    let r;
    try { r = JSON.parse(readFileSync(join(dir, n), "utf8")); } catch { continue; }
    if (!r || typeof r.session !== "string" || `${r.session.slice(3)}.json` !== n) continue;
    if (r.pid > 1 ? !isAlive(r.pid) : !(now - Number(r.t) < NO_PID_ACTIVE_MS)) { rmSync(join(dir, n), { force: true }); continue; }
    out.push(r);
  }
  return out;
}

// The sessions a stop names among the recorded ones.
export const sessionsFor = (stop, sessions) => sessions.filter((s) => stop.scope === "device" || s.session === stop.session);

// Signal what the current stops name and was not signalled yet. → the acks to post.
export function act(stops, { sessions, signed, done, identity = processIdentity, kill = (pid) => process.kill(pid, "SIGTERM"), sentinel = requestKill } = {}) {
  const acks = [];
  for (const stop of stops) {
    if (stop.scope === "device" && !done.has(`sentinel:${stop.id}`)) { done.add(`sentinel:${stop.id}`); try { sentinel({ tool: "stop-watch", ids: [], stage: "policy", stopId: stop.id }); } catch { /* best-effort */ } }
    for (const s of sessionsFor(stop, sessions)) {
      const k = `${stop.id}:${s.session}`;
      if (done.has(k)) continue;
      done.add(k);
      let signalled = false;
      if (signed && s.pid > 1 && s.id && identity(s.pid) === s.id) { try { kill(s.pid); signalled = true; } catch { /* gone */ } }
      if (signalled) acks.push({ stop, session: s.session });
    }
  }
  return acks;
}

export function ackAlert(stop, session, who) {
  return { threatId: 0, category: STOP_CATEGORY, riskLevel: "Blocked", stage: "policy", tool: "stop-watch", contentHash: `stop:${stop.id}`, reasonCode: "SESSION_KILL", decision: "deny",
    stopId: stop.id, stopScope: stop.scope, signalled: true, session, ts: new Date().toISOString(), ...who };
}

async function main() {
  const config = loadConfig();
  if (!config.installToken || !config.serverUrl) return;
  if (!takeLock()) return;
  const user = os.userInfo().username, device = os.hostname();
  const who = { user, device, platform: os.platform(), tenant: config.tenant, actor: actorHash(user, device) };
  const headers = { "X-Install-Token": config.installToken };
  const done = new Set();
  let current = [], signed = false, known = "", failures = 0, lastAlive = Date.now(), stopping = false;
  const quit = () => { stopping = true; if (ownsLock()) rmSync(join(STATE_DIR, WATCH_LOCK), { force: true }); process.exit(0); };
  process.on("SIGTERM", quit);
  process.on("SIGINT", quit);
  const post = (a) => fetch(`${config.serverUrl}/api/alerts`, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify(a), signal: AbortSignal.timeout(5000) }).catch(() => {});
  const sweep = async () => {
    const sessions = readSessions();
    if (sessions.length) lastAlive = Date.now();
    if (current.length) for (const a of act(current, { sessions, signed, done })) await post(ackAlert(a.stop, a.session, who));
  };
  const beat = setInterval(() => {
    if (!ownsLock()) return quit();
    try { const t = new Date(); utimesSync(join(STATE_DIR, WATCH_LOCK), t, t); } catch { /* next beat */ }
    sweep().catch(() => {});
    if (Date.now() - lastAlive > IDLE_EXIT_MS) quit();
  }, HEARTBEAT_MS);
  beat.unref?.();
  await sweep();
  while (!stopping) {
    let r = null;
    const asked = Date.now();
    try {
      r = await fetch(`${config.serverUrl}${STOP_CHANNEL_PATH}?actor=${encodeURIComponent(who.actor)}&wait=${WAIT_SEC}${known ? `&known=${known}` : ""}`,
        { headers, signal: AbortSignal.timeout((WAIT_SEC + 10) * 1000) });
    } catch { r = null; }
    if (r && (r.status === 401 || r.status === 404)) return quit();
    if (r && r.status === 204) {
      failures = 0;
      // A 204 well before `wait` (a proxy cutting the poll short): no tight loop.
      if (Date.now() - asked < 2000) await sleep(1000 + Math.floor(Math.random() * 2000));
      continue;
    }
    if (r && r.status === 200) {
      const raw = await r.text().catch(() => "");
      let doc = null;
      try { doc = JSON.parse(raw); } catch { /* below */ }
      const trust = currentPolicyTrust(config);
      const v = verifyStopDoc(doc, { keys: trust.keys, tenant: config.tenant, actor: who.actor });
      if (v.ok) {
        failures = 0;
        known = /^[0-9a-f]{32}$/.test(String(doc.state)) ? doc.state : "";
        try { writeStopFile(raw, v.stops.length > 0); } catch { /* the hook still has the policy path */ }
        current = v.stops;
        signed = v.signed;
        await sweep();
        continue;
      }
    }
    failures++;
    await sleep(Math.floor(Math.random() * Math.min(BACKOFF_CAP_MS, 1000 * 2 ** Math.min(failures, 5))));
  }
}

const invoked = (() => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (invoked) main().catch(() => process.exit(0));
