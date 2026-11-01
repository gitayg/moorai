// Who listens on moorai-hookd's port. Claude Code sends every hook event, with the bearer token in its headers, to
// http://127.0.0.1:<port> and cannot tell who answers; while moorai-hookd is not listening another local account
// can bind that port, read the events and the token, and answer allow. So `install --hook-transport http` and
// moorai-doctor require that the listener is moorai-hookd run by this user:
//   macOS  `lsof -iTCP:<port> -sTCP:LISTEN -Fpun` run as this user lists only this user's processes; each pid it
//          names must run as this user (ps, cli/quarantine-owner.mjs peerUids), and when `netstat -anv` lists the
//          port's listeners (every user's), each must be one of those pids
//   Linux  /proc/net/tcp{,6}: every LISTEN row on the port (the kernel's socket owner uid) must be this user's
//   other  refused: the listener's owner cannot be read
// A port none of this user's processes listens on is refused, whoever else holds it.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { peerUids } from "./quarantine-owner.mjs";

const LSOF = ["/usr/sbin/lsof", "/usr/bin/lsof", "/bin/lsof"];
function run(bins, args) {
  for (const bin of bins) {
    try { return execFileSync(bin, args, { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] }); } catch (e) {
      if (e && e.code === "ENOENT") continue;
      return typeof e?.stdout === "string" ? e.stdout : null;
    }
  }
  return null;
}

// `lsof -nP -iTCP:<port> -sTCP:LISTEN -Fpun` -> [{ pid, uid, addr }]
export function parseLsofListeners(text, port) {
  const out = [];
  let pid = 0, uid = null;
  for (const line of String(text || "").split("\n")) {
    if (line.startsWith("p")) { pid = Number(line.slice(1)); uid = null; }
    else if (line.startsWith("u")) uid = Number(line.slice(1));
    else if (line.startsWith("n")) {
      const m = line.slice(1).match(/^(.*):(\d+)$/);
      if (m && Number(m[2]) === port && pid > 1) out.push({ pid, uid, addr: m[1] });
    }
  }
  return out;
}

// `netstat -anv` LISTEN rows on the port -> [{ pid } | { ambiguous: true }] (layout: cli/quarantine-owner.mjs
// parseNetstatPeer; the process field is "<name>:<pid>", split at its last colon).
export function parseNetstatListeners(text, port) {
  const out = [];
  for (const line of String(text || "").split("\n")) {
    if (!/^tcp/.test(line)) continue;
    const t = line.trim().split(/\s+/);
    if (t.length < 19 || t[5] !== "LISTEN" || !t[3].endsWith(`.${port}`)) continue;
    const field = t.slice(10, t.length - 8).join(" ");
    const pid = field.slice(field.lastIndexOf(":") + 1);
    out.push(/^\d+$/.test(pid) ? { pid: Number(pid) } : { ambiguous: true });
  }
  return out;
}

// /proc/net/tcp{,6} LISTEN rows (state 0A) on the port -> [{ uid }]
export function parseProcTcpListeners(text, port) {
  const out = [];
  for (const line of String(text || "").split("\n")) {
    const t = line.trim().split(/\s+/);
    if (t.length < 10 || t[3] !== "0A") continue;
    if (parseInt(t[1].split(":")[1], 16) === port) out.push({ uid: Number(t[7]) });
  }
  return out;
}

export function listenerFacts(port, { platform = process.platform } = {}) {
  if (platform === "darwin") {
    const own = parseLsofListeners(run(LSOF, ["-nP", `-iTCP:${port}`, "-sTCP:LISTEN", "-Fpun"]), port);
    return { platform, own: own.map((l) => ({ ...l, uids: peerUids(l.pid, { platform }) })), all: parseNetstatListeners(run(["/usr/sbin/netstat"], ["-anv"]), port) };
  }
  if (platform === "linux") {
    const all = [];
    for (const f of ["/proc/net/tcp", "/proc/net/tcp6"]) { try { all.push(...parseProcTcpListeners(readFileSync(f, "utf8"), port)); } catch { /* absent */ } }
    return { platform, all };
  }
  return { platform };
}

// Pure. -> { ok, why }
export function judgeListener(f, port, uid) {
  const where = `127.0.0.1:${port}`;
  if (uid == null) return { ok: false, why: "this user's id could not be read" };
  if (f.platform === "darwin") {
    if (!f.own || !f.own.length) return { ok: false, why: `no process of this user listens on ${where}` };
    if (f.own.some((l) => !Array.isArray(l.uids) || !l.uids.includes(uid) || (l.uid != null && l.uid !== uid))) return { ok: false, why: `a process that does not run as this user listens on ${where}` };
    const mine = new Set(f.own.map((l) => l.pid));
    if ((f.all || []).some((l) => l.ambiguous || !mine.has(l.pid))) return { ok: false, why: `another account's process also listens on ${where}` };
    return { ok: true, why: "" };
  }
  if (f.platform === "linux") {
    if (!f.all || !f.all.length) return { ok: false, why: `nothing listens on ${where}` };
    if (f.all.some((l) => l.uid !== uid)) return { ok: false, why: `a socket owned by another account listens on ${where}` };
    return { ok: true, why: "" };
  }
  return { ok: false, why: `who listens on ${where} cannot be verified on this platform` };
}

export function listenerOwner(port, { platform = process.platform, uid = typeof process.getuid === "function" ? process.getuid() : null, facts = listenerFacts } = {}) {
  try { return judgeListener(facts(port, { platform }), port, uid); } catch { return { ok: false, why: `who listens on 127.0.0.1:${port} could not be read` }; }
}

// For `install --hook-transport http`: moorai-hookd answers /healthz on the port AND the listener is this user's.
export async function hookdReady(port, { fetchImpl = globalThis.fetch, owner = listenerOwner, timeoutMs = 1500 } = {}) {
  let health = null;
  try {
    const r = await fetchImpl(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(timeoutMs) });
    health = r.ok ? await r.json() : null;
  } catch { /* not listening */ }
  if (!health || health.transport !== "http") return { ok: false, why: `moorai-hookd does not answer on 127.0.0.1:${port}` };
  return owner(port);
}
