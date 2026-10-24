// Who the quarantined reader is talking to. Any process of the agent's OS user can listen on a loopback port, run
// a signed runtime as a code host (ELECTRON_RUN_AS_NODE=1, `-e`), detach from the agent's process tree, or replace a
// binary it owns. So the boundary is the OS account: the process that ACCEPTED this connection (found from the
// connection itself, before a byte of the request is written) must run as a different user from the hook.
//   peer pid + uid  macOS  two of netstat -anv, lsof -Fpn and nettop must name the same pid (parseNetstatPeer et al.),
//                          then ps -o uid=,ruid=
//                   Linux  /proc/net/tcp{,6} (the socket's uid, readable for any user) + /proc/<pid>/fd (tcpTable)
//                          and /proc/<pid>/status Uid when the pid is readable
//                   Windows netstat -ano, the owner SID (GetOwnerSid) against this token's SID (not verified on Windows)
// A same-user reader is accepted only under the admin binding's fileQuarantineSameUserReader, and is weaker by
// construction (the agent can impersonate it). Even then its executable must be an exact file in
// fileQuarantineModel.executables, neither it nor any parent directory writable by the agent's user, on macOS
// signed with a Team ID in fileQuarantineModel.teamIds, and its environment and arguments readable and free of
// code-host switches (ELECTRON_RUN_AS_NODE, NODE_OPTIONS, DYLD_*, LD_PRELOAD, -e / --eval / a script path).
// The agent's process tree (the hook's parent chain through its shells to the agent) is an extra signal: a peer
// inside it is refused in either mode; a peer outside it proves nothing. Anything undetermined is refused.
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, readlinkSync, realpathSync, statSync } from "node:fs";
import { dirname } from "node:path";
import { defaultReadChain, isHookShell } from "./ai-cli-parents.mjs";
import { tcpTable, parseNetstatTcp, runCmd } from "./local-ai-inventory.mjs";

function run(bins, args, { stderr = false } = {}) {
  for (const bin of bins) {
    try { return execFileSync(bin, args, { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", stderr ? "pipe" : "ignore"] }); } catch (e) {
      if (e && e.code === "ENOENT") continue;
      if (stderr && typeof e?.stderr === "string") return e.stderr;
      return typeof e?.stdout === "string" && e.stdout ? e.stdout : null;
    }
  }
  return null;
}
const LSOF = ["/usr/sbin/lsof", "/usr/bin/lsof", "/bin/lsof"];
const PS = ["/bin/ps", "/usr/bin/ps"];

// Peer lookups on macOS. Process names are the executable's file name, which the agent chooses ("x:1 ollama"
// renders as "x:1 ollama:44323"), so a name is never parsed for a pid: a field is "<name><sep><pid>" split at its
// LAST separator, and a name that holds the separator, whitespace, a comma or a line break is ambiguous, which
// refuses. Each returns { pid } | { ambiguous: true } | null.
const PLAIN_NAME = /^[^\s:.,]+$/;
// `netstat -anv`: every user's sockets. Fixed layout: proto recv-q send-q local foreign state rxbytes txbytes
// rhiwat shiwat process:pid, then eight fixed columns (state options gencnt flags flags1 usecnt rtncnt fltrs).
export function parseNetstatPeer(text, serverPort, localPort) {
  for (const line of String(text || "").split("\n")) {
    if (!/^tcp/.test(line)) continue;
    const t = line.trim().split(/\s+/);
    if (t.length < 19 || t[5] !== "ESTABLISHED" || !t[3].endsWith(`.${serverPort}`) || !t[4].endsWith(`.${localPort}`)) continue;
    const field = t.slice(10, t.length - 8);
    if (field.length !== 1) return { ambiguous: true };
    const i = field[0].lastIndexOf(":");
    const name = field[0].slice(0, i), pid = field[0].slice(i + 1);
    if (i <= 0 || !/^\d+$/.test(pid) || !/^[^\s:,]+$/.test(name)) return { ambiguous: true };
    return { pid: Number(pid) };
  }
  return null;
}
// `nettop -L 1 -m tcp -n -x -J state`: a "<name>.<pid>,," line, then that process's "tcp4 <local><-><remote>,<State>,"
// lines. Reads every user's sockets through the kernel's network statistics, a source independent of netstat.
export function parseNettopPeer(text, serverPort, localPort) {
  let proc = null;
  const endsPort = (a, port) => new RegExp(`[:.]${port}$`).test(a);
  for (const line of String(text || "").split("\n")) {
    if (!/^(?:tcp|udp)/.test(line)) { proc = line; continue; }
    const m = line.match(/^tcp[46]? (\S+)<->(\S+),([A-Za-z]+),/);
    if (!m || m[3] !== "Established" || !endsPort(m[1], serverPort) || !endsPort(m[2], localPort)) continue;
    const h = String(proc || "").match(/^(.*)\.(\d+),,$/);
    if (!h || !PLAIN_NAME.test(h[1])) return { ambiguous: true };
    return { pid: Number(h[2]) };
  }
  return null;
}
// `lsof -nP -iTCP:<port> -sTCP:ESTABLISHED -Fpn`: the pid comes from lsof's own "p" record, not from a name, but
// lsof run as a user lists only that user's processes.
export function parseLsofPeer(text, serverPort, localPort) {
  let pid = null;
  for (const line of String(text || "").split("\n")) {
    if (line.startsWith("p")) pid = Number(line.slice(1));
    else if (line.startsWith("n")) { const m = line.match(/:(\d+)->.*:(\d+)$/); if (m && Number(m[1]) === serverPort && Number(m[2]) === localPort && pid) return { pid }; }
  }
  return null;
}
// Two independent sources must name the same pid; an ambiguous source or a disagreement refuses.
// -> { pid, sources } | { pid: null, why }
export function confirmPeer(results) {
  const named = Object.entries(results).filter(([, r]) => r);
  if (named.some(([, r]) => r.ambiguous)) return { pid: null, why: "a process name made the peer lookup ambiguous" };
  const pids = [...new Set(named.map(([, r]) => r.pid))];
  if (pids.length > 1) return { pid: null, why: "the peer lookups disagree on the process" };
  if (named.length < 2) return { pid: null, why: named.length ? "the peer process could not be confirmed by a second source" : "the reader's process could not be determined" };
  return { pid: pids[0], sources: named.map(([k]) => k) };
}
// /proc/net/tcp{,6} (Linux): the ESTABLISHED row local :<serverPort> remote :<localPort> -> { uid, inode } | null.
// The uid column is the socket owner's and readable for every user's sockets.
export function parseProcTcpPeer(text, serverPort, localPort) {
  for (const line of String(text || "").split("\n")) {
    const t = line.trim().split(/\s+/);
    if (t.length < 10 || t[3] !== "01") continue;
    const l = t[1].split(":"), r = t[2].split(":");
    if (parseInt(l[1], 16) === serverPort && parseInt(r[1], 16) === localPort) return { uid: Number(t[7]), inode: t[9] };
  }
  return null;
}

// The server end of 127.0.0.1:<localPort> -> :<serverPort>: { pid, socketUid, why }. pid is null when it cannot be
// read or confirmed (macOS: two of netstat, lsof and nettop must agree), socketUid is Linux-only.
export function peerOf(serverPort, localPort, { platform = process.platform } = {}) {
  if (platform === "darwin") {
    const c = confirmPeer({
      netstat: parseNetstatPeer(run(["/usr/sbin/netstat"], ["-anv"]), serverPort, localPort),
      lsof: parseLsofPeer(run(LSOF, ["-nP", `-iTCP:${serverPort}`, "-sTCP:ESTABLISHED", "-Fpn"]), serverPort, localPort),
      nettop: parseNettopPeer(run(["/usr/bin/nettop"], ["-L", "1", "-m", "tcp", "-n", "-x", "-J", "state"]), serverPort, localPort)
    });
    return { pid: c.pid, socketUid: null, why: c.why || "" };
  }
  if (platform === "linux") {
    let hit = null;
    for (const f of ["/proc/net/tcp", "/proc/net/tcp6"]) { try { hit = parseProcTcpPeer(readFileSync(f, "utf8"), serverPort, localPort); } catch { /* absent */ } if (hit) break; }
    if (!hit) return { pid: null, socketUid: null, why: "" };
    const s = (tcpTable({ platform }).sockets || []).find((x) => x.state === "established" && x.lport === serverPort && x.rport === localPort && x.pid);
    return { pid: s ? Number(s.pid) : null, socketUid: hit.uid, why: "" };
  }
  if (platform === "win32") {
    const s = parseNetstatTcp(runCmd("netstat", ["-ano"]) || "").find((x) => x.state === "established" && x.lport === serverPort && x.rport === localPort);
    return { pid: s ? Number(s.pid) : null, socketUid: null, why: "" };
  }
  return { pid: null, socketUid: null, why: "" };
}

// The peer's uids (effective and real); Windows: windowsSids. -> number[] | { peer, self } | null
export function peerUids(pid, { platform = process.platform } = {}) {
  try {
    if (platform === "darwin") {
      const m = String(run(PS, ["-o", "uid=,ruid=", "-p", String(pid)]) || "").trim().match(/^(\d+)\s+(\d+)$/);
      return m ? [Number(m[1]), Number(m[2])] : null;
    }
    if (platform === "linux") {
      const m = readFileSync(`/proc/${pid}/status`, "utf8").match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m);
      return m ? [...new Set(m.slice(1).map(Number))] : null;
    }
    if (platform === "win32") return windowsSids(run(["powershell.exe"], ["-NoProfile", "-NonInteractive", "-Command", windowsSidScript(pid)]));
  } catch { /* not readable */ }
  return null;
}
// Windows: the peer's owner SID (Win32_Process GetOwnerSid) and this process token's SID, never the USERNAME /
// USERDOMAIN environment, which the agent can set. -> "S-1-…|S-1-…" on one line.
export function windowsSidScript(pid) {
  return `$ErrorActionPreference='Stop'; $p=Get-CimInstance Win32_Process -Filter "ProcessId=${Number(pid) | 0}"; $o=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid; [Console]::Out.Write($o.Sid + '|' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)`;
}
const SID = /^S-1-\d+(?:-\d+){1,14}$/i;
// -> { peer, self } | null when either is missing or not a SID.
export function windowsSids(text) {
  const m = String(text || "").trim().match(/^([^|\s]+)\|([^|\s]+)$/);
  if (!m || !SID.test(m[1]) || !SID.test(m[2])) return null;
  return { peer: m[1].toUpperCase(), self: m[2].toUpperCase() };
}
const agentUidOf = (platform) => (platform === "win32" ? null : typeof process.getuid === "function" ? process.getuid() : null);

export function exePath(pid, { platform = process.platform } = {}) {
  try {
    if (platform === "darwin") {
      const out = run(LSOF, ["-nP", "-p", String(pid), "-a", "-d", "txt", "-Fn"]);
      const n = out && out.split("\n").find((l) => l.startsWith("n/"));
      return n ? n.slice(1) : null;
    }
    if (platform === "linux") return readlinkSync(`/proc/${pid}/exe`).replace(/ \(deleted\)$/, "");
  } catch { /* not readable */ }
  return null;
}

// The peer's environment and arguments. macOS: `ps eww` prints the command then the environment; the part after
// the plain command must hold at least one NAME=value, or the environment is unreadable. -> { env, args } | nulls
export function peerEnvArgs(pid, { platform = process.platform } = {}) {
  try {
    if (platform === "darwin") {
      const cmd = String(run(PS, ["-ww", "-o", "command=", "-p", String(pid)]) || "").replace(/\n+$/, "");
      const all = String(run(PS, ["eww", "-o", "command=", "-p", String(pid)]) || "").replace(/\n+$/, "");
      if (!cmd) return { env: null, args: null };
      const rest = all.startsWith(cmd) ? all.slice(cmd.length).trim() : "";
      const env = rest.split(/\s+(?=[A-Za-z_][A-Za-z0-9_]*=)/).filter((x) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(x));
      return { env: env.length ? env : null, args: cmd.split(/\s+/).slice(1) };
    }
    if (platform === "linux") {
      const env = readFileSync(`/proc/${pid}/environ`, "utf8").split("\0").filter(Boolean);
      const args = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").filter((x, i, a) => i < a.length - 1 || x).slice(1);
      return { env: env.length ? env : null, args };
    }
  } catch { /* not readable */ }
  return { env: null, args: null };
}

// The executable or any directory above it writable by `uid` (its owner, a group it is in, or everyone). -> bool | null
export function writableBy(exe, uid, groups = typeof process.getgroups === "function" ? process.getgroups() : []) {
  try {
    let p = realpathSync(exe);
    for (let i = 0; i < 64; i++) {
      const st = statSync(p);
      if (st.uid === uid || (st.mode & 0o002) || ((st.mode & 0o020) && groups.includes(st.gid))) return true;
      const up = dirname(p);
      if (up === p) return false;
      p = up;
    }
  } catch { /* undetermined */ }
  return null;
}

// macOS code signature: -> { valid, teamId } (teamId null when ad-hoc or a platform binary without one).
export function codeSignature(exe) {
  try {
    const v = spawnSync("/usr/bin/codesign", ["--verify", "--strict", exe], { encoding: "utf8", timeout: 5000 });
    const d = spawnSync("/usr/bin/codesign", ["-dv", "--verbose=2", exe], { encoding: "utf8", timeout: 5000 });
    const m = String(d.stderr || "").match(/^TeamIdentifier=([A-Z0-9]{10})$/m);
    return { valid: v.status === 0, teamId: m ? m[1] : null };
  } catch { return { valid: false, teamId: null }; }
}

export function agentPids(chain) {
  const out = new Set();
  for (const c of chain || []) {
    if (!c || !(c.pid > 1)) break;
    out.add(c.pid);
    if (!isHookShell(c.image)) break;
  }
  return out;
}

const CODE_HOST_ENV = /^(?:ELECTRON_RUN_AS_NODE|NODE_OPTIONS|LD_PRELOAD|LD_AUDIT|DYLD_[A-Z_]*)=/;
const CODE_HOST_ARG = /^(?:-e|--eval|-p|--print|-r|--require|--import|--loader|--experimental-loader|-c|--inspect(?:-brk)?|--remote-debugging-port)(?:=.*)?$|\.(?:m?js|cjs|mts|ts|py|sh|rb|pl|lua)$/i;
function norm(p, platform) {
  let s = String(p || "");
  try { s = realpathSync(s); } catch { /* as given */ }
  s = s.replace(/\\/g, "/");
  return platform === "darwin" || platform === "win32" ? s.toLowerCase() : s;
}
// Exact files only: an entry that names a directory never matches.
export function pinnedExe(exe, executables, { platform = process.platform } = {}) {
  if (!exe) return false;
  const e = norm(exe, platform);
  return (executables || []).some((a) => typeof a === "string" && a && !/[\\/]$/.test(a) && e === norm(a, platform));
}

// Pure. facts: { pid, uids, agentUid, chain, agent, exe, writable, signature: { valid, teamId }, env, args }.
// opts: { sameUser, executables, teamIds, platform }. -> { ok, why, sameUser }
export function judgeOwner(f, { sameUser = false, executables = [], teamIds = [], platform = process.platform } = {}) {
  if (!f || (!f.pid && !(Array.isArray(f.uids) && f.uids.length))) return { ok: false, why: (f && f.why) || "the reader's process could not be determined" };
  if (!Array.isArray(f.uids) || !f.uids.length || f.agentUid == null) return { ok: false, why: "the reader's OS user could not be determined" };
  if (Array.isArray(f.chain) && f.agent && f.chain.some((c) => c.pid > 1 && f.agent.has(c.pid))) return { ok: false, why: "the reader runs inside the agent's process tree" };
  if (!f.uids.includes(f.agentUid)) return { ok: true, why: "", sameUser: false };
  if (!sameUser) return { ok: false, why: "the reader runs as the agent's own OS user (a same-user reader needs fileQuarantineSameUserReader in the admin binding)" };
  if (!f.exe) return { ok: false, why: "the reader's executable could not be determined" };
  if (!pinnedExe(f.exe, executables, { platform })) return { ok: false, why: "the reader's executable is not a file fileQuarantineModel.executables pins" };
  if (f.writable !== false) return { ok: false, why: f.writable === true ? "the reader's executable or a directory above it is writable by the agent's user" : "whether the reader's executable is writable could not be determined" };
  if (platform === "darwin") {
    if (!f.signature || f.signature.valid !== true) return { ok: false, why: "the reader's executable has no valid code signature" };
    if (!f.signature.teamId || !teamIds.includes(f.signature.teamId)) return { ok: false, why: "the reader's executable is not signed by a Team ID fileQuarantineModel.teamIds lists" };
  }
  if (!Array.isArray(f.env) || !Array.isArray(f.args)) return { ok: false, why: "the reader's environment or arguments could not be read" };
  if (f.env.some((x) => CODE_HOST_ENV.test(x))) return { ok: false, why: "the reader runs with a code-host environment variable" };
  if (f.args.some((x) => CODE_HOST_ARG.test(x))) return { ok: false, why: "the reader runs with a code-evaluation argument or a script" };
  return { ok: true, why: "", sameUser: true };
}

// Linux: the socket table's owner uid (kernel-reported, any user) with the pid's uids when the pid is readable; the
// two must agree, or the uid is undetermined. -> uids | null
export function mergeSocketUid(pidUids, socketUid) {
  if (socketUid == null) return pidUids || null;
  if (!pidUids) return [socketUid];
  return pidUids.includes(socketUid) ? pidUids : null;
}

// The facts judgeOwner needs, read from the system. The same-user facts are read only when they can matter.
export function peerFacts({ serverPort, localPort, sameUser = false, platform = process.platform, readChain = defaultReadChain(platform), startPid = process.ppid }) {
  const { pid, socketUid, why } = peerOf(serverPort, localPort, { platform });
  let uids = null, agentUid = agentUidOf(platform);
  if (pid && platform === "win32") { const w = peerUids(pid, { platform }); if (w) { uids = [w.peer]; agentUid = w.self; } }
  else if (pid) uids = peerUids(pid, { platform });
  const f = { pid, why, uids: mergeSocketUid(uids, socketUid), agentUid, chain: null, agent: null };
  if (!pid) return f;
  try { f.chain = readChain(pid, 32); f.agent = agentPids(readChain(startPid, 8)); } catch { /* the tree is a signal, not the boundary */ }
  if (sameUser && Array.isArray(f.uids) && f.uids.includes(f.agentUid)) {
    f.exe = exePath(pid, { platform });
    f.writable = f.exe && f.agentUid >= 0 ? writableBy(f.exe, f.agentUid) : null;
    f.signature = platform === "darwin" && f.exe ? codeSignature(f.exe) : null;
    Object.assign(f, peerEnvArgs(pid, { platform }));
  }
  return f;
}

// The check the reader runs on a loopback connection before sending the file. -> { ok, why }. Never throws.
export function verifyReaderPeer({ serverPort, localPort, sameUser = false, executables = [], teamIds = [], platform = process.platform, gather = peerFacts, readChain, startPid }) {
  try {
    const f = gather({ serverPort, localPort, sameUser, platform, ...(readChain ? { readChain } : {}), ...(startPid ? { startPid } : {}) });
    return judgeOwner(f, { sameUser, executables, teamIds, platform });
  } catch { return { ok: false, why: "the reader's process could not be checked" }; }
}
