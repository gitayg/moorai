// Who the quarantined reader is talking to. Any process of the agent's OS user can listen on a loopback port, run
// a signed runtime as a code host (ELECTRON_RUN_AS_NODE=1, `-e`), detach from the agent's process tree, or replace a
// binary it owns. So the boundary is the OS account: the process that ACCEPTED this connection (found from the
// connection itself, before a byte of the request is written) must run as a different user from the hook.
//   peer pid + uid  macOS  netstat -anv (every user's sockets), else lsof -nP -iTCP:<port> -sTCP:ESTABLISHED -Fpn
//                          (this user's), then ps -o uid=,ruid=
//                   Linux  /proc/net/tcp{,6} (the socket's uid, readable for any user) + /proc/<pid>/fd (tcpTable)
//                          and /proc/<pid>/status Uid when the pid is readable
//                   Windows netstat -ano, Win32_Process GetOwner (best effort; not verified on Windows)
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

// `netstat -anv` (macOS): every user's sockets with process:pid, which lsof run as a user does not show.
// -> pid | null for the ESTABLISHED row <host>.<serverPort> -> <host>.<localPort>.
export function parseNetstatPeer(text, serverPort, localPort) {
  for (const line of String(text || "").split("\n")) {
    if (!/^tcp/.test(line)) continue;
    const t = line.trim().split(/\s+/);
    if (t.length < 11 || t[5] !== "ESTABLISHED" || !t[3].endsWith(`.${serverPort}`) || !t[4].endsWith(`.${localPort}`)) continue;
    const m = t.slice(10).join(" ").match(/:(\d+)(?:\s|$)/);
    if (m) return Number(m[1]);
  }
  return null;
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

// The server end of 127.0.0.1:<localPort> -> :<serverPort>: { pid, socketUid }. pid is null when it cannot be read
// (another user's process on Linux), socketUid is Linux-only.
export function peerOf(serverPort, localPort, { platform = process.platform } = {}) {
  if (platform === "darwin") {
    const ns = parseNetstatPeer(run(["/usr/sbin/netstat"], ["-anv"]), serverPort, localPort);
    if (ns) return { pid: ns, socketUid: null };
    const out = run(LSOF, ["-nP", `-iTCP:${serverPort}`, "-sTCP:ESTABLISHED", "-Fpn"]);
    let pid = null;
    for (const line of String(out || "").split("\n")) {
      if (line.startsWith("p")) pid = Number(line.slice(1));
      else if (line.startsWith("n")) { const m = line.match(/:(\d+)->.*:(\d+)$/); if (m && Number(m[1]) === serverPort && Number(m[2]) === localPort && pid) return { pid, socketUid: null }; }
    }
    return { pid: null, socketUid: null };
  }
  if (platform === "linux") {
    let hit = null;
    for (const f of ["/proc/net/tcp", "/proc/net/tcp6"]) { try { hit = parseProcTcpPeer(readFileSync(f, "utf8"), serverPort, localPort); } catch { /* absent */ } if (hit) break; }
    if (!hit) return { pid: null, socketUid: null };
    const s = (tcpTable({ platform }).sockets || []).find((x) => x.state === "established" && x.lport === serverPort && x.rport === localPort && x.pid);
    return { pid: s ? Number(s.pid) : null, socketUid: hit.uid };
  }
  if (platform === "win32") {
    const s = parseNetstatTcp(runCmd("netstat", ["-ano"]) || "").find((x) => x.state === "established" && x.lport === serverPort && x.rport === localPort);
    return { pid: s ? Number(s.pid) : null, socketUid: null };
  }
  return { pid: null, socketUid: null };
}

// The peer's uids (effective and real). Windows: [owner === this user ? own uid marker : other marker]. -> number[] | null
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
    if (platform === "win32") {
      const out = run(["powershell.exe"], ["-NoProfile", "-NonInteractive", "-Command", `$o=Get-CimInstance Win32_Process -Filter "ProcessId=${Number(pid) | 0}" | Invoke-CimMethod -MethodName GetOwner; "$($o.Domain)\\$($o.User)"`]);
      const who = String(out || "").trim().toLowerCase();
      if (!who || who === "\\") return null;
      const me = `${process.env.USERDOMAIN || ""}\\${process.env.USERNAME || ""}`.toLowerCase();
      return [who === me ? -1 : -2];
    }
  } catch { /* not readable */ }
  return null;
}
const agentUidOf = (platform) => (platform === "win32" ? -1 : typeof process.getuid === "function" ? process.getuid() : null);

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
  if (!f || (!f.pid && !(Array.isArray(f.uids) && f.uids.length))) return { ok: false, why: "the reader's process could not be determined" };
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

// The facts judgeOwner needs, read from the system. The same-user facts are read only when they can matter.
export function peerFacts({ serverPort, localPort, sameUser = false, platform = process.platform, readChain = defaultReadChain(platform), startPid = process.ppid }) {
  const { pid, socketUid } = peerOf(serverPort, localPort, { platform });
  const uids = pid ? peerUids(pid, { platform }) : null;
  const f = { pid, uids: uids || (socketUid != null ? [socketUid] : null), agentUid: agentUidOf(platform), chain: null, agent: null };
  if (uids && socketUid != null && !uids.includes(socketUid)) f.uids = [...uids, socketUid];
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
