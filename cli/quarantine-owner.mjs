// Who the quarantined reader is talking to. The agent runs as the same user, so it can open its own listener on a
// loopback port and receive the raw file the reader sends. Before a byte of the request is written, the process
// that ACCEPTED this connection is found from the connection itself (its local port is the reader's port, its
// remote port is ours), so a listener swapped after a check, or a second one on ::1, cannot slip in:
//   macOS   lsof -nP -iTCP:<port> -sTCP:ESTABLISHED -Fpn   (the "n<server>-><ours>" entry; this user's processes)
//   Linux   /proc/net/tcp{,6} + /proc/<pid>/fd             (cli/local-ai-inventory.mjs tcpTable)
//   Windows netstat -ano                                    (best effort; not verified on Windows)
// That process is refused when it, or any ancestor, is the agent process or a shell between the hook and the agent
// (cli/ai-cli-parents.mjs's walk), or when its executable (macOS: lsof's first txt entry; Linux /proc/<pid>/exe;
// Windows ExecutablePath) is not a known local model runtime or a path fileQuarantineModel.executables names.
// Anything that cannot be determined is refused.
import { execFileSync } from "node:child_process";
import { readlinkSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { defaultReadChain, isHookShell } from "./ai-cli-parents.mjs";
import { tcpTable, parseNetstatTcp, runCmd } from "./local-ai-inventory.mjs";

const LSOF = ["/usr/sbin/lsof", "/usr/bin/lsof", "/bin/lsof"];
function lsof(args) {
  for (const bin of LSOF) {
    try { return execFileSync(bin, args, { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] }); } catch (e) { if (e && e.code === "ENOENT") continue; return typeof e?.stdout === "string" ? e.stdout : null; }
  }
  return null;
}

// The pid holding the server end of the connection 127.0.0.1:<localPort> -> :<serverPort>. -> pid | null
export function peerPid(serverPort, localPort, { platform = process.platform } = {}) {
  if (platform === "darwin") {
    const out = lsof(["-nP", `-iTCP:${serverPort}`, "-sTCP:ESTABLISHED", "-Fpn"]);
    if (!out) return null;
    let pid = null;
    for (const line of out.split("\n")) {
      if (line.startsWith("p")) pid = Number(line.slice(1));
      else if (line.startsWith("n")) {
        const m = line.match(/:(\d+)->.*:(\d+)$/);
        if (m && Number(m[1]) === serverPort && Number(m[2]) === localPort && pid) return pid;
      }
    }
    return null;
  }
  if (platform === "linux") {
    const t = tcpTable({ platform });
    const s = (t.sockets || []).find((x) => x.state === "established" && x.lport === serverPort && x.rport === localPort && x.pid);
    return s ? Number(s.pid) : null;
  }
  if (platform === "win32") {
    const s = parseNetstatTcp(runCmd("netstat", ["-ano"]) || "").find((x) => x.state === "established" && x.lport === serverPort && x.rport === localPort);
    return s ? Number(s.pid) : null;
  }
  return null;
}

export function exePath(pid, { platform = process.platform, chain = [] } = {}) {
  try {
    if (platform === "darwin") {
      const out = lsof(["-nP", "-p", String(pid), "-a", "-d", "txt", "-Fn"]);
      const n = out && out.split("\n").find((l) => l.startsWith("n/"));
      return n ? n.slice(1) : null;
    }
    if (platform === "linux") return readlinkSync(`/proc/${pid}/exe`).replace(/ \(deleted\)$/, "");
    if (platform === "win32") return (chain[0] && chain[0].pid === pid && chain[0].path) || null;
  } catch { /* not readable */ }
  return null;
}

// The agent's processes from the hook's point of view: the hook's parent chain through its shells up to and
// including the first ancestor that is not one (the agent process). chain starts at the hook's parent.
export function agentPids(chain) {
  const out = new Set();
  for (const c of chain || []) {
    if (!c || !(c.pid > 1)) break;
    out.add(c.pid);
    if (!isHookShell(c.image)) break;
  }
  return out;
}

// Known install locations of the runtimes the reader auto-detects (Ollama, LM Studio). A trailing "/" is a
// directory prefix; anything else is one file. "~" is the home directory, %LOCALAPPDATA% that variable.
const RUNTIME_PATHS = {
  darwin: ["/Applications/Ollama.app/", "~/Applications/Ollama.app/", "/opt/homebrew/Cellar/ollama/", "/usr/local/Cellar/ollama/", "/opt/homebrew/bin/ollama", "/usr/local/bin/ollama", "/Applications/LM Studio.app/", "~/Applications/LM Studio.app/", "~/.lmstudio/"],
  linux: ["/usr/local/bin/ollama", "/usr/bin/ollama", "/usr/local/lib/ollama/", "/usr/lib/ollama/", "/snap/ollama/", "~/.lmstudio/"],
  win32: ["%LOCALAPPDATA%/Programs/Ollama/", "%LOCALAPPDATA%/Programs/LM Studio/", "~/.lmstudio/"]
};
export function knownRuntimePaths({ platform = process.platform, home = homedir(), env = process.env } = {}) {
  return (RUNTIME_PATHS[platform] || []).map((p) => p.replace(/^~(?=\/)/, home).replace("%LOCALAPPDATA%", env.LOCALAPPDATA || "\u0000"));
}
function norm(p, platform) {
  let s = String(p || "");
  try { s = realpathSync(s); } catch { /* compare as given */ }
  s = s.replace(/\\/g, "/");
  return platform === "darwin" || platform === "win32" ? s.toLowerCase() : s;
}
export function allowedExe(exe, allowed, { platform = process.platform } = {}) {
  if (!exe) return false;
  const e = norm(exe, platform);
  return allowed.some((a) => {
    if (typeof a !== "string" || !a) return false;
    if (a.endsWith("/") || a.endsWith("\\")) { const d = norm(a, platform).replace(/\/?$/, "/"); return e.startsWith(d); }
    return e === norm(a, platform);
  });
}

// Pure: -> { ok, why }.
export function judgeOwner({ pid, exe, chain, agent, allowed, platform = process.platform }) {
  if (!pid) return { ok: false, why: "the reader's process could not be determined" };
  if (!Array.isArray(chain) || !chain.length || chain[0].pid !== pid) return { ok: false, why: "the reader's process ancestry could not be read" };
  if (!agent || !agent.size) return { ok: false, why: "the agent's process could not be determined" };
  if (chain.some((c) => c.pid > 1 && agent.has(c.pid))) return { ok: false, why: "the reader runs inside the agent's process tree" };
  if (!exe) return { ok: false, why: "the reader's executable could not be determined" };
  if (!allowedExe(exe, allowed, { platform })) return { ok: false, why: "the reader's executable is not a known local model runtime" };
  return { ok: true, why: "" };
}

// The check the reader runs on a loopback connection before sending the file. -> { ok, why }. Never throws.
export function verifyReaderPeer({ serverPort, localPort, executables = [], platform = process.platform, readChain = defaultReadChain(platform), startPid = process.ppid }) {
  try {
    const pid = peerPid(serverPort, localPort, { platform });
    const chain = pid ? readChain(pid, 32) : [];
    const agent = agentPids(readChain(startPid, 8));
    const exe = pid ? exePath(pid, { platform, chain }) : null;
    return judgeOwner({ pid, exe, chain, agent, allowed: [...knownRuntimePaths({ platform }), ...executables], platform });
  } catch { return { ok: false, why: "the reader's process could not be checked" }; }
}
