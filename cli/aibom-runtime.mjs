// RUNNING local model servers and local HTTP/SSE MCP servers — a collector for the AIBOM
// (cli/moorai-aibom.mjs). Model FOLDERS say what is installed; this says what is serving right now.
//
// Reads, via the OS's standard tools (5 s timeout each, fail-open to "unknown"):
//   macOS / Linux  lsof +c 0 -iTCP -sTCP:LISTEN -nP     listening TCP sockets → command NAME + port
//                  ps -A -o comm=                        running command NAMES (never args / environ)
//   Windows        netstat -ano                          listening TCP sockets → PID + port
//                  tasklist /FO CSV /NH                  image NAME per PID
// Only process names and port numbers are kept. The argument vector and environment are never
// requested: they are where a key or token on a command line would be.
//
// Known runtimes. A listener on a DEFAULT port counts on its own only where the port is distinctive;
// generic defaults (8000, 8080) need the process name too, or every dev server would be "vLLM".
//   ollama     process ollama / "ollama app"; default 127.0.0.1:11434 — docs.ollama.com/faq: "Ollama
//              binds 127.0.0.1 port 11434 by default."
//   lmstudio   process "lm studio" / lms. No port rule: LM Studio's docs use 1234 in examples, but
//              `lms server start` "uses the last used port" — no documented default to rely on.
//   llama.cpp  process llama-server; documented default 8080 (tools/server/README.md) — name required.
//   vllm       process vllm; documented default 8000 (docs.vllm.ai `vllm serve --port`) — name
//              required. NOTE: on macOS a `vllm` console script runs as its python interpreter, so
//              the name probe does not see it there (it does on Linux, where comm is the script name).
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

export const RUNTIMES = [
  { runtime: "ollama", names: ["ollama", "ollama app"], ports: [11434], portAlone: true },
  { runtime: "lmstudio", names: ["lm studio", "lms"], ports: [], portAlone: false },
  { runtime: "llama.cpp", names: ["llama-server"], ports: [8080], portAlone: false },
  { runtime: "vllm", names: ["vllm"], ports: [8000], portAlone: false }
];

export function defaultRunner(cmd, args) {
  try {
    return execFileSync(cmd, args, { encoding: "utf8", timeout: 5000, maxBuffer: 8 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
  } catch (e) {
    // lsof exits 1 when it has nothing to list but still printed what it had
    return typeof e?.stdout === "string" && e.stdout ? e.stdout : null;
  }
}

// Test / offline seam: canned command outputs keyed by command name ({ lsof, ps, netstat, tasklist }).
export function fixtureRunner(path) {
  let map = {};
  try { map = JSON.parse(readFileSync(path, "utf8")) || {}; } catch { map = {}; }
  return (cmd) => (typeof map[cmd] === "string" ? map[cmd] : null);
}

// Normalise a process name: basename of a path, no .exe, lsof's \x20 escapes decoded, lower-case.
function normName(s) {
  const n = String(s || "").replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))).trim();
  return n.split(/[\\/]/).pop().replace(/\.exe$/i, "").toLowerCase();
}
function bindOf(host) {
  const h = String(host || "").replace(/^\[|\]$/g, "").toLowerCase();
  return /^127\./.test(h) || h === "::1" || h === "localhost" ? "loopback" : "network";
}
// "127.0.0.1:11434" / "*:8080" / "[::1]:8000" → { host, port }
function splitAddr(a) {
  const i = String(a).lastIndexOf(":");
  if (i < 0) return null;
  const port = Number(a.slice(i + 1));
  return Number.isInteger(port) && port > 0 && port < 65536 ? { host: a.slice(0, i), port } : null;
}

// → [{ proc, port, bind }] or null when the probe could not run.
export function probeListeners(runner = defaultRunner, platform = process.platform) {
  const out = [], seen = new Set();
  const add = (proc, addr) => {
    const a = splitAddr(addr); if (!a) return;
    const rec = { proc: normName(proc), port: a.port, bind: bindOf(a.host) };
    const k = `${rec.proc}|${rec.port}|${rec.bind}`;
    if (!seen.has(k)) { seen.add(k); out.push(rec); }
  };
  if (platform === "win32") {
    const ns = runner("netstat", ["-ano"]);
    if (ns == null) return null;
    const names = pidNames(runner("tasklist", ["/FO", "CSV", "/NH"]));
    for (const line of ns.split(/\r?\n/)) {
      const t = line.trim().split(/\s+/);
      // TCP <local> <foreign> <state> <pid>. Listening = all-zero foreign address (the state word is localised).
      if (t[0] !== "TCP" || t.length < 5 || !/^(0\.0\.0\.0|\[::\]):0$/.test(t[2])) continue;
      add(names.get(t[t.length - 1]) || "", t[1]);
    }
    return out;
  }
  const txt = runner("lsof", ["+c", "0", "-iTCP", "-sTCP:LISTEN", "-nP"]);
  if (txt == null) return null;
  for (const line of txt.split("\n")) {
    const m = line.match(/^(\S+)\s+\d+\s.*\bTCP\s+(\S+)\s+\(LISTEN\)\s*$/);
    if (m) add(m[1], m[2]);
  }
  return out;
}

function pidNames(csv) {
  const map = new Map();
  for (const line of String(csv || "").split(/\r?\n/)) {
    const m = line.match(/^"([^"]*)","(\d+)"/);
    if (m) map.set(m[2], m[1]);
  }
  return map;
}

// → [normalised process name] or null when the probe could not run. Command NAME only.
export function probeProcesses(runner = defaultRunner, platform = process.platform) {
  if (platform === "win32") {
    const csv = runner("tasklist", ["/FO", "CSV", "/NH"]);
    return csv == null ? null : [...new Set([...pidNames(csv).values()].map(normName))];
  }
  const ps = runner("ps", ["-A", "-o", "comm="]);
  return ps == null ? null : [...new Set(ps.split("\n").map(normName).filter(Boolean))];
}

// → [{ runtime, running: true, ports, bind, detectedBy }] for each known runtime found running.
export function localRuntimes({ listeners, processes } = {}) {
  const L = Array.isArray(listeners) ? listeners : [], P = new Set(Array.isArray(processes) ? processes : []);
  const out = [];
  for (const r of RUNTIMES) {
    const byName = L.filter((l) => r.names.includes(l.proc));
    const byPort = r.portAlone ? L.filter((l) => r.ports.includes(l.port)) : [];
    const procSeen = r.names.some((n) => P.has(n)) || byName.length > 0;
    if (!procSeen && !byPort.length) continue;
    const ls = [...byName, ...byPort];
    const ports = [...new Set(ls.map((l) => l.port))].sort((a, b) => a - b);
    const bind = !ls.length ? "unknown" : ls.some((l) => l.bind === "network") ? "network" : "loopback";
    out.push({ runtime: r.runtime, running: true, ports, bind, detectedBy: [procSeen && "process", byPort.length && "port"].filter(Boolean) });
  }
  return out;
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1", "0.0.0.0"]);
// decls: [{ name, scope, url, type, transport }] from the MCP configs the AIBOM reads. Only servers
// declared on a localhost URL are reported, with the port and whether something listens there
// (null = probe unavailable, never a false "not running"). The URL itself is never echoed — its
// query string can carry a token.
export function localMcpListeners(decls, listeners) {
  const out = [];
  for (const d of decls || []) {
    if (!d || !d.url) continue;
    let u;
    try { u = new URL(d.url); } catch { continue; }
    if (!/^https?:$/.test(u.protocol) || !LOCAL_HOSTS.has(u.hostname.toLowerCase())) continue;
    const port = Number(u.port) || (u.protocol === "https:" ? 443 : 80);
    const sse = d.type === "sse" || d.transport === "sse" || /\/sse\/?$/i.test(u.pathname);
    const running = Array.isArray(listeners) ? listeners.some((l) => l.port === port) : null;
    out.push({ name: d.name, scope: d.scope, transport: sse ? "sse" : "http", port, running });
  }
  return out;
}
