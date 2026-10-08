// Listening TCP sockets → [{ pid, proc, port, bind }], read WITHOUT admin rights, for the local-AI
// inventory (cli/local-ai-inventory.mjs). Only a process NAME, a port and loopback-vs-network are
// kept; no address beyond that class is ever returned, and no argument vector or environment is read.
//
//   macOS / Linux  lsof +c 0 -iTCP -sTCP:LISTEN -nP      (+ ps -A -o pid=,comm= to name the PID)
//   Linux          ss -ltnp                              when lsof is missing (common on Linux)
//   Linux          /proc/net/tcp + /proc/net/tcp6        when ss is missing too (no process names)
//   Windows        netstat -ano                          (+ tasklist /FO CSV /NH to name the PID)
//
// Every parser is pure (text in, records out) so the tests drive it with captured samples.
import { readFileSync } from "node:fs";

// Basename of a path, no .exe, lsof's \x20 escapes decoded, lower-case.
export function normName(s) {
  const n = String(s || "").replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))).trim();
  return n.split(/[\\/]/).pop().replace(/\.exe$/i, "").toLowerCase();
}

// "127.0.0.1" | "[::1]" | "::ffff:127.0.0.1" | "127.0.0.53%lo" | "localhost" → loopback; anything else
// ("*", "0.0.0.0", "[::]", a LAN address) → network.
export function bindOf(host) {
  let h = String(host || "").replace(/^\[|\]$/g, "").toLowerCase();
  const zone = h.indexOf("%");
  if (zone >= 0) { if (/^lo\d*$/.test(h.slice(zone + 1))) return "loopback"; h = h.slice(0, zone); }
  h = h.replace(/^::ffff:/, "");
  return /^127\./.test(h) || h === "::1" || h === "localhost" ? "loopback" : "network";
}

// "127.0.0.1:11434" / "*:8080" / "[::1]:8000" → { host, port }
export function splitAddr(a) {
  const s = String(a || ""), i = s.lastIndexOf(":");
  if (i < 0) return null;
  const port = Number(s.slice(i + 1));
  return Number.isInteger(port) && port > 0 && port < 65536 ? { host: s.slice(0, i), port } : null;
}

const rec = (pid, proc, addr) => {
  const a = splitAddr(addr);
  return a ? { pid: pid == null ? null : String(pid), proc: normName(proc), port: a.port, bind: bindOf(a.host) } : null;
};

// `lsof +c 0 -iTCP -sTCP:LISTEN -nP`
export function parseLsof(txt) {
  const out = [];
  for (const line of String(txt || "").split("\n")) {
    const m = line.match(/^(\S+)\s+(\d+)\s.*\bTCP\s+(\S+)\s+\(LISTEN\)\s*$/);
    const r = m && rec(m[2], m[1], m[3]);
    if (r) out.push(r);
  }
  return out;
}

// `ss -ltnp`: State Recv-Q Send-Q Local:Port Peer:Port [users:(("name",pid=N,fd=M))]. Without root,
// users:() is filled only for the caller's own processes; the others keep port + bind with no name.
export function parseSs(txt) {
  const out = [];
  for (const line of String(txt || "").split("\n")) {
    const m = line.match(/^LISTEN\s+\d+\s+\d+\s+(\S+)\s+\S+(?:\s+(.*))?$/);
    if (!m) continue;
    const u = (m[2] || "").match(/users:\(\("((?:[^"\\]|\\.)*)",pid=(\d+)/);
    const r = rec(u ? u[2] : null, u ? u[1] : "", m[1]);
    if (r) out.push(r);
  }
  return out;
}

// /proc/net/tcp{,6}: "sl local_address rem_address st ...", addresses as little-endian hex words.
// State 0A = LISTEN. No process names (the inode → pid walk needs /proc/<pid>/fd, often unreadable).
function procHexLoopback(hex) {
  const bytes = [];
  for (let w = 0; w < hex.length; w += 8) {
    const word = hex.slice(w, w + 8);
    for (let b = 6; b >= 0; b -= 2) bytes.push(parseInt(word.slice(b, b + 2), 16));
  }
  if (bytes.length === 4) return bytes[0] === 127;
  if (bytes.length !== 16) return false;
  const zero = (from, to) => bytes.slice(from, to).every((x) => x === 0);
  if (zero(0, 15) && bytes[15] === 1) return true;                                    // ::1
  return zero(0, 10) && bytes[10] === 0xff && bytes[11] === 0xff && bytes[12] === 127; // ::ffff:127.x
}
export function parseProcNetTcp(txt) {
  const out = [];
  for (const line of String(txt || "").split("\n")) {
    const t = line.trim().split(/\s+/);
    if (t.length < 4 || t[3] !== "0A") continue;
    const m = t[1].match(/^([0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}):([0-9A-Fa-f]{4})$/);
    if (!m) continue;
    const port = parseInt(m[2], 16);
    if (port > 0) out.push({ pid: null, proc: "", port, bind: procHexLoopback(m[1]) ? "loopback" : "network" });
  }
  return out;
}

// `netstat -ano`: TCP <local> <foreign> <state> <pid>. Listening = all-zero foreign address (the state
// word is localised, so it is not read).
export function parseNetstat(txt) {
  const out = [];
  for (const line of String(txt || "").split(/\r?\n/)) {
    const t = line.trim().split(/\s+/);
    if (t[0] !== "TCP" || t.length < 5 || !/^(0\.0\.0\.0|\[::\]):0$/.test(t[2])) continue;
    const r = rec(t[t.length - 1], "", t[1]);
    if (r) out.push(r);
  }
  return out;
}

// `ps -A -o pid=,comm=` → Map(pid → name). A comm-only line (no pid) is still kept as a name.
export function parsePs(txt) {
  const byPid = new Map(), names = [];
  for (const line of String(txt || "").split("\n")) {
    const m = line.match(/^\s*(\d+)\s+(.+?)\s*$/);
    const name = normName(m ? m[2] : line);
    if (!name) continue;
    names.push(name);
    if (m) byPid.set(m[1], name);
  }
  return { byPid, names: [...new Set(names)] };
}

// `tasklist /FO CSV /NH` → Map(pid → name)
export function parseTasklist(csv) {
  const byPid = new Map();
  for (const line of String(csv || "").split(/\r?\n/)) {
    const m = line.match(/^"([^"]*)","(\d+)"/);
    if (m) byPid.set(m[2], normName(m[1]));
  }
  return { byPid, names: [...new Set(byPid.values())] };
}

const readOr = (readFile, p) => { try { return readFile(p, "utf8"); } catch { return null; } };

// → { listeners: [{pid, proc, port, bind}] | null, processes: [name] | null, source }
// A probe that could not run is null — never an empty list that would read as "nothing listens".
export function probeSockets(runner, platform = process.platform, readFile = readFileSync) {
  let listeners = null, procs = null, source = "none";
  if (platform === "win32") {
    const ns = runner("netstat", ["-ano"]);
    if (ns != null) { listeners = parseNetstat(ns); source = "netstat"; }
    const tl = runner("tasklist", ["/FO", "CSV", "/NH"]);
    if (tl != null) procs = parseTasklist(tl);
  } else {
    const lsof = runner("lsof", ["+c", "0", "-iTCP", "-sTCP:LISTEN", "-nP"]);
    if (lsof != null) { listeners = parseLsof(lsof); source = "lsof"; }
    if (listeners == null && platform === "linux") {
      const ss = runner("ss", ["-ltnp"]);
      if (ss != null) { listeners = parseSs(ss); source = "ss"; }
    }
    if (listeners == null && platform === "linux") {
      const t4 = readOr(readFile, "/proc/net/tcp"), t6 = readOr(readFile, "/proc/net/tcp6");
      if (t4 != null || t6 != null) { listeners = [...parseProcNetTcp(t4), ...parseProcNetTcp(t6)]; source = "proc"; }
    }
    const ps = runner("ps", ["-A", "-o", "pid=,comm="]);
    if (ps != null) procs = parsePs(ps);
  }
  if (listeners && procs) for (const l of listeners) if (l.pid && procs.byPid.has(l.pid)) l.proc = procs.byPid.get(l.pid);
  if (listeners) {
    const seen = new Set();
    listeners = listeners.filter((l) => { const k = `${l.proc}|${l.port}|${l.bind}`; if (seen.has(k)) return false; seen.add(k); return true; });
  }
  return { listeners, processes: procs ? procs.names : null, source };
}
