// Listening-socket parsers for the local-AI inventory (cli/listen-sockets.mjs): lsof (macOS/Linux),
// ss and /proc/net/tcp{,6} (Linux fallbacks), netstat (Windows). Each must classify loopback vs
// network correctly and keep only a process name + port + that class.
//
//   node --test test/local-ai-inventory-sockets.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { bindOf, parseLsof, parseSs, parseProcNetTcp, parseNetstat, parsePs, probeSockets } from "../cli/listen-sockets.mjs";

const LSOF = [
  "COMMAND                       PID       USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME",
  "ollama                       2463 dev    4u  IPv4 0x544abbf993f4877f      0t0  TCP 127.0.0.1:11434 (LISTEN)",
  "llama-server                 7100 dev    3u  IPv4 0x0000000000000002      0t0  TCP *:8080 (LISTEN)",
  "Jan                          7300 dev    9u  IPv6 0x0000000000000003      0t0  TCP [::1]:1337 (LISTEN)",
  "koboldcpp-mac-a              7400 dev    5u  IPv4 0x0000000000000004      0t0  TCP 192.168.1.20:5001 (LISTEN)",
  "Qwen3.5-0.8B-Q8_             7500 dev    6u  IPv4 0x0000000000000005      0t0  TCP 127.0.0.1:8080 (LISTEN)",
  "ollama                       2463 dev    5u  IPv4 0x0000000000000006      0t0  TCP 127.0.0.1:50000->127.0.0.1:11434 (ESTABLISHED)",
  ""
].join("\n");

const SS = [
  "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process",
  'LISTEN 0      4096       127.0.0.1:11434      0.0.0.0:*    users:(("ollama",pid=812,fd=3))',
  'LISTEN 0      511          0.0.0.0:8080       0.0.0.0:*    users:(("llama-server",pid=900,fd=7))',
  'LISTEN 0      128             [::]:8000          [::]:*    users:(("vllm",pid=901,fd=12))',
  'LISTEN 0      128   [::ffff:127.0.0.1]:1234        *:*    users:(("lms",pid=902,fd=4))',
  "LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*",
  "LISTEN 0      4096               *:12434            *:*",
  "ESTAB  0      0          127.0.0.1:41000  127.0.0.1:11434 users:((\"curl\",pid=5,fd=3))",
  ""
].join("\n");

// /proc/net/tcp: 127.0.0.1:11434 LISTEN, 0.0.0.0:8080 LISTEN, an ESTABLISHED row (01) to ignore.
const PROC_TCP = [
  "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
  "   0: 0100007F:2CAA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1",
  "   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22222 1",
  "   2: 0100007F:A028 0100007F:2CAA 01 00000000:00000000 00:00000000 00000000  1000        0 33333 1",
  ""
].join("\n");
// /proc/net/tcp6: [::1]:1337, [::]:8000, [::ffff:127.0.0.1]:4891, all LISTEN.
const PROC_TCP6 = [
  "  sl  local_address                         remote_address                        st",
  "   0: 00000000000000000000000001000000:0539 00000000000000000000000000000000:0000 0A 00000000:00000000",
  "   1: 00000000000000000000000000000000:1F40 00000000000000000000000000000000:0000 0A 00000000:00000000",
  "   2: 0000000000000000FFFF00000100007F:131B 00000000000000000000000000000000:0000 0A 00000000:00000000",
  ""
].join("\n");

const NETSTAT = [
  "",
  "Active Connections",
  "",
  "  Proto  Local Address          Foreign Address        State           PID",
  "  TCP    127.0.0.1:11434        0.0.0.0:0              LISTENING       4100",
  "  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       4200",
  "  TCP    [::1]:1234             [::]:0                 ABHÖREN         4300",
  "  TCP    [::]:4891              [::]:0                 LISTENING       4400",
  "  TCP    127.0.0.1:50000        127.0.0.1:11434        ESTABLISHED     9999",
  "  UDP    0.0.0.0:5353           *:*                                    4500",
  ""
].join("\r\n");

const at = (ls, port) => ls.filter((l) => l.port === port).map(({ proc, port: p, bind }) => ({ proc, port: p, bind }));

test("bind class: loopback forms vs network forms", () => {
  for (const h of ["127.0.0.1", "127.1.2.3", "[::1]", "::1", "::ffff:127.0.0.1", "[::ffff:127.0.0.1]", "127.0.0.53%lo", "localhost", "[fe80::1%lo0]"])
    assert.equal(bindOf(h), "loopback", h);
  for (const h of ["*", "0.0.0.0", "[::]", "::", "192.168.1.20", "[fe80::1%en0]", "10.0.0.5"])
    assert.equal(bindOf(h), "network", h);
});

test("lsof: LISTEN rows only, with pid, name, port and bind", () => {
  const l = parseLsof(LSOF);
  assert.equal(l.length, 5, "the ESTABLISHED row is not a listener");
  assert.deepEqual(l[0], { pid: "2463", proc: "ollama", port: 11434, bind: "loopback" });
  assert.deepEqual(at(l, 8080), [{ proc: "llama-server", port: 8080, bind: "network" }, { proc: "qwen3.5-0.8b-q8_", port: 8080, bind: "loopback" }]);
  assert.deepEqual(at(l, 1337), [{ proc: "jan", port: 1337, bind: "loopback" }]);
  assert.deepEqual(at(l, 5001), [{ proc: "koboldcpp-mac-a", port: 5001, bind: "network" }]);
});

test("ss: users:() names, v4-mapped and %lo loopback, unnamed rows kept, non-LISTEN dropped", () => {
  const l = parseSs(SS);
  assert.deepEqual(l.map(({ proc, port, bind, pid }) => [proc, port, bind, pid]), [
    ["ollama", 11434, "loopback", "812"],
    ["llama-server", 8080, "network", "900"],
    ["vllm", 8000, "network", "901"],
    ["lms", 1234, "loopback", "902"],
    ["", 53, "loopback", null],
    ["", 12434, "network", null]
  ]);
});

test("/proc/net/tcp and tcp6: little-endian hex decoded to port + loopback/network; state 0A only", () => {
  assert.deepEqual(parseProcNetTcp(PROC_TCP).map(({ port, bind }) => [port, bind]), [[11434, "loopback"], [8080, "network"]]);
  assert.deepEqual(parseProcNetTcp(PROC_TCP6).map(({ port, bind }) => [port, bind]), [[1337, "loopback"], [8000, "network"], [4891, "loopback"]]);
});

test("netstat: all-zero foreign address = listening; localized state word ignored; UDP ignored", () => {
  const l = parseNetstat(NETSTAT);
  assert.deepEqual(l.map(({ pid, port, bind }) => [pid, port, bind]), [["4100", 11434, "loopback"], ["4200", 8080, "network"], ["4300", 1234, "loopback"], ["4400", 4891, "network"]]);
});

test("ps with pids renames a listener by PID when the lsof command column is truncated", () => {
  const ps = parsePs("  7500 /Users/dev/models/Qwen3.5-0.8B-Q8_0.llamafile\n  2463 /opt/homebrew/bin/ollama\n");
  assert.equal(ps.byPid.get("7500"), "qwen3.5-0.8b-q8_0.llamafile");
  const runner = (cmd) => ({ lsof: LSOF, ps: "  7500 /Users/dev/models/Qwen3.5-0.8B-Q8_0.llamafile\n" })[cmd] ?? null;
  const { listeners } = probeSockets(runner, "darwin");
  assert.equal(listeners.find((l) => l.pid === "7500").proc, "qwen3.5-0.8b-q8_0.llamafile");
});

test("Linux fallback chain: lsof missing → ss; ss missing too → /proc/net/tcp{,6}; all missing → null", () => {
  const calls = [];
  const only = (outs) => (cmd, args) => { calls.push([cmd, ...args]); return outs[cmd] ?? null; };
  const viaSs = probeSockets(only({ ss: SS }), "linux", () => { throw new Error("no /proc"); });
  assert.equal(viaSs.source, "ss");
  assert.ok(viaSs.listeners.some((l) => l.proc === "llama-server" && l.bind === "network"));
  assert.deepEqual(calls.find((c) => c[0] === "ss"), ["ss", "-ltnp"]);
  const files = { "/proc/net/tcp": PROC_TCP, "/proc/net/tcp6": PROC_TCP6 };
  const viaProc = probeSockets(only({}), "linux", (p) => { if (p in files) return files[p]; throw new Error("ENOENT"); });
  assert.equal(viaProc.source, "proc");
  assert.equal(viaProc.listeners.length, 5);
  const none = probeSockets(only({}), "linux", () => { throw new Error("ENOENT"); });
  assert.equal(none.listeners, null, "unreadable sockets are null, never an empty 'nothing listens'");
  // macOS never falls back to ss or /proc
  const mac = probeSockets(only({ ss: SS }), "darwin", () => PROC_TCP);
  assert.equal(mac.listeners, null);
});

test("Windows: netstat joined to tasklist by PID; the process probe asks for names only", () => {
  const calls = [];
  const runner = (cmd, args) => { calls.push([cmd, ...args]); return { netstat: NETSTAT, tasklist: '"ollama.exe","4100","Console","1","45,000 K"\r\n"llama-server.exe","4200","Console","1","90,000 K"\r\n' }[cmd] ?? null; };
  const { listeners, processes } = probeSockets(runner, "win32");
  assert.deepEqual(at(listeners, 8080), [{ proc: "llama-server", port: 8080, bind: "network" }]);
  assert.deepEqual(at(listeners, 11434), [{ proc: "ollama", port: 11434, bind: "loopback" }]);
  assert.deepEqual(processes.sort(), ["llama-server", "ollama"]);
  assert.deepEqual(calls, [["netstat", "-ano"], ["tasklist", "/FO", "CSV", "/NH"]]);
});
