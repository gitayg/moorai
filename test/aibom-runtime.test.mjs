// RUNNING local model servers and local HTTP/SSE MCP servers. The AIBOM already lists model FOLDERS;
// this pins the "is it actually serving right now?" layer: listeners on known local-inference ports
// and known process names, read from the OS's standard tools (lsof/ps, netstat/tasklist). The command
// runner is INJECTED so nothing here depends on what happens to be running on the test machine.
//
// Content-free: process NAMES and PORTS only. The process probe asks the OS for the command name
// (`ps -o comm=`), never the argument vector or environment, which can carry secrets.
//
//   node --test test/aibom-runtime.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { probeListeners, probeProcesses, localRuntimes, localMcpListeners } from "../cli/aibom-runtime.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const AIBOM = join(ROOT, "cli", "moorai-aibom.mjs");
const SHADOW = join(ROOT, "cli", "moorai-shadow.mjs");

// Captured shape of `lsof +c 0 -iTCP -sTCP:LISTEN -nP` on macOS (header + rows; spaces in a command
// name are escaped as \x20 by lsof).
const LSOF = [
  "COMMAND                       PID       USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME",
  "ollama                      64889 dev    4u  IPv4 0xd74f2b7e8dff72c6      0t0  TCP 127.0.0.1:11434 (LISTEN)",
  "LM\\x20Studio                 7001 dev   40u  IPv4 0x0000000000000001      0t0  TCP 127.0.0.1:1234 (LISTEN)",
  "llama-server                7100 dev    3u  IPv4 0x0000000000000002      0t0  TCP *:8080 (LISTEN)",
  "node                        7200 dev   17u  IPv6 0x0000000000000003      0t0  TCP [::1]:8000 (LISTEN)",
  "node                        7201 dev   18u  IPv4 0x0000000000000004      0t0  TCP 127.0.0.1:3333 (LISTEN)",
  ""
].join("\n");
const PS = [
  "/Applications/Ollama.app/Contents/Resources/ollama",
  "/Applications/LM Studio.app/Contents/MacOS/LM Studio",
  "/usr/local/bin/llama-server",
  "/usr/local/bin/node",
  "/bin/zsh",
  ""
].join("\n");
// `netstat -ano` and `tasklist /FO CSV /NH` on Windows. Listening rows are recognised by the all-zero
// foreign address, not the (localised) state word.
const NETSTAT = [
  "",
  "Active Connections",
  "",
  "  Proto  Local Address          Foreign Address        State           PID",
  "  TCP    127.0.0.1:11434        0.0.0.0:0              LISTENING       4100",
  "  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       4200",
  "  TCP    [::1]:1234             [::]:0                 ABHÖREN         4300",
  "  TCP    127.0.0.1:50000        127.0.0.1:11434        ESTABLISHED     9999",
  "  UDP    0.0.0.0:5353           *:*                                    4400",
  ""
].join("\r\n");
const TASKLIST = [
  '"ollama.exe","4100","Console","1","45,000 K"',
  '"llama-server.exe","4200","Console","1","90,000 K"',
  '"LM Studio.exe","4300","Console","1","300,000 K"',
  '"svchost.exe","4400","Services","0","9,000 K"',
  ""
].join("\r\n");

function recordingRunner(outputs) {
  const calls = [];
  const fn = (cmd, args) => { calls.push([cmd, ...args]); return outputs[cmd] ?? null; };
  fn.calls = calls;
  return fn;
}

test("POSIX: lsof listeners are parsed to {proc, port, bind}; names decoded", () => {
  const r = recordingRunner({ lsof: LSOF });
  const l = probeListeners(r, "darwin");
  assert.deepEqual(l.find((x) => x.port === 11434), { proc: "ollama", port: 11434, bind: "loopback" });
  assert.deepEqual(l.find((x) => x.port === 1234), { proc: "lm studio", port: 1234, bind: "loopback" });
  assert.deepEqual(l.find((x) => x.port === 8080), { proc: "llama-server", port: 8080, bind: "network" });
  assert.deepEqual(l.find((x) => x.port === 8000), { proc: "node", port: 8000, bind: "loopback" });
});

test("POSIX: the process probe asks for the command NAME only — never args or environment", () => {
  const r = recordingRunner({ ps: PS });
  const names = probeProcesses(r, "darwin");
  assert.ok(names.includes("ollama") && names.includes("lm studio") && names.includes("llama-server"));
  const psCall = r.calls.find((c) => c[0] === "ps");
  assert.deepEqual(psCall, ["ps", "-A", "-o", "comm="]);
});

test("runtimes: process + distinctive port; generic ports need the process name", () => {
  const listeners = probeListeners(recordingRunner({ lsof: LSOF }), "darwin");
  const processes = probeProcesses(recordingRunner({ ps: PS }), "darwin");
  const rt = localRuntimes({ listeners, processes });
  const by = Object.fromEntries(rt.map((x) => [x.runtime, x]));
  assert.deepEqual(by.ollama, { runtime: "ollama", running: true, ports: [11434], bind: "loopback", detectedBy: ["process", "port"] });
  assert.deepEqual(by.lmstudio, { runtime: "lmstudio", running: true, ports: [1234], bind: "loopback", detectedBy: ["process"] });
  assert.deepEqual(by["llama.cpp"], { runtime: "llama.cpp", running: true, ports: [8080], bind: "network", detectedBy: ["process"] });
  assert.equal(by.vllm, undefined, "a node dev server on :8000 is NOT vLLM");
  assert.equal(rt.length, 3);
});

test("runtimes: a listener on Ollama's documented default port counts even under another process name", () => {
  const listeners = [{ proc: "com.docker.backend", port: 11434, bind: "loopback" }];
  assert.deepEqual(localRuntimes({ listeners, processes: [] }),
    [{ runtime: "ollama", running: true, ports: [11434], bind: "loopback", detectedBy: ["port"] }]);
  // …but a generic default port alone never does
  assert.deepEqual(localRuntimes({ listeners: [{ proc: "python3", port: 8000, bind: "loopback" }], processes: ["python3"] }), []);
});

test("Windows: netstat + tasklist are joined by PID; localized state word is irrelevant", () => {
  const r = recordingRunner({ netstat: NETSTAT, tasklist: TASKLIST });
  const listeners = probeListeners(r, "win32");
  assert.deepEqual(listeners.find((x) => x.port === 11434), { proc: "ollama", port: 11434, bind: "loopback" });
  assert.deepEqual(listeners.find((x) => x.port === 1234), { proc: "lm studio", port: 1234, bind: "loopback" });
  assert.ok(!listeners.some((x) => x.port === 50000), "established connection is not a listener");
  assert.ok(!listeners.some((x) => x.port === 5353), "UDP ignored");
  const processes = probeProcesses(r, "win32");
  const rt = localRuntimes({ listeners, processes });
  assert.deepEqual(rt.map((x) => x.runtime).sort(), ["llama.cpp", "lmstudio", "ollama"]);
  assert.equal(rt.find((x) => x.runtime === "llama.cpp").bind, "network");
  for (const c of r.calls) assert.ok(!c.some((a) => /\/v\b|\/verbose|-o\b.*args/i.test(a)), `no verbose/args flags: ${c}`);
});

test("fail-open: a missing/failed tool yields null listeners and no runtimes, never a throw", () => {
  const r = recordingRunner({});
  assert.equal(probeListeners(r, "darwin"), null);
  assert.equal(probeProcesses(r, "darwin"), null);
  assert.deepEqual(localRuntimes({ listeners: null, processes: null }), []);
});

test("local MCP over HTTP/SSE: declared localhost URL ports are matched to listeners", () => {
  const decls = [
    { name: "local-http", scope: "claude", url: "http://localhost:3333/mcp", type: "http" },
    { name: "local-sse", scope: "cursor", url: "http://127.0.0.1:4444/sse" },
    { name: "remote", scope: "claude", url: "https://mcp.example.com/mcp", type: "http" },
    { name: "stdio-one", scope: "claude" },
    { name: "bad-url", scope: "claude", url: "not a url" }
  ];
  const listeners = [{ proc: "node", port: 3333, bind: "loopback" }];
  assert.deepEqual(localMcpListeners(decls, listeners), [
    { name: "local-http", scope: "claude", transport: "http", port: 3333, running: true },
    { name: "local-sse", scope: "cursor", transport: "sse", port: 4444, running: false }
  ]);
  // probe unavailable → unknown, never a false "not running"
  assert.deepEqual(localMcpListeners(decls, null).map((x) => x.running), [null, null]);
});

test("CLI end-to-end: running runtimes + local MCP listeners reach the AIBOM and the shadow report", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-runtime-"));
  try {
    writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: {
      "local-http": { type: "http", url: "http://localhost:3333/mcp?token=SECRETMCPTOKEN", headers: { Authorization: "Bearer SECRETHEADER" } },
      "local-sse": { type: "sse", url: "http://127.0.0.1:4444/sse" }
    } }));
    mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: "http://localhost:1", tenant: "t", sanctioned: { runtimes: ["ollama"] } }));
    const fixture = join(home, "probe.json");
    writeFileSync(fixture, JSON.stringify({ lsof: LSOF, ps: PS, netstat: NETSTAT, tasklist: TASKLIST }));
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_AIBOM_PROBE_FIXTURE: fixture };
    delete env.MOORAI_SANCTIONED; delete env.MOORAI_AIBOM_JSON;

    const out = execFileSync(process.execPath, [AIBOM], { env, encoding: "utf8" });
    const d = JSON.parse(out);
    assert.ok(d.localRuntimes.some((x) => x.runtime === "ollama" && x.running && x.ports.includes(11434)));
    assert.deepEqual(d.localMcpListeners.find((x) => x.name === "local-http"), { name: "local-http", scope: "claude", transport: "http", port: 3333, running: true });
    assert.deepEqual(d.localMcpListeners.find((x) => x.name === "local-sse"), { name: "local-sse", scope: "claude", transport: "sse", port: 4444, running: false });
    assert.equal(d.summary.runningLocalRuntimes, d.localRuntimes.length);
    assert.equal(d.summary.localMcpRunning, 1);
    for (const s of ["SECRETMCPTOKEN", "SECRETHEADER", "Bearer"]) assert.ok(!out.includes(s), `${s} leaked`);
    const md = execFileSync(process.execPath, [AIBOM, "--format", "md"], { env, encoding: "utf8" });
    assert.match(md, /Running local model servers/);
    assert.ok(!md.includes("SECRETMCPTOKEN"));

    const sh = JSON.parse(execFileSync(process.execPath, [SHADOW, "--json"], { env, encoding: "utf8" }));
    const rts = sh.shadow.filter((x) => x.kind === "local-runtime").map((x) => x.name).sort();
    assert.ok(!rts.includes("ollama"), "sanctioned runtime excluded");
    assert.ok(rts.includes("lmstudio") && rts.includes("llama.cpp"));
    assert.equal(sh.shadow.find((x) => x.name === "llama.cpp").risk, "high", "network-bound unapproved runtime ranks high");
    const mcp = sh.shadow.find((x) => x.kind === "mcp-server" && x.name === "local-http");
    assert.equal(mcp.running, true);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
