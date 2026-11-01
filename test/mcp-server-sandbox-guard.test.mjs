// mcpServerSandbox through the real stdio guard (mcp-proxy/moorai-mcp-guard.mjs).
//
// macOS (darwin only): the TEST-NET fixture server (test/fixtures/mcp-netprobe-server.mjs) tries to open a
// TCP connection to 192.0.2.1:443 — documentation space, never routed on the internet, so nothing outside
// this machine is contacted. With the sandbox off the connect is attempted (it times out or the network
// says unreachable); with mcpServerSandbox "network" and egressDefault "block" the kernel refuses it
// (EPERM). Loopback still connects under the sandbox.
//
// Every platform: with the guard believing it runs on Linux (test-only preload test/fixtures/fake-linux.mjs),
// "network" has no backend: fail mode closed never starts the server, open starts it unsandboxed with a
// High alert.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-server-sandbox-guard.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import net from "node:net";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const PROBE = join(ROOT, "test", "fixtures", "mcp-netprobe-server.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const FAKE_LINUX = join(ROOT, "test", "fixtures", "fake-linux.mjs");
const DARWIN = process.platform === "darwin" && existsSync("/usr/bin/sandbox-exec");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function consoleStub(t) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); return res.end("{}"); }
      res.writeHead(500); res.end("offline");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => srv.close(r)));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts };
}

// One guard run: write the (unsigned, unpinned-device) policy, send `lines`, collect answers by id.
async function drive(t, { url, policy, server, serverArgs = [], preload, lines, wait = 8000 }) {
  const home = mkdtempSync(join(tmpdir(), "moorai-sbx-guard-"));
  t.after(() => rmTree(home));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "sbx", installToken: "tok-sbx-guard" }));
  if (policy) writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
  const argv = [...(preload ? ["--import", preload] : []), GUARD, "--server", "sbxsrv", "--", process.execPath, server, ...serverArgs.map((a) => a.replace("$HOME", home))];
  const child = spawn(process.execPath, argv, { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home } });
  let stderr = "";
  child.stderr.on("data", (c) => (stderr += c));
  const exited = new Promise((r) => child.on("exit", (code) => r(code)));
  const byId = new Map();
  let buf = "";
  child.stdout.on("data", (c) => {
    buf += c.toString();
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
      try { const m = JSON.parse(line); if (m.id != null) byId.set(m.id, m); } catch { /* ignore */ }
    }
  });
  for (const l of lines) child.stdin.write(l + "\n");
  const end = Date.now() + wait;
  let code;
  let gone = false;
  exited.then((c) => { code = c; gone = true; });
  while (byId.size < lines.length && !gone && Date.now() < end) await sleep(25);
  try { child.stdin.end(); } catch { /* ignore */ }
  const timer = setTimeout(() => { try { child.kill(); } catch { /* ignore */ } }, 5000);
  code = await exited;
  clearTimeout(timer);
  return { byId, code, stderr, home };
}

const init = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "0" } } });
const probeCall = (id, args = {}) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "probe", arguments: args } });
const text = (m) => String(m && m.result && m.result.content && m.result.content[0] && m.result.content[0].text);
async function until(fn, ms = 5000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(50); } return false; }

test("darwin: sandbox off, the server's connect to TEST-NET 192.0.2.1 is attempted", { skip: !DARWIN && "macOS with /usr/bin/sandbox-exec only" }, async (t) => {
  const c = await consoleStub(t);
  const r = await drive(t, { url: c.url, policy: { egressDefault: "block" }, server: PROBE, lines: [init, probeCall(2)] });
  const out = text(r.byId.get(2));
  process.stdout.write(`# sandbox off: ${out}\n`);
  assert.match(out, /^connect:/);
  assert.notEqual(out, "connect:EPERM");
  assert.doesNotMatch(r.stderr, /network sandbox/);
});

test("darwin: mcpServerSandbox network + egressDefault block, the kernel refuses it (EPERM); loopback still connects", { skip: !DARWIN && "macOS with /usr/bin/sandbox-exec only" }, async (t) => {
  const c = await consoleStub(t);
  const lo = net.createServer((s) => s.end());
  await new Promise((r) => lo.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => lo.close(r)));
  const policy = { mcpServerSandbox: "network", egressDefault: "block", egressRules: [{ id: "gh", host: "api.github.com", action: "allow" }] };
  const r = await drive(t, { url: c.url, policy, server: PROBE, lines: [init, probeCall(2), probeCall(3, { host: "127.0.0.1", port: lo.address().port })] });
  const out = text(r.byId.get(2)), loop = text(r.byId.get(3));
  process.stdout.write(`# sandbox on: TEST-NET ${out}; loopback ${loop}\n`);
  assert.equal(out, "connect:EPERM");
  assert.equal(loop, "connect:ok");
  assert.match(r.stderr, /runs under the macOS network sandbox/);
  assert.match(r.stderr, /egress rule not expressed in the sandbox: .*"id":"gh".*"effect":"omitted"/);
  assert.ok(await until(() => c.alerts.some((a) => a.category === "Containment: MCP server sandbox rules not expressed")), "the unexpressed rule is alerted");
  const a = c.alerts.find((x) => x.category === "Containment: MCP server sandbox rules not expressed");
  assert.equal(a.mcpServer, "sbxsrv");
  assert.equal(JSON.stringify(a).includes("github"), false);
});

test("darwin: network + block also cuts DNS (a public name does not resolve), keeps localhost resolving and loopback connecting, refuses exec of open / osascript", { skip: !DARWIN && "macOS with /usr/bin/sandbox-exec only" }, async (t) => {
  const c = await consoleStub(t);
  const lo = net.createServer((s) => s.end());
  await new Promise((r) => lo.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => lo.close(r)));
  const call = (id, name, args) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
  const r = await drive(t, {
    url: c.url, policy: { mcpServerSandbox: "network", egressDefault: "block" }, server: PROBE,
    lines: [init, call(2, "lookup", { name: "example.com" }), call(3, "lookup", { name: "localhost" }), probeCall(4, { host: "127.0.0.1", port: lo.address().port }),
      call(5, "exec", { cmd: "/usr/bin/open", args: ["-h"] }), call(6, "exec", { cmd: "/usr/bin/osascript", args: ["-e", "return 1"] })]
  });
  const got = [2, 3, 4, 5, 6].map((id) => text(r.byId.get(id)));
  process.stdout.write(`# sandbox on: example.com ${got[0]}; localhost ${got[1]}; loopback ${got[2]}; open ${got[3]}; osascript ${got[4]}\n`);
  assert.equal(got[0], "lookup:ENOTFOUND");
  assert.match(got[1], /^lookup:(4|6)$/);
  assert.equal(got[2], "connect:ok");
  assert.equal(got[3], "exec:EPERM");
  assert.equal(got[4], "exec:EPERM");
  assert.match(r.stderr, /not full containment/);
});

test("no backend (Linux), fail mode closed: the real server is never started, the guard exits 1, a Blocked alert", async (t) => {
  const c = await consoleStub(t);
  const policy = { mcpServerSandbox: "network", egressDefault: "block", failMode: { mcpGateway: "closed" } };
  const r = await drive(t, { url: c.url, policy, server: FAKE, serverArgs: ["$HOME/recv.log"], preload: FAKE_LINUX, lines: [init, JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { msg: "x" } } })] });
  assert.equal(r.code, 1);
  assert.equal(r.byId.size, 0, "nothing answered: there is no server");
  assert.equal(existsSync(join(r.home, "recv.log")), false, "the real server never ran");
  assert.match(r.stderr, /was not started: mcpServerSandbox is "network"/);
  assert.ok(await until(() => c.alerts.some((a) => a.category === "Containment: MCP server sandbox unavailable")), "the refusal is alerted");
  const a = c.alerts.find((x) => x.category === "Containment: MCP server sandbox unavailable");
  assert.equal(a.riskLevel, "Blocked");
  assert.equal(a.decision, "deny");
  assert.equal(a.reasonCode, "CONTAINMENT_UNAVAILABLE");
  assert.equal(a.failModeSource, "policy");
});

test("no backend (Linux), fail mode open: the server starts unsandboxed with a High alert and a stderr line", async (t) => {
  const c = await consoleStub(t);
  const policy = { mcpServerSandbox: "network", egressDefault: "block" };
  const r = await drive(t, { url: c.url, policy, server: FAKE, serverArgs: ["$HOME/recv.log"], preload: FAKE_LINUX, lines: [init, JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { msg: "x" } } })] });
  assert.ok(r.byId.get(2) && r.byId.get(2).result, "the server answered");
  assert.match(readFileSync(join(r.home, "recv.log"), "utf8"), /"msg":"x"/);
  assert.match(r.stderr, /runs UNSANDBOXED/);
  assert.ok(await until(() => c.alerts.some((a) => a.category === "Containment: MCP server sandbox unavailable")));
  const a = c.alerts.find((x) => x.category === "Containment: MCP server sandbox unavailable");
  assert.equal(a.riskLevel, "High");
  assert.equal(a.failMode, "open");
});

test("off (no key): no sandbox note, no sandbox alert, the server answers", async (t) => {
  const c = await consoleStub(t);
  const r = await drive(t, { url: c.url, policy: { egressDefault: "block", failMode: { mcpGateway: "closed" } }, server: FAKE, serverArgs: ["$HOME/recv.log"], preload: FAKE_LINUX, lines: [init] });
  assert.ok(r.byId.get(1) && r.byId.get(1).result);
  assert.doesNotMatch(r.stderr, /sandbox/i);
  await sleep(300);
  assert.equal(c.alerts.some((a) => /sandbox/i.test(a.category)), false);
});

// The coverage heartbeat (cli/moorai-hook.mjs posturebeat → POST /api/agent-posture) carries the effective
// mode and whether the guard can apply it here, from static prerequisites only.
for (const [label, policy, expect] of [
  ["network", { captureTier: "content-free", mcpServerSandbox: "network" }, { mode: "network", state: DARWIN ? "on" : "unavailable" }],
  ["no key", { captureTier: "content-free" }, { mode: "off", state: "off" }]
]) {
  test(`heartbeat carries mcpServerSandbox: ${label}`, async (t) => {
    const posts = [];
    const srv = http.createServer((req, res) => {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => { if (req.url === "/api/agent-posture") { posts.push(JSON.parse(b)); res.writeHead(201); return res.end("{}"); } res.writeHead(404); res.end("{}"); });
    });
    await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    t.after(() => srv.close());
    const { makeSandbox } = await import("../cli/doctor-sandbox.mjs");
    const empty = mkdtempSync(join(tmpdir(), "moorai-sbx-beat-"));
    const sb = makeSandbox({ realHome: empty, config: { serverUrl: `http://127.0.0.1:${srv.address().port}`, tenant: "acme", installToken: "tok-sbx" } });
    t.after(() => { sb.cleanup(); rmTree(empty); });
    writeFileSync(join(sb.home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
    const { spawnSync } = await import("node:child_process");
    const r = spawnSync(process.execPath, [join(ROOT, "cli", "moorai-hook.mjs")], {
      input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls -la" }, session_id: "s-1", cwd: sb.proj }),
      env: sb.env(), encoding: "utf8", timeout: 20000
    });
    assert.equal(r.status, 0);
    assert.ok(await until(() => posts.length === 1, 10000), "heartbeat posted");
    assert.deepEqual(posts[0].mcpServerSandbox, expect);
  });
}
