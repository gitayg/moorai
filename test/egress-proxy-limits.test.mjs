// moorai-egress-proxy: the hardening. Proxy-Authorization with a token, the loopback-only bind without one,
// the connection cap, header / idle / DNS / connect timeouts, and the real entrypoint end to end.
//
//   node --test --import ./test/hermetic-env.mjs test/egress-proxy-limits.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { startUpstream, startEcho, fakeResolver, fakeConnect, startProxy, stateOf, viaProxy, connectVia, echoOnce } from "../egress-proxy/test/harness.mjs";
import { parseConfig } from "../egress-proxy/config.mjs";

const ENTRY = join(dirname(fileURLToPath(import.meta.url)), "..", "egress-proxy", "moorai-egress-proxy.mjs");
const PUBLIC = "93.184.216.34";
const TOKEN = "0123456789abcdef0123";
let up, echo;
before(async () => { up = await startUpstream(); echo = await startEcho(); });
after(async () => { await up.close(); await echo.close(); });

const deps = (extra = {}) => ({ getState: stateOf({ egressDefault: "allow" }), resolve: fakeResolver({ "ok.example": [PUBLIC] }), connect: fakeConnect({ httpPort: up.port, echoPort: echo.port }), ...extra });
const basic = (user, pass) => `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}`;

// Resolves when the socket closes; rejects past `ms`.
const closedWithin = (sock, ms) => new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error(`still open after ${ms} ms`)), ms);
  sock.on("close", () => { clearTimeout(t); resolve(); });
  sock.on("error", () => {});
  sock.resume(); // a paused socket never reaches "close" after the peer's FIN
});

test("auth: with a token, Proxy-Authorization (Basic password or Bearer) is required for HTTP and CONNECT", async () => {
  const p = await startProxy({ token: TOKEN }, deps());
  try {
    const none = await viaProxy(p.port, "http://ok.example/");
    assert.equal(none.status, 407);
    assert.match(none.headers["proxy-authenticate"], /^Basic realm=/);
    assert.equal((await viaProxy(p.port, "http://ok.example/", { headers: { "proxy-authorization": basic("moorai", "wrong-token-wrong-token") } })).status, 407);
    assert.equal((await viaProxy(p.port, "http://ok.example/", { headers: { "proxy-authorization": basic("moorai", TOKEN) } })).status, 200);
    assert.equal((await viaProxy(p.port, "http://ok.example/", { headers: { "proxy-authorization": `Bearer ${TOKEN}` } })).status, 200);
    assert.equal((await connectVia(p.port, "ok.example:443")).status, 407);
    const c = await connectVia(p.port, "ok.example:443", { "proxy-authorization": basic("x", TOKEN) });
    assert.equal(c.status, 200);
    c.socket.destroy();
    assert.equal((await viaProxy(p.port, "/healthz")).status, 200, "the health check needs no token");
  } finally { await p.close(); }
});

test("config: loopback by default; a non-loopback bind needs --allow-remote AND a token of 16+ characters", () => {
  assert.equal(parseConfig([], {}).host, "127.0.0.1");
  assert.throws(() => parseConfig(["--host", "0.0.0.0"], {}), /needs --allow-remote/);
  assert.throws(() => parseConfig(["--host", "0.0.0.0", "--allow-remote"], {}), /needs a proxy token/);
  assert.throws(() => parseConfig(["--host", "0.0.0.0", "--allow-remote"], { MOORAI_EGRESS_PROXY_TOKEN: "short" }), /at least 16/);
  const ok = parseConfig(["--host", "0.0.0.0", "--allow-remote"], { MOORAI_EGRESS_PROXY_TOKEN: TOKEN });
  assert.equal(ok.token, TOKEN);
  assert.equal(parseConfig(["--host", "0.0.0.0", "--allow-remote", "--token-file", "/t"], {}, () => `${TOKEN}\n`).token, TOKEN);
  assert.throws(() => parseConfig(["--max-connections", "0"], {}), /whole number/);
  assert.throws(() => parseConfig(["--egress-default", "allow"], {}), /unknown argument/, "no flag sets policy");
  const r = spawnSync(process.execPath, [ENTRY, "--host", "0.0.0.0"], { encoding: "utf8", env: { ...process.env, MOORAI_EGRESS_PROXY_TOKEN: "" } });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /refusing to bind 0\.0\.0\.0/);
});

test("limits: past --max-connections a new client connection is dropped", async () => {
  const p = await startProxy({ maxConnections: 2 }, deps());
  const held = [];
  try {
    for (let i = 0; i < 2; i++) { const s = net.connect(p.port, "127.0.0.1"); s.on("error", () => {}); await new Promise((r) => s.once("connect", r)); held.push(s); }
    await new Promise((r) => setTimeout(r, 50));
    const third = net.connect(p.port, "127.0.0.1");
    let data = "";
    third.on("data", (c) => (data += c));
    third.write("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
    await closedWithin(third, 2000);
    assert.equal(data, "", "the dropped connection got no answer");
    held[0].destroy();
    await new Promise((r) => setTimeout(r, 50));
    assert.equal((await viaProxy(p.port, "/healthz")).status, 200, "a freed slot is usable again");
  } finally { for (const s of held) s.destroy(); await p.close(); }
});

test("limits: a client that never finishes its headers is cut off at --headers-timeout-ms", async () => {
  const p = await startProxy({ headersTimeoutMs: 300 }, deps());
  try {
    const s = net.connect(p.port, "127.0.0.1");
    await new Promise((r) => s.once("connect", r));
    s.write("GET http://ok.example/ HTTP/1.1\r\nHost: ok.example\r\n");
    let data = "";
    s.on("data", (c) => (data += c));
    await closedWithin(s, 3000);
    assert.match(data, /^HTTP\/1\.1 408 /);
  } finally { await p.close(); }
});

test("limits: an idle tunnel is closed at --idle-timeout-ms; a busy one is not", async () => {
  const p = await startProxy({ idleTimeoutMs: 400 }, deps());
  try {
    const busy = await connectVia(p.port, "ok.example:443");
    assert.equal(busy.status, 200);
    for (let i = 0; i < 4; i++) { await new Promise((r) => setTimeout(r, 200)); assert.equal(await echoOnce(busy.socket, `b${i}`), `b${i}`); busy.socket.removeAllListeners("data"); }
    const idle = await connectVia(p.port, "ok.example:443");
    assert.equal(idle.status, 200);
    await closedWithin(idle.socket, 3000);
    busy.socket.destroy();
  } finally { await p.close(); }
});

test("limits: DNS and the upstream connect are bounded by their timeouts", async () => {
  const hang = await startProxy({ dnsTimeoutMs: 200 }, deps({ resolve: () => new Promise(() => {}) }));
  try { assert.equal((await viaProxy(hang.port, "http://ok.example/")).status, 504); } finally { await hang.close(); }
  const neverConnects = () => new net.Socket();
  const slow = await startProxy({ connectTimeoutMs: 200 }, deps({ connect: neverConnects }));
  try {
    assert.equal((await viaProxy(slow.port, "http://ok.example/")).status, 504);
    assert.equal((await connectVia(slow.port, "ok.example:443")).status, 504);
  } finally { await slow.close(); }
});

test("entrypoint: the real binary starts on loopback, answers /healthz, and with no policy still refuses loopback and IP literals", async () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-egress-h-"));
  const env = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: "http://127.0.0.1:9", MOORAI_EGRESS_PROXY_TOKEN: "" };
  delete env.MOORAI_MODE;
  const child = spawn(process.execPath, [ENTRY, "--port", "0"], { env, stdio: ["ignore", "pipe", "pipe"] });
  try {
    const port = await new Promise((resolve, reject) => {
      let err = "";
      const t = setTimeout(() => reject(new Error(`no listening line: ${err}`)), 10000);
      child.stderr.on("data", (c) => { err += c; const m = /listening on http:\/\/127\.0\.0\.1:(\d+)/.exec(err); if (m) { clearTimeout(t); resolve(Number(m[1])); } });
    });
    assert.equal((await viaProxy(port, "/healthz")).status, 200);
    assert.equal((await viaProxy(port, `http://localhost:${up.port}/`)).status, 403);
    assert.equal((await viaProxy(port, `http://127.0.0.1:${up.port}/`)).status, 403);
    assert.equal((await connectVia(port, `127.0.0.1:${echo.port}`)).status, 403);
  } finally { child.kill(); rmSync(home, { recursive: true, force: true }); }
});
