// Placeholder credentials in moorai-mcp-gateway (cfg.credentials → ../model-proxy/credentials.mjs and
// credential-mask.mjs), end to end: a real gateway process, an in-test remote MCP server that records and
// echoes what it receives, and a fake console. The "secrets" are test strings that exist only in this file.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-gateway-credentials.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { spawnSync } from "node:child_process";
import { writeFileSync, chmodSync, rmSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { startConsole, makeHome, startGateway, stopGateway, GATEWAY, H, call, settle } from "../mcp-gateway/test/harness.mjs";

const SECRET = "FAKE-mcp-secret-0123456789abcdefGHIJ";
const SECRET_K = "FAKE-mcp-apikey-zyxwvu9876543210";
const PH = "moorai-ph:mcp-test";
const PH_K = "moorai-ph:mcp-key";
const RAW = "Bearer gho_FAKE-raw-oauth-token-000111222";
const POSIX = process.platform !== "win32";

// A remote MCP server: `reply(rec, res)` answers; default a valid tools/call result naming the call.
async function startRemote() {
  const received = [];
  let reply = null;
  const server = http.createServer((req, res) => {
    let body = ""; req.setEncoding("utf8");
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const rec = { method: req.method, url: req.url, headers: req.headers, body, json: (() => { try { return JSON.parse(body); } catch { return null; } })() };
      received.push(rec);
      if (reply) return reply(rec, res);
      if (req.method !== "POST") { res.writeHead(req.method === "GET" ? 405 : 200); return res.end(); }
      const m = rec.json;
      if (!m || m.id == null) { res.writeHead(202); return res.end(); }
      const result = m.method === "tools/call" ? { content: [{ type: "text", text: "done" }], isError: false } : m.method === "initialize" ? { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "remote", version: "1" } } : {};
      const out = JSON.stringify({ jsonrpc: "2.0", id: m.id, result });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(out) }); res.end(out);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}/mcp`, received, on(fn) { reply = fn; }, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}
const result = (id, text) => JSON.stringify({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text }], isError: false } });
const echoed = (rec) => String(rec.headers.authorization || rec.headers["x-api-key"] || "");

let con, home, up, credFile, secretFile, gw, gwReq;
const childEnv = { FAKE_MCP_SECRET: SECRET };
const bindings = () => ({
  [PH]: { secret: { env: "FAKE_MCP_SECRET" }, route: "/remote", upstream: up.url, header: "authorization", scheme: "Bearer" },
  [PH_K]: { secret: { file: secretFile }, route: "/remote", upstream: up.url, header: "x-api-key" }
});
function writeBindings(path, b, mode = 0o600) { writeFileSync(path, JSON.stringify({ bindings: b }), { mode }); chmodSync(path, mode); }
const routeArgs = () => ["--port", "0", "--route", `/remote=${up.url}`, "--route", `/other=${up.url}`];

before(async () => {
  con = await startConsole(null);
  home = makeHome(con.url);
  up = await startRemote();
  credFile = join(home, "credentials.json");
  secretFile = join(home, "mcp.secret");
  writeFileSync(secretFile, SECRET_K, { mode: 0o600 }); chmodSync(secretFile, 0o600);
  writeBindings(credFile, bindings());
  gw = await startGateway({ home, consoleUrl: con.url, args: [...routeArgs(), "--credentials", credFile], env: childEnv });
  gwReq = await startGateway({ home, consoleUrl: con.url, args: routeArgs(), env: { ...childEnv, MOORAI_GATEWAY_CREDENTIALS: credFile } });
  if (!gw.url || !gwReq.url) throw new Error(`gateway did not start: ${gw.stderr} ${gwReq.stderr}`);
});
// Defensive: a before() that failed half-way must not leave servers open and hang the run.
after(async () => { await stopGateway(gw); await stopGateway(gwReq); await up?.close(); await con?.close(); if (home) rmSync(home, { recursive: true, force: true }); });

async function post(base, msg, headers = {}, method = "POST") {
  const r = await fetch(base, { method, headers: { ...H, ...headers }, body: method === "POST" ? JSON.stringify(msg) : undefined, redirect: "manual" });
  const raw = Buffer.from(await r.arrayBuffer());
  const hdrs = Object.fromEntries(r.headers);
  return { status: r.status, statusText: r.statusText, headers: hdrs, raw, text: raw.toString("utf8"), json: (() => { try { return JSON.parse(raw.toString("utf8")); } catch { return null; } })(), visible: `${r.status} ${r.statusText} ${JSON.stringify(hdrs)} ${raw.toString("latin1")}` };
}
// The listen-time lines after "listening on" can arrive in a later stderr chunk (pipes are async on macOS).
async function stderrMatch(g, re) { for (let i = 0; i < 80 && !re.test(g.stderr); i++) await settle(25); return g.stderr; }
const noSecret = (text, where) => { for (const s of [SECRET, SECRET_K]) assert.ok(!String(text).includes(s), `${where} carries a bound secret`); };

test("startup: the placeholders are listed by name only; MOORAI_GATEWAY_CREDENTIALS loads the same file", async () => {
  assert.match(await stderrMatch(gw, /mcp-key/), /credential placeholder moorai-ph:mcp-test -> \/remote header authorization/);
  assert.match(await stderrMatch(gwReq, /mcp-key/), /credential placeholder moorai-ph:mcp-key -> \/remote header x-api-key/, "MOORAI_GATEWAY_CREDENTIALS loads it too");
  noSecret(gw.stderr + gwReq.stderr, "the startup log");
});

test("swap: the bound secret reaches the remote server on every method (POST, GET stream, DELETE), in the bound header with its scheme", async () => {
  up.on(null);
  const n = up.received.length;
  const r = await post(`${gw.url}/remote`, call(1, "echo", { a: 1 }), { authorization: `Bearer ${PH}`, "mcp-session-id": "s1" });
  assert.equal(r.status, 200); assert.equal(r.json.result.content[0].text, "done");
  assert.equal(up.received[n].headers.authorization, `Bearer ${SECRET}`);
  assert.equal(up.received[n].headers["mcp-session-id"], "s1");
  await post(`${gw.url}/remote`, null, { "x-api-key": PH_K }, "GET");
  assert.equal(up.received.at(-1).method, "GET"); assert.equal(up.received.at(-1).headers["x-api-key"], SECRET_K);
  await post(`${gw.url}/remote`, null, { authorization: `bearer ${PH}` }, "DELETE");
  assert.equal(up.received.at(-1).method, "DELETE"); assert.equal(up.received.at(-1).headers.authorization, `Bearer ${SECRET}`, "the binding's scheme spelling goes upstream");
});

test("refused, never forwarded: wrong route (same remote URL), unknown placeholder, wrong header, placeholder in the URL, case-variant duplicates", async () => {
  up.on(null);
  const n = up.received.length;
  const other = await post(`${gw.url}/other`, call(2, "echo"), { authorization: `Bearer ${PH}` });
  assert.equal(other.status, 403); assert.match(other.json.error.message, /not bound to this route/);
  const unknown = await post(`${gw.url}/remote`, call(3, "echo"), { authorization: "Bearer moorai-ph:nope" });
  assert.equal(unknown.status, 401); assert.match(unknown.json.error.message, /unknown or malformed credential placeholder/);
  const header = await post(`${gw.url}/remote`, call(4, "echo"), { "x-api-key": PH });
  assert.equal(header.status, 403); assert.match(header.json.error.message, /not bound to this header/);
  const query = await post(`${gw.url}/remote?token=${encodeURIComponent(PH)}`, call(5, "echo"), { authorization: `Bearer ${PH}` });
  assert.equal(query.status, 400);
  for (const r of [other, unknown, header, query]) { noSecret(r.visible, "a refusal"); assert.equal(r.json.jsonrpc, "2.0"); }
  // two spellings of Authorization: Node keeps the first and drops the second silently; refused instead
  const body = JSON.stringify(call(6, "echo"));
  const dup = await new Promise((res, rej) => {
    const u = new URL(gw.url);
    const s = net.connect(Number(u.port), u.hostname, () => s.write(`POST /remote HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: ${body.length}\r\nConnection: close\r\nAuthorization: Bearer ${PH}\r\nauthorization: ${RAW}\r\n\r\n${body}`));
    let out = ""; s.on("data", (d) => (out += d)); s.on("end", () => res(out)); s.on("error", rej);
  });
  assert.match(dup, /^HTTP\/1\.1 400 /); assert.match(dup, /appears more than once/);
  assert.equal(up.received.length, n, "nothing reached the remote server");
});

test("a remote server that echoes the secret: masked in the JSON result, an SSE result split in 3-byte slices, a header, the status line, an error body, a gzip body", async () => {
  const sendJsonish = (res, status, text, headers = {}, statusMessage) => { res.writeHead(status, statusMessage, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text), ...headers }); res.end(text); };
  const cases = [
    ["json", (rec, res) => sendJsonish(res, 200, result(rec.json.id, `you sent ${echoed(rec)}`), { "x-echo": echoed(rec), "set-cookie": [`t=${echoed(rec)}`] }, `OK ${echoed(rec)}`)],
    ["sse", (rec, res) => {
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      const out = Buffer.from(`id: e1\nevent: message\ndata: ${result(rec.json.id, `token=${echoed(rec)} again ${echoed(rec)}`)}\n\n`);
      let i = 0; const step = () => { if (i >= out.length) return res.end(); res.write(out.subarray(i, i + 3)); i += 3; setTimeout(step, 1); }; step();
    }],
    ["401", (rec, res) => sendJsonish(res, 401, JSON.stringify({ error: `bad token ${echoed(rec)}` }), { "WWW-Authenticate": `Bearer error="invalid_token", hint="${echoed(rec)}"` })],
    ["gzip", (rec, res) => { const b = gzipSync(result(rec.json.id, `gz ${echoed(rec)}`)); res.writeHead(200, { "Content-Type": "application/json", "Content-Encoding": "gzip", "Content-Length": b.length }); res.end(b); }]
  ];
  for (const [name, fn] of cases) {
    for (const [hdr, val] of [["authorization", `Bearer ${PH}`], ["x-api-key", PH_K]]) {
      up.on(fn);
      const r = await post(`${gw.url}/remote`, call(10, "echo"), { [hdr]: val });
      noSecret(r.visible, `${name} via ${hdr}`);
      assert.ok(/\*{20,}/.test(r.visible), `${name}: masked in place`);
      if (name === "json") { assert.equal(r.status, 200); assert.match(r.json.result.content[0].text, /^you sent (Bearer )?\*+$/); assert.match(r.statusText, /^OK (Bearer )?\*+$/); assert.equal(Number(r.headers["content-length"]), r.raw.length); }
      if (name === "gzip") { assert.equal(r.headers["content-encoding"], undefined); assert.match(r.json.result.content[0].text, /^gz (Bearer )?\*+$/); }
      if (name === "401") assert.equal(r.status, 401);
    }
  }
  up.on((rec, res) => { res.writeHead(200, { "Content-Type": "application/json", "Content-Encoding": "zstd" }); res.end(echoed(rec)); });
  const z = await post(`${gw.url}/remote`, call(11, "echo"), { authorization: `Bearer ${PH}` });
  assert.equal(z.status, 502); noSecret(z.visible, "an unknown coding");
  up.on(null);
  await settle(300);
  noSecret(gw.stderr, "the gateway's log");
  noSecret(JSON.stringify(con.alerts) + JSON.stringify(con.usage), "the console posts");
});

test("a raw credential where placeholders are configured: forwarded and reported once per route, content-free; --require-placeholders refuses it (401)", async () => {
  up.on(null);
  const n = up.received.length;
  const r = await post(`${gw.url}/remote`, call(20, "echo"), { authorization: RAW });
  assert.equal(r.status, 200); assert.equal(up.received[n].headers.authorization, RAW, "the client's own credential goes upstream untouched");
  await post(`${gw.url}/remote`, call(21, "echo"), { authorization: RAW });
  await settle();
  const sent = con.alerts.filter((a) => /raw credential sent/.test(a.category));
  assert.equal(sent.length, 1, JSON.stringify(con.alerts.map((a) => a.category)));
  assert.ok(!JSON.stringify(con.alerts).includes("FAKE-raw-oauth"), "content-free");

  const strict = await startGateway({ home, consoleUrl: con.url, args: [...routeArgs(), "--credentials", credFile, "--require-placeholders"], env: childEnv });
  try {
    assert.match(await stderrMatch(strict, /raw credentials are refused/), /raw credentials are refused/);
    const m = up.received.length;
    const refused = await post(`${strict.url}/remote`, call(22, "echo"), { authorization: RAW });
    assert.equal(refused.status, 401); assert.match(refused.json.error.message, /accepts only credential placeholders/);
    assert.ok(!refused.visible.includes("FAKE-raw-oauth"));
    assert.equal(up.received.length, m, "not forwarded");
    const ok = await post(`${strict.url}/remote`, call(23, "echo"), { authorization: `Bearer ${PH}` });
    assert.equal(ok.status, 200); assert.equal(up.received.at(-1).headers.authorization, `Bearer ${SECRET}`);
    await settle();
    assert.ok(con.alerts.some((a) => /raw credential refused/.test(a.category) && a.riskLevel === "Blocked"));
  } finally { await stopGateway(strict); }
});

test("no bindings: unchanged — a placeholder-looking Authorization goes upstream as sent, the response is not touched", async () => {
  const plain = await startGateway({ home, consoleUrl: con.url, args: routeArgs(), env: childEnv });
  try {
    assert.doesNotMatch(plain.stderr, /credential placeholder/);
    up.on((rec, res) => { const t = result(rec.json.id, `you sent ${echoed(rec)}`); res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(t), "x-echo": echoed(rec) }); res.end(t); });
    const r = await post(`${plain.url}/other?k=moorai-ph:x`, call(30, "echo"), { authorization: `Bearer ${PH}` });
    assert.equal(r.status, 200);
    assert.equal(up.received.at(-1).headers.authorization, `Bearer ${PH}`); assert.match(up.received.at(-1).url, /k=moorai-ph%3Ax|k=moorai-ph:x/);
    assert.equal(r.headers["x-echo"], `Bearer ${PH}`);
  } finally { up.on(null); await stopGateway(plain); }
});

test("an unsafe bindings or secret file, or an invalid binding, stops the gateway before it listens (exit 2), without echoing a secret", { skip: !POSIX && "POSIX modes" }, () => {
  const run = (file, extra = {}) => spawnSync(process.execPath, [GATEWAY, ...routeArgs(), "--credentials", file], { encoding: "utf8", timeout: 15000, env: { PATH: process.env.PATH, HOME: home, ...childEnv, ...extra } });
  const bad = join(home, "bad.json");
  for (const mode of [0o666, 0o620]) {
    writeBindings(bad, bindings(), mode);
    const r = run(bad);
    assert.equal(r.status, 2); assert.match(r.stderr, /group- or world-writable/);
  }
  writeBindings(bad, bindings());
  chmodSync(secretFile, 0o606);
  try { const r = run(bad); assert.equal(r.status, 2); assert.match(r.stderr, /secret file .* group- or world-writable/); } finally { chmodSync(secretFile, 0o600); }
  for (const [b, re] of [
    [{ [PH]: { ...bindings()[PH], upstream: "https://mcp.example.com/mcp" } }, /does not match route \/remote's upstream exactly/],
    [{ [PH]: { ...bindings()[PH], header: "x-moorai-gateway-token" } }, /stripped or owned/],
    [{ [PH]: { ...bindings()[PH], secret: { value: SECRET } } }, /literal secret is refused/]
  ]) {
    writeBindings(bad, b);
    const r = run(bad);
    assert.equal(r.status, 2, String(re)); assert.match(r.stderr, re); noSecret(r.stderr, "an error");
  }
  const rp = spawnSync(process.execPath, [GATEWAY, ...routeArgs(), "--require-placeholders"], { encoding: "utf8", timeout: 15000, env: { PATH: process.env.PATH, HOME: home } });
  assert.equal(rp.status, 2); assert.match(rp.stderr, /needs --credentials/);
});
