// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/model-proxy-connect-timeout.test.mjs
//
// --connect-timeout: the upstream must be ready to take the request (TCP connected, and for https the TLS
// handshake done) within this budget, else 504 with a content-free reason. Measured before: only the 600s
// idle timeout existed, so a dropped upstream hung for the kernel's SYN timeout (~75-135s) before a 502.
//
// The silent upstream is a local TCP listener that accepts and never sends a byte, behind an https route:
// the TCP connect succeeds and the TLS handshake never completes, which is the "not ready" phase the
// timeout covers. It is deterministic on every OS and makes no network call. A non-routable address
// (192.0.2.1) was not used: whether its SYN is dropped or answered with an ICMP error depends on the host's
// network, so it is not reliable in CI.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";
import { pathToFileURL } from "node:url";
import { startFakeProvider, sendJson, anthropicMessage } from "../model-proxy/test/fake-provider.mjs";
import { CLI, sandbox, startProxy, request } from "../model-proxy/test/harness.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const { parseArgs } = await import(pathToFileURL(CLI).href);
const BODY = { model: "claude-fake", max_tokens: 16, messages: [{ role: "user", content: "hi" }] };
const HDR = { "x-api-key": "sk-ant-FAKE-connect-timeout-0123456789", "anthropic-version": "2023-06-01" };

let silent, socks = [], fp, home, px;
before(async () => {
  silent = net.createServer((s) => { socks.push(s); s.on("error", () => {}); });
  await new Promise((r) => silent.listen(0, "127.0.0.1", r));
  fp = await startFakeProvider();
  home = sandbox();
  px = await startProxy(home, ["--connect-timeout", "500", "--route", `/silent=https://127.0.0.1:${silent.address().port}`, "--route", `/anthropic=${fp.url}`]);
});
after(async () => { for (const s of socks) s.destroy(); silent.close(); await fp.close(); if (px) await px.stop(); rmTree(home); });

// POST with a client-side deadline: resolves the response, or { status: "no answer" } (and drops the
// connection, so nothing is left open) if nothing came back within ms.
function within(ms, path) {
  const u = new URL(path, px.listening), data = Buffer.from(JSON.stringify(BODY));
  return new Promise((res) => {
    const r = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { ...HDR, "content-type": "application/json", "content-length": data.length } }, (resp) => {
      const chunks = []; resp.on("data", (d) => chunks.push(d));
      resp.on("end", () => { clearTimeout(t); const raw = Buffer.concat(chunks); let json = null; try { json = JSON.parse(raw.toString("utf8")); } catch {} res({ status: resp.statusCode, raw, json }); });
    });
    const t = setTimeout(() => { r.destroy(); res({ status: "no answer", raw: Buffer.alloc(0), json: null }); }, ms);
    r.on("error", () => {});
    r.end(data);
  });
}

test("args: --connect-timeout defaults to 10000 ms and is validated", () => {
  assert.equal(parseArgs([], {}).connectTimeoutMs, 10000);
  assert.equal(parseArgs(["--connect-timeout", "2500"], {}).connectTimeoutMs, 2500);
  assert.throws(() => parseArgs(["--connect-timeout", "50"], {}), /--connect-timeout must be an integer >= 100/);
  assert.throws(() => parseArgs(["--connect-timeout", "ten"], {}), /--connect-timeout must be an integer >= 100/);
});

test("an upstream that never becomes ready answers 504 within the connect timeout, content-free", async () => {
  const t0 = Date.now();
  const r = await within(6000, "/silent/v1/messages");
  const ms = Date.now() - t0;
  assert.equal(r.status, 504, `expected 504, got ${r.status} after ${ms}ms`);
  assert.ok(ms < 3000, `took ${ms}ms with a 500ms connect timeout`);
  assert.match(r.json.error.message, /did not accept a connection within 500 ms/);
  const text = r.raw.toString("utf8");
  assert.ok(!text.includes("127.0.0.1") && !text.includes(String(silent.address().port)) && !text.includes(HDR["x-api-key"]), `the reason must not carry the upstream address or the key: ${text}`);
});

test("once connected, a response slower than the connect timeout is not cut off", async () => {
  fp.on((req, res) => { setTimeout(() => sendJson(res, anthropicMessage({ text: "late but fine" })), 1200); });
  const r = await request(px.listening, "/anthropic/v1/messages", { body: BODY, headers: HDR });
  assert.equal(r.status, 200);
  assert.equal(r.json.content[0].text, "late but fine");
});

test("once connected, a stream that runs longer than the connect timeout arrives whole", async () => {
  fp.on((req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" });
    let i = 0;
    const t = setInterval(() => {
      if (i === 4) { clearInterval(t); res.end("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"); return; }
      res.write(`event: ping\ndata: {"type":"ping","n":${i++}}\n\n`);
    }, 300);
  });
  const r = await request(px.listening, "/anthropic/v1/messages", { body: { ...BODY, stream: true }, headers: HDR });
  assert.equal(r.status, 200);
  const text = r.raw.toString("utf8");
  for (let n = 0; n < 4; n++) assert.ok(text.includes(`"n":${n}`), `ping ${n} missing: ${text}`);
  assert.ok(text.includes("message_stop"));
  assert.ok(r.chunks.length >= 2, "the stream must arrive incrementally, not buffered");
});
