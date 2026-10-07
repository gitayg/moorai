// Regressions from the v1.4.0 commit review of the HTTP MCP gateway (mcp-gateway/server.mjs):
//   (1) the per-client cool-down: what a "client" is, and which refusals count
//   (2) parser differentials: the gateway gating one reading of a body while forwarding bytes another
//       parser reads differently
//   (3) scan coverage: request and response paths the gate or the result scan does not read
// Benign stand-ins only (the AWS documentation example key), local fake upstreams only.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-gateway-review.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { rmSync } from "node:fs";
import { scenario, rpc, call, settle, sign, startConsole, makeHome, startGateway, stopGateway, H } from "../mcp-gateway/test/harness.mjs";

const POLICY = { captureTier: "content-free", threatPolicy: { 39: "block" } };
const AWS = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1\n";
const KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_J = JSON.stringify(AWS);
const COOL = ["--cooldown-refusals", "2", "--cooldown-window", "60", "--cooldown-seconds", "30"];
const schemaAlerts = (con) => con.alerts.filter((a) => a.reasonCode === "SCHEMA_INVALID");
const resultJson = (id, text) => `{"jsonrpc":"2.0","id":${id},"result":{"content":[{"type":"text","text":${JSON.stringify(text)}}],"isError":false}}`;

// A local upstream whose every POST is answered by reply(msg, raw) → { ctype, body }. It decodes the body
// the way the MCP SDK's server does (new TextDecoder(): BOM dropped, invalid UTF-8 replaced), so `json`
// on a received request is what an SDK server would have acted on.
async function rawUpstream(reply) {
  const received = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks);
      let json = null;
      try { json = JSON.parse(new TextDecoder().decode(raw)); } catch { /* not JSON to an SDK server either */ }
      received.push({ method: req.method, headers: req.headers, raw, json });
      const r = reply(json, raw);
      res.writeHead(200, { "Content-Type": r.ctype || "application/json" });
      res.end(r.body);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}/mcp`, received, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}
async function withRaw({ policy = POLICY, gatewayArgs = [], reply }, fn) {
  const con = await startConsole(sign(policy));
  const home = makeHome(con.url);
  const up = await rawUpstream(reply);
  const gw = await startGateway({ home, consoleUrl: con.url, args: ["--port", "0", "--route", `/remote=${up.url}`, ...gatewayArgs] });
  try {
    if (!gw.url) throw new Error(`gateway did not start: exit=${gw.exitCode} stderr=${gw.stderr}`);
    await fn({ con, up, base: `${gw.url}/remote` });
  } finally {
    await stopGateway(gw);
    await up.close();
    await con.close();
    rmSync(home, { recursive: true, force: true });
  }
}
// A POST of raw bytes; the answer read as the SDK client reads it (fetch: BOM dropped, lenient UTF-8).
async function post(url, bytes, headers = {}) {
  const r = await fetch(url, { method: "POST", headers: { ...H, ...headers }, body: bytes });
  const text = await r.text();
  return { status: r.status, text, json: (() => { try { return JSON.parse(text); } catch { return null; } })() };
}

// ------------------------------------------------------------------------------- (1) cool-down
test("REVIEW cool-down: a client that sends a new Authorization value with each refused call is still cooled down", async () => {
  await scenario({ policy: POLICY, gatewayArgs: COOL }, async ({ con, up, base }) => {
    for (let i = 0; i < 3; i++) {
      const r = await rpc(base, call(i, "send", { body: AWS }), { Authorization: `Bearer rotated-${i}-0123456789` });
      assert.equal(r.json.result.isError, true);
    }
    const fresh = await rpc(base, call(9, "echo", { a: 1 }), { Authorization: "Bearer rotated-fresh-0123456789" });
    assert.equal(fresh.json.result.isError, true, `rotating Authorization dodged the cool-down: ${fresh.text}`);
    assert.match(fresh.json.result.content[0].text, /cool-down after repeated refusals/);
    const none = await rpc(base, call(10, "echo", { a: 1 }));
    assert.equal(none.json.result.isError, true, "dropping Authorization dodged the cool-down");
    assert.equal(up.received.length, 0, "a cooled-down peer reached the upstream");
    await settle();
    assert.ok(con.alerts.some((a) => a.reasonCode === "CLIENT_COOLDOWN"));
  });
});

test("REVIEW cool-down: Mcp-Name / Mcp-Method header-mismatch refusals count toward the cool-down", async () => {
  await scenario({ policy: POLICY, gatewayArgs: COOL }, async ({ up, base }) => {
    const A = { Authorization: "Bearer agent-A-token-123456" };
    assert.equal((await rpc(base, call(1, "echo", {}), { ...A, "Mcp-Name": "other" })).status, 400);
    assert.equal((await rpc(base, call(2, "echo", {}), { ...A, "Mcp-Method": "tools/list" })).status, 400);
    const r = await rpc(base, call(3, "echo", { a: 1 }), A);
    assert.equal(r.json.result.isError, true, `header-mismatch refusals were not counted: ${r.text}`);
    assert.equal(up.received.length, 0);
  });
});

test("REVIEW cool-down: X-Forwarded-For and Mcp-Session-Id are not part of the client key", async () => {
  await scenario({ policy: POLICY, gatewayArgs: COOL }, async ({ up, base }) => {
    const A = { Authorization: "Bearer agent-A-token-123456" };
    for (let i = 0; i < 2; i++) await rpc(base, call(i, "send", { body: AWS }), { ...A, "X-Forwarded-For": `10.0.0.${i}`, "Mcp-Session-Id": `s-${i}` });
    const r = await rpc(base, call(5, "echo", { a: 1 }), { ...A, "X-Forwarded-For": "10.9.9.9", "Mcp-Session-Id": "s-new" });
    assert.equal(r.json.result.isError, true, "a client-chosen header changed the cool-down key");
    assert.equal(up.received.length, 0);
  });
});

// ------------------------------------------------------------------------------- (2) parser differential
test("REVIEW parse: a body with a repeated key is refused, not gated on JSON.parse's last value and forwarded", async () => {
  await scenario({ policy: POLICY }, async ({ con, up, base }) => {
    // The gate reads arguments.body = "hello"; a first-wins parser upstream reads the key.
    const args = await rpc(base, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":{"body":${AWS_J},"body":"hello"}}}`);
    assert.equal(args.json && args.json.result && args.json.result.isError, true, `repeated argument key: ${args.text}`);
    // The gate reads method "ping" and never gates; a first-wins parser upstream runs tools/call.
    const meth = await rpc(base, `{"jsonrpc":"2.0","id":2,"method":"tools/call","method":"ping","params":{"name":"send","arguments":{"body":${AWS_J}}}}`);
    assert.equal(meth.json && meth.json.error && meth.json.error.code, -32700, `repeated method key: ${meth.text}`);
    assert.equal(up.received.length, 0, "a body with a repeated key reached the upstream");
    await settle();
    // Posted once per stage/path (report.mjs seenOnce).
    assert.deepEqual(schemaAlerts(con).map((a) => `${a.schemaStage}@${a.schemaPath}:${a.decision}`), ["json@$:deny"]);
  });
});

test("REVIEW parse: envelope / params keys that differ only in case are refused; argument keys may", async () => {
  await scenario({ policy: POLICY }, async ({ up, base }) => {
    // Go's encoding/json matches struct fields case-insensitively and keeps the last: it reads Arguments.
    const p = await rpc(base, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"a":1},"Arguments":{"body":${AWS_J}}}}`);
    assert.equal(p.json && p.json.result && p.json.result.isError, true, `case-variant params key: ${p.text}`);
    const e = await rpc(base, `{"jsonrpc":"2.0","id":4,"method":"ping","Method":"tools/call","params":{"name":"send","arguments":{"body":${AWS_J}}}}`);
    assert.equal(e.json && e.json.error && e.json.error.code, -32700, `case-variant envelope key: ${e.text}`);
    assert.equal(up.received.length, 0, "a case-variant MCP key reached the upstream");
    const ok = await rpc(base, call(5, "echo", { Name: "x", name: "y" }));
    assert.equal(ok.json.result.isError, false, "argument keys that differ in case are valid JSON-RPC");
    assert.equal(up.received.length, 1);
  });
});

test("REVIEW parse: a batch whose Mcp-Name / Mcp-Method header disagrees with a message in it is refused", async () => {
  await scenario({ policy: POLICY }, async ({ up, base }) => {
    const r = await rpc(base, [call(1, "echo", { a: 1 })], { "Mcp-Method": "tools/call", "Mcp-Name": "other" });
    assert.deepEqual([r.status, r.json && r.json.error && r.json.error.code], [400, -32020], r.text);
    assert.equal(up.received.length, 0);
    const same = await rpc(base, [call(2, "echo", { a: 1 })], { "Mcp-Method": "tools/call", "Mcp-Name": "echo" });
    assert.notEqual(same.status, 400, same.text);
    assert.equal(up.received.length, 1, "a batch that agrees with its headers is forwarded");
  });
});

// ------------------------------------------------------------------------------- (3) scan coverage
test("REVIEW scan: --schema report|off still gates a body with invalid UTF-8 or a BOM (the SDK server's TextDecoder reads both)", async () => {
  for (const mode of ["report", "off"]) {
    await scenario({ policy: POLICY, gatewayArgs: ["--schema", mode] }, async ({ up, base }) => {
      const json = JSON.stringify(call(1, "send", { body: AWS }));
      const bom = await post(base, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(json)]));
      assert.equal(bom.json && bom.json.result && bom.json.result.isError, true, `${mode} BOM: ${bom.text}`);
      const at = json.indexOf(KEY);
      const bad = await post(base, Buffer.concat([Buffer.from(json.slice(0, at)), Buffer.from([0xff]), Buffer.from(json.slice(at))]));
      assert.equal(bad.json && bad.json.result && bad.json.result.isError, true, `${mode} invalid UTF-8: ${bad.text}`);
      assert.equal(up.received.length, 0, `${mode}: an ungated call reached the upstream`);
    });
  }
});

test("REVIEW scan: a JSON tools/call result with an invalid UTF-8 byte, or behind a BOM, is scanned before the client reads it", async () => {
  for (const [label, wrap] of [
    ["invalid UTF-8", (s) => { const at = s.indexOf(KEY); return Buffer.concat([Buffer.from(s.slice(0, at)), Buffer.from([0xff]), Buffer.from(s.slice(at))]); }],
    ["BOM", (s) => Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(s)])]
  ]) {
    await withRaw({ reply: (m) => ({ body: wrap(resultJson(m.id, AWS)) }) }, async ({ base }) => {
      const r = await post(base, JSON.stringify(call(7, "read_file", { path: "/x/.env" })));
      assert.ok(r.json, `${label}: the client could not parse the answer: ${r.text}`);
      assert.ok(!r.text.includes(KEY), `${label}: an unscanned result reached the client: ${r.text}`);
      assert.deepEqual([r.json.id, r.json.result.isError], [7, true]);
    });
  }
});

test("REVIEW scan: an SSE event is scanned whatever its event: type, as v1.3.2 did", async () => {
  await withRaw({ reply: (m) => ({ ctype: "text/event-stream", body: `id: e1\nevent: result\ndata: ${resultJson(m.id, AWS)}\n\n` }) }, async ({ base }) => {
    const r = await post(base, JSON.stringify(call(8, "read_file", {})));
    assert.ok(!r.text.includes(KEY), `a typed SSE event went unscanned: ${r.text}`);
  });
});

test("REVIEW scan: an SSE result is scanned however the JSON spells it (\\u0072esult, a U+2028 in the data, a leading BOM, a batch array)", async () => {
  const variants = {
    escapedKey: (m) => `id: e1\nevent: message\ndata: ${resultJson(m.id, AWS).replace('"result"', '"\\u0072esult"')}\n\n`,
    lineSeparator: (m) => `id: e1\nevent: message\ndata: ${resultJson(m.id, AWS + "\u2028")}\n\n`,
    leadingBom: (m) => `\uFEFFdata: ${resultJson(m.id, AWS)}\n\n`,
    batchArray: (m) => `id: e1\nevent: message\ndata: [${resultJson(m.id, AWS)}]\n\n`
  };
  for (const [label, body] of Object.entries(variants)) {
    await withRaw({ reply: (m) => ({ ctype: "text/event-stream", body: body(m) }) }, async ({ base }) => {
      const r = await post(base, JSON.stringify(call(9, "read_file", {})));
      assert.ok(!r.text.includes(KEY), `${label}: an SSE result reached the client unscanned: ${r.text}`);
      assert.match(r.text, /MoorAI blocked this MCP tool result/, label);
    });
  }
});
