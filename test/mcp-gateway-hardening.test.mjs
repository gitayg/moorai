// C5 hardening end to end: a real gateway process, the fake remote MCP server and a fake console.
//   (a) staged JSON-RPC / MCP validation, both directions — SCHEMA_INVALID with schemaStage + schemaPath
//   (b) the response size cap — RESPONSE_TOO_LARGE with limitBytes
//   (c) the per-client cool-down — CLIENT_COOLDOWN with cooldownSeconds
// and that valid traffic of both spec eras still passes untouched.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-gateway-hardening.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { scenario, rpc, call, settle } from "../mcp-gateway/test/harness.mjs";

const POLICY = { captureTier: "content-free", threatPolicy: { 39: "block" } };
const AWS = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1\n";
const V = "VALUE-must-not-leave-q8w7";
const PV = "io.modelcontextprotocol/protocolVersion";
const schemaAlerts = (con) => con.alerts.filter((a) => a.reasonCode === "SCHEMA_INVALID");
function sseData(text) {
  return text.split(/\n\n/).map((ev) => ev.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n")).filter(Boolean).map((d) => JSON.parse(d));
}

// ---------------------------------------------------------------------------------- (a) validation
test("SCHEMA client: an invalid tools/call is refused with the gateway's tool-error shape; SCHEMA_INVALID carries stage + path, no values", async () => {
  await scenario({ policy: POLICY }, async ({ con, up, base }) => {
    const r = await rpc(base, { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "send", arguments: [V] } });
    assert.equal(r.status, 200);
    assert.equal(r.json.id, 7);
    assert.equal(r.json.result.isError, true);
    assert.match(r.json.result.content[0].text, /MoorAI blocked this MCP tool call: this MCP message failed validation \(schema at \$\.params\.arguments\)/);
    assert.equal(up.received.length, 0, "an invalid call reached the upstream");
    await settle();
    const a = schemaAlerts(con);
    assert.equal(a.length, 1, JSON.stringify(con.alerts.map((x) => x.category)));
    assert.equal(a[0].schemaStage, "schema");
    assert.equal(a[0].schemaPath, "$.params.arguments");
    assert.equal(a[0].schemaDirection, "client");
    assert.equal(a[0].decision, "deny");
    assert.equal(a[0].riskLevel, "Blocked");
    assert.equal(a[0].tool, "gateway:send");
    assert.equal(a[0].mcpServer, "remote");
    assert.ok(!JSON.stringify(con.alerts).includes(V), "a value reached an alert");
  });
});

test("SCHEMA client: each stage gets its own JSON-RPC answer (parse 400, envelope, method allow-list, protocol version, header)", async () => {
  await scenario({ policy: POLICY, gatewayArgs: ["--allow-method", "initialize", "--allow-method", "tools/call", "--allow-method", "tools/list"] }, async ({ con, up, base }) => {
    const parse = await rpc(base, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"a":"${V}"}},}`);
    assert.equal(parse.status, 400);
    assert.deepEqual(parse.json.error.code, -32700);
    assert.equal(parse.json.id, null);
    const env = await rpc(base, { jsonrpc: "1.0", id: 2, method: "tools/list" });
    assert.equal(env.status, 200);
    assert.deepEqual([env.json.id, env.json.error.code], [2, -32600]);
    const meth = await rpc(base, { jsonrpc: "2.0", id: 3, method: "resources/read", params: { uri: "file:///etc/passwd" } });
    assert.deepEqual([meth.status, meth.json.id, meth.json.error.code], [200, 3, -32601]);
    const pv = await rpc(base, { jsonrpc: "2.0", id: 4, method: "initialize", params: { protocolVersion: "June", capabilities: {}, clientInfo: { name: "c", version: "1" } } });
    assert.deepEqual([pv.status, pv.json.id, pv.json.error.code], [200, 4, -32602]);
    const hdr = await rpc(base, call(5, "echo", {}), { "MCP-Protocol-Version": "banana" });
    assert.equal(hdr.status, 400);
    const mismatch = await rpc(base, { jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "echo", _meta: { [PV]: "2026-07-28" } } }, { "MCP-Protocol-Version": "2025-06-18" });
    assert.deepEqual([mismatch.status, mismatch.json.error.code], [400, -32020]);
    const notif = await rpc(base, { jsonrpc: "2.0", method: "tools/call", params: { name: "x" } });
    assert.equal(notif.status, 400, "a tools/call without an id cannot be answered and is not forwarded");
    assert.equal(up.received.length, 0, "an invalid message reached the upstream");
    await settle();
    const stages = schemaAlerts(con).map((a) => `${a.schemaStage}@${a.schemaPath}`).sort();
    assert.deepEqual(stages, ["json@$", "jsonrpc@$.jsonrpc", "method@$.method", "protocolVersion@$", `protocolVersion@$.params._meta["${PV}"]`, "protocolVersion@$.params.protocolVersion", "structure@$.id"].sort());
    assert.ok(schemaAlerts(con).find((a) => a.schemaStage === "protocolVersion" && a.schemaPath === "$").schemaHeader === "MCP-Protocol-Version");
    assert.ok(!JSON.stringify(con.alerts).includes(V));
  });
});

test("SCHEMA client: a batch with one invalid message is refused whole", async () => {
  await scenario({ policy: POLICY }, async ({ up, base }) => {
    const r = await rpc(base, [call(1, "echo", { a: 1 }), { jsonrpc: "2.0", id: 2, method: "tools/list", params: { cursor: 9 } }]);
    assert.deepEqual(r.json.map((m) => [m.id, m.result ? m.result.isError : m.error.code]), [[1, true], [2, -32602]]);
    assert.equal(up.received.length, 0);
  });
});

test("SCHEMA client: --schema report forwards the invalid message and reports it as allowed; --schema off reports nothing", async () => {
  await scenario({ policy: POLICY, gatewayArgs: ["--schema", "report"] }, async ({ con, up, base }) => {
    await rpc(base, { jsonrpc: "2.0", id: 1, method: "tools/list", params: { cursor: 9 } });
    assert.equal(up.received.length, 1);
    await settle();
    const a = schemaAlerts(con);
    assert.equal(a.length, 1);
    assert.deepEqual([a[0].decision, a[0].riskLevel, a[0].schemaPath], ["allow", "Medium", "$.params.cursor"]);
  });
  await scenario({ policy: POLICY, gatewayArgs: ["--schema", "off"] }, async ({ con, up, base }) => {
    await rpc(base, { jsonrpc: "2.0", id: 1, method: "tools/list", params: { cursor: 9 } });
    assert.equal(up.received.length, 1);
    await settle();
    assert.equal(schemaAlerts(con).length, 0);
  });
});

test("SCHEMA client: an unknown method is forwarded and reported when no allow-list is configured", async () => {
  await scenario({ policy: POLICY }, async ({ con, up, base }) => {
    await rpc(base, { jsonrpc: "2.0", id: 1, method: "vendor/frobnicate", params: {} });
    assert.equal(up.received.length, 1);
    await settle();
    const a = schemaAlerts(con);
    assert.deepEqual(a.map((x) => [x.schemaStage, x.decision]), [["method", "allow"]]);
  });
});

test("SCHEMA server: an invalid tools/call result is replaced by a tool error (JSON and SSE); an invalid tools/list is reported, never altered", async () => {
  const bad = (m) => JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { content: `${V} hidden from the scan`, isError: false } });
  await scenario({ policy: POLICY, upstream: { callReply: bad } }, async ({ con, base }) => {
    const r = await rpc(base, call(9, "weather", {}));
    assert.equal(r.json.id, 9);
    assert.equal(r.json.result.isError, true);
    assert.ok(!r.text.includes(V), "the malformed result reached the client");
    await settle();
    const a = schemaAlerts(con)[0];
    assert.deepEqual([a.schemaDirection, a.schemaStage, a.schemaPath, a.decision, a.tool], ["server", "schema", "$.result.content", "deny", "gateway:weather"]);
  });
  await scenario({ policy: POLICY, upstream: { mode: "sse", callReply: bad, splitBytes: 7 } }, async ({ base }) => {
    const r = await rpc(base, call(10, "weather", {}));
    const evs = sseData(r.text);
    assert.equal(evs[0].method, "notifications/progress");
    assert.deepEqual([evs[1].id, evs[1].result.isError], [10, true]);
    assert.ok(!r.text.includes(V));
  });
  const LIST = `{"jsonrpc":"2.0","id":__ID__,"result":{"tools":[{"name":"ok"},{"description":"no name"}]}}`;
  await scenario({ policy: POLICY, upstream: { listReply: (m) => LIST.replace("__ID__", String(m.id)) } }, async ({ con, base }) => {
    const r = await rpc(base, { jsonrpc: "2.0", id: 3, method: "tools/list" });
    assert.equal(r.text, LIST.replace("__ID__", "3"), "a tools/list was altered");
    await settle();
    const a = schemaAlerts(con)[0];
    assert.deepEqual([a.schemaPath, a.decision], ["$.result.tools[1].name", "allow"]);
  });
});

test("BOTH ERAS: 2026-07-28 requests (_meta, mirrored headers) and results (resultType, input_required) pass untouched", async () => {
  const MRTR = (m) => JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { resultType: "input_required", inputRequests: { q: { method: "elicitation/create", params: { message: "?" } } }, requestState: "s1" } });
  await scenario({ policy: POLICY, upstream: { callReply: MRTR } }, async ({ con, up, base }) => {
    const msg = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "book", arguments: { day: "mon" }, _meta: { [PV]: "2026-07-28", "io.modelcontextprotocol/clientCapabilities": { elicitation: {} } } } };
    const r = await rpc(base, msg, { "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "book" });
    assert.equal(r.text, MRTR({ id: 1 }));
    assert.equal(up.calls().length, 1);
    const d = await rpc(base, { jsonrpc: "2.0", id: 2, method: "server/discover", params: { _meta: { [PV]: "2026-07-28" } } }, { "MCP-Protocol-Version": "2026-07-28" });
    assert.equal(d.status, 200);
    await settle();
    assert.equal(schemaAlerts(con).length, 0, JSON.stringify(schemaAlerts(con)));
  });
});

// ---------------------------------------------------------------------------------- (b) size cap
test("SIZE: a JSON response over --max-response-bytes is refused (Content-Length and chunked); RESPONSE_TOO_LARGE carries limitBytes", async () => {
  for (const chunked of [false, true]) {
    await scenario({ policy: POLICY, gatewayArgs: ["--max-response-bytes", "50000"], upstream: { resultText: "a".repeat(60000), chunked } }, async ({ con, base }) => {
      const r = await rpc(base, call(4, "dump", {}));
      assert.equal(r.status, 200);
      assert.equal(r.json.id, 4);
      assert.equal(r.json.result.isError, true);
      assert.match(r.json.result.content[0].text, /exceeded the gateway's 50000-byte response limit/);
      await settle();
      const a = con.alerts.filter((x) => x.reasonCode === "RESPONSE_TOO_LARGE");
      assert.equal(a.length, 1, `chunked=${chunked}`);
      assert.deepEqual([a[0].limitBytes, a[0].tool, a[0].decision], [50000, "gateway:dump", "deny"]);
    });
  }
  // Under the cap: byte-for-byte as before.
  await scenario({ policy: POLICY, gatewayArgs: ["--max-response-bytes", "50000"], upstream: { resultText: "a".repeat(40000) } }, async ({ base }) => {
    const r = await rpc(base, call(4, "dump", {}));
    assert.equal(r.json.result.content[0].text.length, 40000);
  });
});

test("SIZE: a non-tools/call response over the cap gets a JSON-RPC error for its id", async () => {
  const big = { name: "t", description: "d".repeat(60000), inputSchema: { type: "object" } };
  await scenario({ policy: POLICY, gatewayArgs: ["--max-response-bytes", "50000"], upstream: { tools: [big] } }, async ({ base }) => {
    const r = await rpc(base, { jsonrpc: "2.0", id: 8, method: "tools/list" });
    assert.deepEqual([r.status, r.json.id, r.json.error.code], [200, 8, -32603]);
  });
});

test("SIZE: an SSE event over the cap is dropped and replaced by the answer for the request; the stream ends", async () => {
  await scenario({ policy: POLICY, gatewayArgs: ["--max-response-bytes", "50000"], upstream: { mode: "sse", resultText: "b".repeat(60000), splitBytes: 4096 } }, async ({ con, base }) => {
    const r = await rpc(base, call(12, "dump", {}));
    assert.ok(!r.text.includes("bbbbbbbbbb"), "oversized event content reached the client");
    const evs = sseData(r.text);
    assert.equal(evs[0].method, "notifications/progress", "the event before the oversized one passes");
    assert.deepEqual([evs[1].id, evs[1].result.isError], [12, true]);
    assert.ok(r.text.includes("id: e2"), "the replacement keeps the dropped event's id");
    await settle();
    assert.equal(con.alerts.filter((x) => x.reasonCode === "RESPONSE_TOO_LARGE")[0].limitBytes, 50000);
  });
});

test("SIZE: the default cap is 4 MiB — a 1.5 MB response still passes (unscanned, as before)", async () => {
  await scenario({ policy: POLICY, upstream: { resultText: "c".repeat(1_500_000) } }, async ({ con, base }) => {
    const r = await rpc(base, call(1, "dump", {}));
    assert.equal(r.json.result.content[0].text.length, 1_500_000);
    await settle();
    assert.equal(con.alerts.filter((x) => x.reasonCode === "RESPONSE_TOO_LARGE").length, 0);
  });
});

// ---------------------------------------------------------------------------------- (c) cool-down
test("COOLDOWN: after N refusals in the window the client is refused for M seconds; one alert; another client is served; it ends on time", async () => {
  await scenario({ policy: POLICY, gatewayArgs: ["--cooldown-refusals", "2", "--cooldown-window", "60", "--cooldown-seconds", "2"] }, async ({ con, up, base }) => {
    const A = { Authorization: "Bearer agent-A-token-123456" }, B = { Authorization: "Bearer agent-B-token-654321" };
    for (let i = 0; i < 2; i++) assert.equal((await rpc(base, call(i, "send", { body: AWS }), A)).json.result.isError, true);
    const cold = await rpc(base, call(5, "echo", { a: 1 }), A);
    assert.equal(cold.json.result.isError, true);
    assert.match(cold.json.result.content[0].text, /cool-down after repeated refusals \(\d s left\)/);
    const list = await rpc(base, { jsonrpc: "2.0", id: 6, method: "tools/list" }, A);
    assert.equal(list.json.error.code, -32603, "every request of a cooled-down client is refused");
    assert.equal(up.received.length, 0, "a cooled-down client reached the upstream");
    const other = await rpc(base, call(7, "echo", { a: 1 }), B);
    assert.equal(other.json.result.isError, false, "a different client must not be cooled down");
    await settle(2200);
    const back = await rpc(base, call(8, "echo", { a: 1 }), A);
    assert.equal(back.json.result.isError, false, "the cool-down did not end");
    const a = con.alerts.filter((x) => x.reasonCode === "CLIENT_COOLDOWN");
    assert.equal(a.length, 1);
    assert.deepEqual([a[0].cooldownSeconds, a[0].decision, a[0].mcpServer], [2, "deny", "remote"]);
    assert.ok(!JSON.stringify(a).includes("agent-A-token"), "the client credential leaked");
  });
});

test("COOLDOWN: off by default — many refusals, the next clean call still passes", async () => {
  await scenario({ policy: POLICY }, async ({ con, base }) => {
    for (let i = 0; i < 6; i++) await rpc(base, call(i, "send", { body: AWS }));
    assert.equal((await rpc(base, call(9, "echo", {}))).json.result.isError, false);
    await settle();
    assert.equal(con.alerts.filter((x) => x.reasonCode === "CLIENT_COOLDOWN").length, 0);
  });
});
