// C5 hardening units for the HTTP MCP gateway: the staged JSON-RPC / MCP validator (mcp-gateway/validate.mjs),
// the per-client cool-down (mcp-gateway/cooldown.mjs) and the new config flags (mcp-gateway/config.mjs).
// Valid traffic of BOTH spec eras the gateway carries must pass; each stage must fail with its own stage and
// a JSON path built from schema names only — never a value the peer sent.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-gateway-validate.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseBody, validateClientBody, validateClientMessage, validateServerMessage, validateHeaderPv } from "../mcp-gateway/validate.mjs";
import { createCooldown } from "../mcp-gateway/cooldown.mjs";
import { parseConfig, DEFAULT_MAX_RESPONSE_BYTES } from "../mcp-gateway/config.mjs";
import { REASON, reasonCodeOf } from "../cli/provenance.mjs";

const V = "SECRET-VALUE-zz91";
const PV = "io.modelcontextprotocol/protocolVersion";
const req = (id, method, params) => ({ jsonrpc: "2.0", id, method, ...(params !== undefined ? { params } : {}) });

// ---- valid traffic, both eras ----
const VALID_2025 = [
  req(0, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "c", version: "1" } }),
  req(1, "initialize", { protocolVersion: "2024-11-05", capabilities: { roots: { listChanged: true } }, clientInfo: { name: "old" } }),
  { jsonrpc: "2.0", method: "notifications/initialized" },
  { jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 3, reason: "x" } },
  req(2, "tools/list"), req(3, "tools/list", { cursor: "c1" }),
  req("a-4", "tools/call", { name: "echo", arguments: { msg: "hi" } }),
  req(5, "tools/call", { name: "noargs" }), req(6, "tools/call", { name: "nullargs", arguments: null }),
  req(7, "ping"), req(8, "resources/read", { uri: "file:///x" }), req(9, "prompts/get", { name: "p" }),
  { jsonrpc: "2.0", id: 10, result: { roots: [{ uri: "file:///p" }] } },             // answer to a server's roots/list
  { jsonrpc: "2.0", id: 11, error: { code: -32601, message: "no" } }
];
const VALID_2026 = [
  req(20, "server/discover", { _meta: { [PV]: "2026-07-28" } }),
  req(21, "tools/call", { name: "get_weather", arguments: { location: "NY" }, _meta: { [PV]: "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}, traceparent: "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01" } }),
  req(22, "subscriptions/listen", { _meta: { [PV]: "2026-07-28" }, toolsListChanged: true }),
  req(23, "tasks/get", { taskId: "t1" }),
  req(24, "tools/call", { name: "x", arguments: {}, inputResponses: { a: {} }, requestState: "s", _meta: { [PV]: "2026-07-28" } })
];

test("VALID: client messages from 2024-11-05 through 2026-07-28 (and the tasks extension) pass", () => {
  for (const m of [...VALID_2025, ...VALID_2026]) assert.equal(validateClientMessage(m), null, JSON.stringify(m));
  assert.equal(validateClientMessage(req(21, "tools/call", { name: "x", _meta: { [PV]: "2026-07-28" } }), { headerPv: "2026-07-28" }), null);
  assert.equal(validateClientBody([VALID_2025[5], VALID_2025[6]]), null, "a 2025-03-26 batch");
  for (const h of [undefined, "2025-03-26", "2026-07-28", "2099-01-01"]) assert.equal(validateHeaderPv(h), null);
});

test("VALID: server results from both eras pass, incl. resultType, MRTR input_required, boolean inputSchema", () => {
  const m = (id) => ({ "0": "initialize", "2": "tools/list", "4": "tools/call" })[String(id)] || "";
  const ok = [
    { jsonrpc: "2.0", id: 0, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "s", version: "1" }, instructions: "x" } },
    { jsonrpc: "2.0", id: 2, result: { tools: [{ name: "a", inputSchema: { type: "object" } }, { name: "b", inputSchema: true }, { name: "c" }], nextCursor: "n" } },
    { jsonrpc: "2.0", id: 2, result: { resultType: "complete", tools: [], ttlMs: 1000, cacheScope: "private" } },
    { jsonrpc: "2.0", id: 4, result: { content: [{ type: "text", text: "t" }, { type: "image", data: "AA==", mimeType: "image/png" }], isError: false } },
    { jsonrpc: "2.0", id: 4, result: { resultType: "complete", content: [], structuredContent: [1, 2] } },
    { jsonrpc: "2.0", id: 4, result: { resultType: "input_required", inputRequests: { a: { method: "elicitation/create", params: {} } } } },
    { jsonrpc: "2.0", id: 4, error: { code: -32602, message: "Unknown tool" } },
    { jsonrpc: "2.0", error: { code: -32700, message: "Parse error" } },                     // 2026: id may be absent
    { jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: "p", progress: 1 } },
    { jsonrpc: "2.0", id: "s1", method: "sampling/createMessage", params: {} }                // legacy server-initiated request
  ];
  for (const x of ok) assert.equal(validateServerMessage(x, { methodOf: m }), null, JSON.stringify(x));
});

// ---- each stage, with its path ----
const CLIENT_BAD = [
  ["json", "$", () => parseBody(Buffer.from(`{"jsonrpc":"2.0","id":1,"method":"tools/call",${V}`)).error],
  ["json", "$", () => parseBody(Buffer.from([0x7b, 0xff, 0x7d])).error],                                  // invalid UTF-8
  ["json", "$", () => parseBody(Buffer.from("﻿{}", "utf8")).error],                                   // BOM
  ["jsonrpc", "$", () => validateClientBody([])],
  ["jsonrpc", "$.jsonrpc", () => validateClientMessage({ jsonrpc: "1.0", id: 1, method: "tools/list" })],
  ["jsonrpc", "$", () => validateClientMessage(V)],
  ["jsonrpc", "$.method", () => validateClientMessage({ jsonrpc: "2.0", id: 1, method: 7 })],
  ["structure", "$.method", () => validateClientMessage(req(1, `rpc.${V}`))],
  ["structure", "$.method", () => validateClientMessage(req(1, `bad method ${V}`))],
  ["structure", "$.id", () => validateClientMessage({ jsonrpc: "2.0", id: null, method: "tools/list" })],
  ["structure", "$.id", () => validateClientMessage({ jsonrpc: "2.0", id: 1.5, method: "tools/list" })],
  ["structure", "$.id", () => validateClientMessage({ jsonrpc: "2.0", id: { v: V }, method: "tools/list" })],
  ["structure", "$.id", () => validateClientMessage({ jsonrpc: "2.0", id: 1, method: "notifications/initialized" })],
  ["structure", "$.id", () => validateClientMessage({ jsonrpc: "2.0", method: "tools/call", params: { name: "x" } })],
  ["structure", "$.params", () => validateClientMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: [V] })],
  ["structure", "$.params._meta", () => validateClientMessage(req(1, "tools/list", { _meta: V }))],
  ["structure", "$", () => validateClientMessage({ jsonrpc: "2.0", id: 1, result: {}, error: { code: 1, message: V } })],
  ["structure", "$.error.code", () => validateClientMessage({ jsonrpc: "2.0", id: 1, error: { code: "x", message: V } })],
  ["method", "$.method", () => validateClientMessage(req(1, "resources/read", { uri: V }), { allowedMethods: new Set(["tools/call"]) })],
  ["protocolVersion", "$.params.protocolVersion", () => validateClientMessage(req(1, "initialize", { protocolVersion: V, capabilities: {}, clientInfo: { name: "c" } }))],
  ["protocolVersion", `$.params._meta["${PV}"]`, () => validateClientMessage(req(1, "tools/call", { name: "x", _meta: { [PV]: V } }))],
  ["protocolVersion", `$.params._meta["${PV}"]`, () => validateClientMessage(req(1, "tools/call", { name: "x", _meta: { [PV]: "2026-07-28" } }), { headerPv: "2025-06-18" })],
  ["protocolVersion", "$", () => validateHeaderPv(V)],
  ["schema", "$.params", () => validateClientMessage(req(1, "initialize"))],
  ["schema", "$.params.capabilities", () => validateClientMessage(req(1, "initialize", { protocolVersion: "2025-06-18", capabilities: V, clientInfo: { name: "c" } }))],
  ["schema", "$.params.clientInfo.name", () => validateClientMessage(req(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: 1 } }))],
  ["schema", "$.params", () => validateClientMessage(req(1, "tools/call"))],
  ["schema", "$.params.name", () => validateClientMessage(req(1, "tools/call", { name: "", arguments: { a: V } }))],
  ["schema", "$.params.name", () => validateClientMessage(req(1, "tools/call", { name: { v: V } }))],
  ["schema", "$.params.arguments", () => validateClientMessage(req(1, "tools/call", { name: "x", arguments: [V] }))],
  ["schema", "$.params.arguments", () => validateClientMessage(req(1, "tools/call", { name: "x", arguments: V }))],
  ["schema", "$.params.cursor", () => validateClientMessage(req(1, "tools/list", { cursor: 5 }))],
  ["schema", "$[1].params.name", () => validateClientBody([req(1, "tools/list"), req(2, "tools/call", { name: 3 })])]
];

test("STAGES: every client-side failure names its stage and a schema-built path; no value appears", () => {
  for (const [stage, path, fn] of CLIENT_BAD) {
    const r = fn();
    assert.ok(r, `expected a ${stage} failure at ${path}`);
    assert.equal(r.stage, stage, `${path}: ${JSON.stringify(r)}`);
    assert.equal(r.path, path, JSON.stringify(r));
    assert.ok(!JSON.stringify(r).includes(V), `a value leaked into the finding: ${JSON.stringify(r)}`);
  }
});

test("STAGES: server-side failures name their stage and path", () => {
  const m = (id) => ({ "0": "initialize", "2": "tools/list", "4": "tools/call" })[String(id)] || "";
  const bad = [
    ["jsonrpc", "$.jsonrpc", { jsonrpc: "1.0", id: 4, result: {} }],
    ["structure", "$", { jsonrpc: "2.0", id: 4 }],
    ["structure", "$.result", { jsonrpc: "2.0", id: 4, result: [V] }],
    ["structure", "$.id", { jsonrpc: "2.0", id: null, result: {} }],
    ["protocolVersion", "$.result.protocolVersion", { jsonrpc: "2.0", id: 0, result: { protocolVersion: V, capabilities: {}, serverInfo: { name: "s" } } }],
    ["schema", "$.result.serverInfo", { jsonrpc: "2.0", id: 0, result: { protocolVersion: "2025-06-18", capabilities: {} } }],
    ["schema", "$.result.tools", { jsonrpc: "2.0", id: 2, result: { tools: V } }],
    ["schema", "$.result.tools[1].name", { jsonrpc: "2.0", id: 2, result: { tools: [{ name: "a" }, { description: V }] } }],
    ["schema", "$.result.content", { jsonrpc: "2.0", id: 4, result: { content: V } }],
    ["schema", "$.result.content[0].type", { jsonrpc: "2.0", id: 4, result: { content: [{ text: V }] } }],
    ["schema", "$.result.isError", { jsonrpc: "2.0", id: 4, result: { content: [], isError: "no" } }],
    ["schema", "$.result.resultType", { jsonrpc: "2.0", id: 4, result: { resultType: 1 } }]
  ];
  for (const [stage, path, msg] of bad) {
    const r = validateServerMessage(msg, { methodOf: m });
    assert.deepEqual(r, { stage, path }, JSON.stringify(msg));
  }
});

test("METHOD: an unknown request method is reported (not failed) without an allow-list, refused with one", () => {
  assert.deepEqual(validateClientBody(req(1, "vendor/frobnicate")), { unknownMethods: ["vendor/frobnicate"] });
  assert.equal(validateClientBody(req(1, "vendor/frobnicate"), { allowedMethods: new Set(["tools/call"]) }).stage, "method");
  assert.equal(validateClientBody(req(1, "tools/call", { name: "x" }), { allowedMethods: new Set(["tools/call"]) }), null);
  assert.deepEqual(validateClientBody({ jsonrpc: "2.0", method: "notifications/whatever" }), null, "notifications are never 'unknown'");
});

test("COOLDOWN: N refusals inside the window start it; it is per key, fixed-length, and off by default", () => {
  let t = 1_000_000;
  const now = () => t;
  assert.equal(createCooldown({ now }).enabled, false);
  const off = createCooldown({ now });
  for (let i = 0; i < 50; i++) assert.equal(off.refused("a"), false);
  assert.equal(off.remaining("a"), 0);

  const c = createCooldown({ refusals: 3, windowSeconds: 10, seconds: 30, now });
  assert.equal(c.refused("a"), false); t += 4000;
  assert.equal(c.refused("a"), false); t += 7000;                 // first refusal now outside the window
  assert.equal(c.refused("a"), false);
  assert.equal(c.remaining("a"), 0);
  assert.equal(c.refused("a"), true, "third refusal within 10 s starts the cool-down");
  assert.equal(c.remaining("a"), 30);
  assert.equal(c.remaining("b"), 0, "another client is unaffected");
  t += 20000;
  assert.equal(c.refused("a"), false, "a refusal during the cool-down does not extend it");
  assert.equal(c.remaining("a"), 10);
  t += 10001;
  assert.equal(c.remaining("a"), 0, "the client is let back in on time");
});

test("CONFIG: hardening flags and JSON keys parse; bad values exit with a message; defaults", () => {
  const base = ["--route", "/r=https://example.com/mcp"];
  const d = parseConfig(base, {});
  assert.equal(d.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES);
  assert.equal(d.maxResponseBytes, 4194304);
  assert.equal(d.schemaValidation, "enforce");
  assert.equal(d.allowedMethods, null);
  assert.deepEqual(d.cooldown, { refusals: 0, windowSeconds: 60, seconds: 120 });
  const f = parseConfig([...base, "--max-response-bytes", "1000", "--schema", "report", "--allow-method", "tools/call", "--allow-method", "tools/list", "--cooldown-refusals", "5", "--cooldown-window", "30", "--cooldown-seconds", "90"], {});
  assert.deepEqual([f.maxResponseBytes, f.schemaValidation, f.allowedMethods, f.cooldown], [1000, "report", ["tools/call", "tools/list"], { refusals: 5, windowSeconds: 30, seconds: 90 }]);
  const j = parseConfig(["--config", "g.json"], {}, () => JSON.stringify({ routes: { "/r": "https://example.com/mcp" }, maxResponseBytes: 0, schemaValidation: "off", allowedMethods: ["initialize"], cooldown: { refusals: 2 } }));
  assert.deepEqual([j.maxResponseBytes, j.schemaValidation, j.allowedMethods, j.cooldown], [0, "off", ["initialize"], { refusals: 2, windowSeconds: 60, seconds: 120 }]);
  assert.throws(() => parseConfig([...base, "--schema", "strict"], {}), /--schema must be one of/);
  assert.throws(() => parseConfig([...base, "--max-response-bytes", "-1"], {}), /max response bytes/);
  assert.throws(() => parseConfig([...base, "--cooldown-seconds", "1.5"], {}), /cooldown seconds/);
});

test("PROVENANCE: the three C5 reason codes exist and the gateway's categories map to them", () => {
  assert.equal(REASON.SCHEMA_INVALID, "SCHEMA_INVALID");
  assert.equal(REASON.RESPONSE_TOO_LARGE, "RESPONSE_TOO_LARGE");
  assert.equal(REASON.CLIENT_COOLDOWN, "CLIENT_COOLDOWN");
  assert.equal(reasonCodeOf({ category: "MCP gateway: invalid message" }), "SCHEMA_INVALID");
  assert.equal(reasonCodeOf({ category: "MCP gateway: response too large" }), "RESPONSE_TOO_LARGE");
  assert.equal(reasonCodeOf({ category: "MCP gateway: client cool-down" }), "CLIENT_COOLDOWN");
});
