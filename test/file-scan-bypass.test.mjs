// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/file-scan-bypass.test.mjs
//
// The ways a file could reach a provider past the cloud file scan, closed: a body the proxy cannot read
// (compressed, not JSON) on a parsed path; endpoints that carry files outside the parsed APIs (Anthropic
// message batches and Gemini cachedContents are parsed and scanned; the Files / uploads APIs and Gemini batch
// generation are refused or alerted); file parts given as references or as values that are not data URLs; and a
// "clean" verdict from too few engines (fileScan.minEngines). In process, against the fake providers.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { gzipSync } from "node:zlib";
import { fileParts } from "../model-proxy/file-parts.mjs";
import { createProxy } from "../model-proxy/server.mjs";
import { createFileScanner } from "../cli/file-scan.mjs";
import { fileScanPolicy } from "../cli/file-scan-policy.mjs";
import { startFakeProvider, sendJson, anthropicMessage, openaiCompletion } from "../model-proxy/test/fake-provider.mjs";
import { request, waitFor } from "../model-proxy/test/harness.mjs";
import { startMetaDefender, startVirusTotal, sha256, TEST_KEY } from "./file-scan-fakes.mjs";

const BAD = Buffer.from("pretend-malicious-sample-bytes-0001");
const GOOD = Buffer.from("an ordinary harmless document body");
const THIN = Buffer.from("seen by only two engines so far");
const b64 = (b) => b.toString("base64");
const durl = (b, mt) => `data:${mt};base64,${b64(b)}`;

// ---- file-parts coverage ----
test("fileParts: an OpenAI Responses computer_call_output screenshot is read", () => {
  const r = fileParts("openai-responses", { input: [{ type: "computer_call_output", call_id: "c1", output: { type: "computer_screenshot", image_url: durl(BAD, "image/png") } }] });
  assert.equal(r.parts.length, 1);
  assert.ok(r.parts[0].bytes.equals(BAD));
});

test("fileParts: a file_data / image_url value that is not a data: URL is unscannable, not skipped", () => {
  const cases = [
    ["openai-chat", { messages: [{ role: "user", content: [{ type: "image_url", image_url: b64(BAD) }] }] }],
    ["openai-chat", { messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: b64(BAD) } }] }] }],
    ["openai-chat", { messages: [{ role: "user", content: [{ type: "file", file: { filename: "a.pdf", file_data: b64(BAD) } }] }] }],
    ["openai-responses", { input: [{ role: "user", content: [{ type: "input_file", filename: "a.pdf", file_data: b64(BAD) }] }] }],
    ["openai-responses", { input: [{ role: "user", content: [{ type: "input_image", image_url: b64(BAD) }] }] }]
  ];
  for (const [kind, body] of cases) {
    const r = fileParts(kind, body);
    assert.equal(r.parts.length, 0, JSON.stringify(body).slice(0, 80));
    assert.equal(r.unscannable.length, 1, JSON.stringify(body).slice(0, 80));
  }
});

test("fileParts: URL and file-id references are listed (refs), never silently passed", () => {
  const cases = [
    ["openai-chat", { messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: "https://example.com/cat.png" } }] }] }],
    ["openai-chat", { messages: [{ role: "user", content: [{ type: "file", file: { file_id: "file-abc123" } }] }] }],
    ["openai-responses", { input: [{ role: "user", content: [{ type: "input_file", file_id: "file-abc123" }] }] }],
    ["openai-responses", { input: [{ role: "user", content: [{ type: "input_file", file_url: "https://example.com/a.pdf" }] }] }],
    ["openai-responses", { input: [{ role: "user", content: [{ type: "input_image", file_id: "file-abc123" }] }] }],
    ["openai-responses", { input: [{ role: "user", content: [{ type: "input_image", image_url: "https://example.com/cat.png" }] }] }],
    ["openai-responses", { input: [{ type: "computer_call_output", call_id: "c1", output: { type: "computer_screenshot", file_id: "file-abc123" } }] }],
    ["anthropic", { messages: [{ role: "user", content: [{ type: "image", source: { type: "url", url: "https://example.com/cat.png" } }] }] }],
    ["anthropic", { messages: [{ role: "user", content: [{ type: "document", source: { type: "file", file_id: "file_011" } }] }] }],
    ["gemini", { contents: [{ role: "user", parts: [{ fileData: { mimeType: "application/pdf", fileUri: "https://generativelanguage.googleapis.com/v1beta/files/abc" } }] }] }],
    ["gemini", { contents: [{ role: "user", parts: [{ file_data: { mime_type: "application/pdf", file_uri: "gs://bucket/a.pdf" } }] }] }]
  ];
  for (const [kind, body] of cases) {
    const r = fileParts(kind, body);
    assert.equal(r.parts.length, 0);
    assert.equal(r.refs.length, 1, JSON.stringify(body).slice(0, 100));
    assert.ok(!JSON.stringify(r.refs[0]).includes("undefined"));
  }
});

// ---- minEngines ----
test("minEngines: a clean verdict from fewer engines than fileScan.minEngines (default 3) is unknown", async () => {
  const md = await startMetaDefender({ known: { [sha256(THIN)]: { result: 0, detected: 0, total: 2 }, [sha256(GOOD)]: { result: 0, detected: 0, total: 30 }, [sha256(BAD)]: { result: 1, detected: 1, total: 1, threat: "X" } } });
  const vt = await startVirusTotal({ known: { [sha256(THIN)]: { malicious: 0, undetected: 1 }, [sha256(GOOD)]: { malicious: 0, undetected: 60 } } });
  try {
    assert.equal(fileScanPolicy({ fileScan: { mode: "hash" } }).minEngines, 3);
    assert.equal(fileScanPolicy({ fileScan: { mode: "hash", minEngines: 1 } }).minEngines, 1);
    assert.equal(fileScanPolicy({ fileScan: { mode: "hash", minEngines: 0 } }).minEngines, 3, "out of range -> default");
    const s = createFileScanner({ keys: { metadefender: TEST_KEY, virustotal: TEST_KEY }, endpoints: { metadefender: md.base, virustotal: vt.base } });
    for (const provider of ["metadefender", "virustotal"]) {
      const cfg = fileScanPolicy({ fileScan: { provider, mode: "hash" } });
      const thin = await s.scan(THIN, cfg);
      assert.deepEqual([thin.verdict, thin.why], ["unknown", "few-engines"], provider);
      assert.equal((await s.scan(THIN, cfg)).verdict, "unknown", `${provider}: a cached thin clean is still unknown`);
      assert.equal((await s.scan(GOOD, cfg)).verdict, "clean", provider);
      assert.equal((await s.scan(THIN, fileScanPolicy({ fileScan: { provider, mode: "hash", minEngines: 1 } }))).verdict, "clean", `${provider}: minEngines 1`);
    }
    assert.equal((await s.scan(BAD, fileScanPolicy({ fileScan: { provider: "metadefender", mode: "hash" } }))).verdict, "malicious", "a detection is malicious whatever the engine count");
  } finally { await md.close(); await vt.close(); }
});

// ---- through the proxy ----
let fp, md;
before(async () => {
  fp = await startFakeProvider();
  md = await startMetaDefender({ known: { [sha256(BAD)]: { result: 1, detected: 12, total: 30, threat: "Trojan.FakeFamily" }, [sha256(GOOD)]: { result: 0, detected: 0, total: 30 } } });
});
after(async () => { await fp?.close(); await md?.close(); });
async function startConsole() {
  const alerts = [];
  const srv = http.createServer((q, r) => { let b = ""; q.on("data", (d) => (b += d)); q.on("end", () => { if (q.url === "/api/alerts") alerts.push(b); r.writeHead(q.url.startsWith("/api/policy") ? 404 : 201); r.end("{}"); }); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, parsed: () => alerts.map((a) => JSON.parse(a)), close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(() => r()); }) };
}
const HASH = { provider: "metadefender", mode: "hash" };
const OPEN = { resolveFailMode: () => ({ mode: "open", source: "policy" }) };
const proxy = (mode, fileScan, extra = {}) => createProxy({ port: 0, mode, policy: { captureTier: "content-free", fileScan }, systemConfig: null, env: {}, routes: { "/anthropic": fp.url, "/openai": `${fp.url}/v1`, "/gemini": fp.url }, fileScanKeys: { metadefender: TEST_KEY }, fileScanEndpoints: { metadefender: md.base }, ...extra });
const ok = () => fp.on((r, res) => sendJson(res, anthropicMessage({ text: "ok" })));
const msg = (data) => ({ model: "claude-fake", max_tokens: 8, messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data } }] }] });

test("a parsed path with a compressed body: enforce refuses it with scanning on; report alerts and forwards; scanning off forwards", async () => {
  const gz = gzipSync(Buffer.from(JSON.stringify(msg(b64(BAD)))));
  const send = (px) => { ok(); return request(px.url, "/anthropic/v1/messages", { body: gz, headers: { "content-encoding": "gzip" } }); };
  const con = await startConsole();
  try { await compressed(send, con); } finally { await con.close(); }
});
async function compressed(send, con) {
  const e = await proxy("enforce", HASH);
  try {
    const n = fp.requests.length;
    const r = await send(e);
    assert.equal(r.status, 403, String(r.raw));
    assert.match(r.raw.toString(), /could not be read for files/);
    assert.equal(fp.requests.length, n);
  } finally { await e.close(); }
  const rep = await proxy("report", HASH, { ...OPEN, console: { serverUrl: con.url, tenant: "t", installToken: "tok-bypass-1" } });
  try {
    const n = fp.requests.length;
    assert.equal((await send(rep)).status, 200);
    assert.equal(fp.requests.length, n + 1);
    assert.ok(await waitFor(() => con.parsed().some((a) => /file-scan-body/.test(a.tool))), "an alert for the unread body");
  } finally { await rep.close(); }
  const off = await proxy("enforce", undefined);
  try { assert.equal((await send(off)).status, 200); } finally { await off.close(); }
}

test("a parsed path with a body that is not a JSON object (BOM) is refused in enforce mode with scanning on", async () => {
  const px = await proxy("enforce", HASH);
  try {
    ok();
    const n = fp.requests.length;
    const r = await request(px.url, "/anthropic/v1/messages", { body: `﻿${JSON.stringify(msg(b64(BAD)))}` });
    assert.equal(r.status, 403, String(r.raw));
    assert.equal(fp.requests.length, n);
  } finally { await px.close(); }
});

test("Anthropic message batches are parsed: a malicious inline file in any request's params is refused; a clean one forwarded", async () => {
  const px = await proxy("enforce", HASH);
  const batch = (data) => ({ requests: [{ custom_id: "a", params: msg(b64(GOOD)) }, { custom_id: "b", params: msg(data) }] });
  try {
    const n = fp.requests.length;
    fp.on((r, res) => sendJson(res, { id: "msgbatch_1", type: "message_batch" }));
    const r = await request(px.url, "/anthropic/v1/messages/batches", { body: batch(b64(BAD)) });
    assert.equal(r.status, 403, String(r.raw));
    assert.match(r.raw.toString(), /malicious file/);
    assert.equal(fp.requests.length, n);
    assert.equal((await request(px.url, "/anthropic/v1/messages/batches", { body: batch(b64(GOOD)) })).status, 200);
  } finally { await px.close(); }
});

test("Gemini cachedContents is parsed: a malicious inline file is refused", async () => {
  const px = await proxy("enforce", HASH);
  try {
    const n = fp.requests.length;
    fp.on((r, res) => sendJson(res, { name: "cachedContents/abc" }));
    const r = await request(px.url, "/gemini/v1beta/cachedContents", { body: { model: "models/gemini-fake", contents: [{ role: "user", parts: [{ inlineData: { mimeType: "application/pdf", data: b64(BAD) } }] }] } });
    assert.equal(r.status, 403, String(r.raw));
    assert.equal(fp.requests.length, n);
  } finally { await px.close(); }
});

test("file upload APIs and Gemini batch generation are refused in enforce mode with scanning on, alerted in report mode, untouched with it off", async () => {
  const paths = ["/anthropic/v1/files", "/openai/files", "/openai/uploads", "/openai/uploads/upload_abc/parts", "/gemini/upload/v1beta/files", "/gemini/v1beta/models/gemini-fake:batchGenerateContent"];
  const con = await startConsole();
  const e = await proxy("enforce", HASH);
  const rep = await proxy("report", HASH, { ...OPEN, console: { serverUrl: con.url, tenant: "t", installToken: "tok-bypass-2" } });
  const off = await proxy("enforce", undefined);
  try {
    for (const p of paths) {
      fp.on((r, res) => sendJson(res, { id: "file_1" }));
      const n = fp.requests.length;
      const r = await request(e.url, p, { body: b64(BAD), headers: { "content-type": "application/octet-stream" } });
      assert.equal(r.status, 403, `${p}: ${r.raw}`);
      assert.match(r.raw.toString(), /not scanned/);
      assert.equal(fp.requests.length, n, p);
      assert.equal((await request(rep.url, p, { body: b64(BAD), headers: { "content-type": "application/octet-stream" } })).status, 200, `${p} report`);
      assert.equal((await request(off.url, p, { body: b64(BAD), headers: { "content-type": "application/octet-stream" } })).status, 200, `${p} off`);
    }
    assert.ok(await waitFor(() => con.parsed().some((a) => /file-scan-endpoint/.test(a.tool))));
  } finally { await e.close(); await rep.close(); await off.close(); await con.close(); }
});

test("a file sent by reference raises an alert and follows onUnknown", async () => {
  const con = await startConsole();
  const body = { model: "gpt-fake", messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: "https://example.com/cat.png" } }] }] };
  const send = (px) => { fp.on((r, res) => sendJson(res, openaiCompletion({ text: "ok" }))); return request(px.url, "/openai/chat/completions", { body }); };
  try { await byReference(send, con); } finally { await con.close(); }
});
async function byReference(send, con) {
  const block = await proxy("enforce", { ...HASH, onUnknown: "block" });
  try {
    const r = await send(block);
    assert.equal(r.status, 403, String(r.raw));
    assert.match(r.raw.toString(), /sent by reference/);
  } finally { await block.close(); }
  const allow = await proxy("enforce", HASH, { console: { serverUrl: con.url, tenant: "t", installToken: "tok-bypass-3" } });
  try {
    assert.equal((await send(allow)).status, 200);
    assert.ok(await waitFor(() => con.parsed().some((a) => a.fileScan && a.fileScan.why === "reference")));
    for (const a of con.alerts) assert.ok(!a.includes("example.com"), "the reference itself never leaves");
  } finally { await allow.close(); }
}
