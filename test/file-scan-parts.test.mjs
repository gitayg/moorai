// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/file-scan-parts.test.mjs
//
// What the cloud file scan reads out of a request (model-proxy/file-parts.mjs) must be what the provider
// reads: both spellings of a dual-spelled field (Gemini's proto JSON accepts lowerCamel and snake_case), every
// nested inline blob (Gemini functionResponse.parts, tool results), and base64 decoded strictly — data a lenient
// decoder and the provider could read differently is unscannable, never clean. The proxy forwards the body it
// scanned, re-serialised from the parsed object. In process, against the fake providers.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { fileParts, strictBase64 } from "../model-proxy/file-parts.mjs";
import { createProxy } from "../model-proxy/server.mjs";
import { startFakeProvider, sendJson, anthropicMessage } from "../model-proxy/test/fake-provider.mjs";
import { geminiResponse } from "../model-proxy/test/fake-gemini.mjs";
import { request, waitFor } from "../model-proxy/test/harness.mjs";
import { createServer } from "../cli/moorai-serve.mjs";
import { startMetaDefender, sha256, TEST_KEY } from "./file-scan-fakes.mjs";

const BAD = Buffer.from("pretend-malicious-sample-bytes-0001");
const GOOD = Buffer.from("an ordinary harmless document body");
const b64 = (b) => b.toString("base64");
const inject = (s, at, ch) => s.slice(0, at) + ch + s.slice(at);

// ---- strict base64 ----
test("strictBase64: the standard alphabet with end padding, whitespace removed; anything else is null", () => {
  assert.deepEqual(strictBase64(b64(BAD)), BAD);
  assert.deepEqual(strictBase64(`${b64(BAD).slice(0, 8)}\n${b64(BAD).slice(8)}`), BAD, "line breaks are removed first");
  assert.equal(strictBase64(inject(b64(BAD), 5, "*")), null, "an invalid character");
  assert.equal(strictBase64("QQ==QQ=="), null, "padding mid-string");
  assert.equal(strictBase64("QUJD" + "Q"), null, "length not a multiple of 4");
  assert.equal(strictBase64("QR=="), null, "non-canonical trailing bits fail the round trip");
  assert.equal(strictBase64("ab-_"), null, "URL-safe characters where the API does not document them");
  assert.deepEqual(strictBase64(Buffer.from([0xfb, 0xff]).toString("base64url") + "=", { urlSafe: true }), Buffer.from([0xfb, 0xff]), "URL-safe where documented (proto3 JSON bytes)");
  assert.equal(strictBase64("+/-_", { urlSafe: true }), null, "the two alphabets mixed");
  assert.equal(strictBase64(""), null);
});

test("fileParts: data that fails strict base64 is listed unscannable, never as a part", () => {
  const bad = inject(b64(BAD), 6, "!");
  const r = fileParts("anthropic", { messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: bad } }] }] });
  assert.equal(r.parts.length, 0);
  assert.equal(r.unscannable.length, 1);
  assert.equal(r.unscannable[0].where, "anthropic:image");
  const o = fileParts("ollama", { messages: [{ role: "user", images: ["QQ==QQ=="] }] });
  assert.deepEqual([o.parts.length, o.unscannable.length], [0, 1]);
  const d = fileParts("openai-chat", { messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: `data:image/png;base64,${inject(b64(BAD), 3, "%")}` } }] }] });
  assert.deepEqual([d.parts.length, d.unscannable.length], [0, 1]);
});

// ---- dual spellings ----
test("fileParts: Gemini inlineData and inline_data in one part are both scanned, and differing ones are ambiguous", () => {
  const part = { inlineData: { mimeType: "image/png", data: b64(GOOD) }, inline_data: { mime_type: "image/png", data: b64(BAD) } };
  const r = fileParts("gemini", { contents: [{ role: "user", parts: [part] }] });
  assert.ok(r.parts.some((p) => p.bytes.equals(BAD)), "the snake_case blob is scanned too");
  assert.ok(r.parts.some((p) => p.bytes.equals(GOOD)));
  assert.equal(r.ambiguous.length, 1);
  const same = fileParts("gemini", { contents: [{ role: "user", parts: [{ inlineData: { mimeType: "image/png", data: b64(GOOD) }, inline_data: { mime_type: "image/png", data: b64(GOOD) } }] }] });
  assert.equal(same.ambiguous.length, 0, "the same blob twice is not ambiguous");
  const mt = fileParts("gemini", { contents: [{ role: "user", parts: [{ inlineData: { mimeType: "image/png", mime_type: "application/x-msdownload", data: b64(GOOD) } }] }] });
  assert.equal(mt.ambiguous.length, 1, "mimeType and mime_type differ");
  const fr = fileParts("gemini", { contents: [{ role: "user", parts: [{ functionResponse: { name: "f", response: {}, parts: [] }, function_response: { name: "f", response: {}, parts: [{ inlineData: { mimeType: "image/png", data: b64(BAD) } }] } }] }] });
  assert.ok(fr.parts.some((p) => p.bytes.equals(BAD)));
  assert.equal(fr.ambiguous.length, 1);
  const si = fileParts("gemini", { systemInstruction: { parts: [] }, system_instruction: { parts: [{ inline_data: { mime_type: "image/png", data: b64(BAD) } }] }, contents: [] });
  assert.ok(si.parts.some((p) => p.bytes.equals(BAD)));
  assert.equal(si.ambiguous.length, 1);
});

// ---- nested blobs ----
test("fileParts: nested inline blobs — Gemini functionResponse.parts, an OpenAI tool message's file, an Anthropic tool_result document", () => {
  const g = fileParts("gemini", { contents: [{ role: "user", parts: [{ functionResponse: { name: "screenshot", response: { ok: true }, parts: [{ inlineData: { mimeType: "image/png", data: b64(BAD) } }] } }] }] });
  assert.equal(g.parts.length, 1);
  assert.ok(g.parts[0].bytes.equals(BAD));
  const o = fileParts("openai-chat", { messages: [{ role: "tool", tool_call_id: "c1", content: [{ type: "file", file: { filename: "r.pdf", file_data: `data:application/pdf;base64,${b64(BAD)}` } }] }] });
  assert.equal(o.parts.length, 1);
  const a = fileParts("anthropic", { messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: [{ type: "document", source: { type: "base64", media_type: "application/pdf", data: b64(BAD) } }] }] }] });
  assert.equal(a.parts.length, 1);
  assert.equal(a.parts[0].mediaType, "application/pdf");
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
const proxy = (mode, fileScan, extra = {}) => createProxy({ port: 0, mode, policy: { captureTier: "content-free", fileScan }, systemConfig: null, env: {}, routes: { "/anthropic": fp.url, "/gemini": fp.url }, fileScanKeys: { metadefender: TEST_KEY }, fileScanEndpoints: { metadefender: md.base }, ...extra });
const gemini = (px, body) => { fp.on((r, res) => sendJson(res, geminiResponse({ text: "ok" }))); return request(px.url, "/gemini/v1beta/models/gemini-fake:generateContent", { body }); };
const anthropic = (px, body) => { fp.on((r, res) => sendJson(res, anthropicMessage({ text: "ok" }))); return request(px.url, "/anthropic/v1/messages", { body }); };
const HASH = { provider: "metadefender", mode: "hash" };

test("proxy enforce: dual spellings with different data are refused as ambiguous before the upstream", async () => {
  const px = await proxy("enforce", HASH);
  try {
    const n = fp.requests.length;
    const r = await gemini(px, { contents: [{ role: "user", parts: [{ inlineData: { mimeType: "image/png", data: b64(GOOD) }, inline_data: { mime_type: "image/png", data: b64(Buffer.from("another harmless body")) } }] }] });
    assert.equal(r.status, 403, String(r.raw));
    assert.match(r.raw.toString(), /ambiguous/);
    assert.equal(fp.requests.length, n);
  } finally { await px.close(); }
});

test("proxy enforce: a malicious blob nested in functionResponse.parts is refused", async () => {
  const px = await proxy("enforce", HASH);
  try {
    const n = fp.requests.length;
    const r = await gemini(px, { contents: [{ role: "user", parts: [{ text: "here" }] }, { role: "user", parts: [{ functionResponse: { name: "screenshot", response: { ok: true }, parts: [{ inlineData: { mimeType: "image/png", data: b64(BAD) } }] } }] }] });
    assert.equal(r.status, 403, String(r.raw));
    assert.match(r.raw.toString(), /malicious file/);
    assert.equal(fp.requests.length, n);
  } finally { await px.close(); }
});

test("proxy: base64 with an injected invalid character or mid-string padding is unscannable — it follows the fail mode and onUnknown, never clean", async () => {
  const con = await startConsole();
  const body = (data) => ({ model: "claude-fake", max_tokens: 8, messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data } }] }] });
  const before = md.requests.length;
  try {
    const closed = await proxy("enforce", HASH, { resolveFailMode: () => ({ mode: "closed", source: "policy" }) });
    try {
      for (const data of [inject(b64(BAD), 6, "*"), `${b64(GOOD).slice(0, 4)}==${b64(GOOD).slice(4)}`]) {
        const r = await anthropic(closed, body(data));
        assert.equal(r.status, 403, String(r.raw));
        assert.match(r.raw.toString(), /not scanned \(unscannable\)/);
      }
    } finally { await closed.close(); }
    const block = await proxy("enforce", { ...HASH, onUnknown: "block" }, { resolveFailMode: () => ({ mode: "open", source: "policy" }) });
    try { assert.equal((await anthropic(block, body(inject(b64(BAD), 6, "*")))).status, 403); } finally { await block.close(); }
    const allow = await proxy("enforce", HASH, { resolveFailMode: () => ({ mode: "open", source: "policy" }), console: { serverUrl: con.url, tenant: "t", installToken: "tok-fs-parts" } });
    try {
      assert.equal((await anthropic(allow, body(inject(b64(BAD), 6, "*")))).status, 200, "open + onUnknown allow forwards it");
      assert.ok(await waitFor(() => con.parsed().some((a) => a.fileScan && a.fileScan.why === "unscannable")));
      const a = con.parsed().find((x) => x.fileScan && x.fileScan.why === "unscannable");
      assert.equal(a.fileScan.verdict, "error", "never clean");
    } finally { await allow.close(); }
    assert.equal(md.requests.length, before, "unscannable data is never looked up as if it were the file");
  } finally { await con.close(); }
});

test("proxy (report, open): the body forwarded is the one scanned — a duplicate key is re-serialised away", async () => {
  const px = await proxy("report", HASH, { resolveFailMode: () => ({ mode: "open", source: "policy" }) });
  try {
    // JSON.parse keeps the last "data" (GOOD, clean); a reader that keeps the first would see BAD.
    const raw = `{"model":"claude-fake","max_tokens":8,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"${b64(BAD)}","data":"${b64(GOOD)}"}}]}],"n":12345678901234567890}`;
    const n = fp.requests.length, m = md.requests.length;
    fp.on((r, res) => sendJson(res, anthropicMessage({ text: "ok" })));
    const r = await request(px.url, "/anthropic/v1/messages", { body: raw });
    assert.equal(r.status, 200, String(r.raw));
    assert.ok(await waitFor(() => md.requests.length > m), "report mode scans after the response");
    assert.equal(fp.requests.length, n + 1);
    const sent = fp.requests[n].body.toString("utf8");
    assert.ok(!sent.includes(b64(BAD)), "the unscanned duplicate reached the upstream");
    assert.ok(sent.includes(b64(GOOD)));
    assert.ok(sent.includes("12345678901234567890"), "re-serialised losslessly");
  } finally { await px.close(); }
});

test("moorai-serve /v1/file-scan: data that fails strict base64 is unscannable (error), not a 400 and not clean", async () => {
  const s = await createServer({ port: 0, policy: { fileScan: HASH }, env: {}, systemConfig: null, fileScanKeys: { metadefender: TEST_KEY }, fileScanEndpoints: { metadefender: md.base } });
  try {
    const before = md.requests.length;
    const data = JSON.stringify({ data: `${b64(GOOD).slice(0, 4)}==${b64(GOOD).slice(4)}` });
    const res = await new Promise((resolve, reject) => {
      const u = new URL("/v1/file-scan", s.url);
      const q = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data) } }, (p) => { let b = ""; p.on("data", (d) => (b += d)); p.on("end", () => resolve({ status: p.statusCode, json: JSON.parse(b) })); });
      q.on("error", reject); q.end(data);
    });
    assert.equal(res.status, 200);
    assert.deepEqual([res.json.verdict, res.json.why], ["error", "unscannable"]);
    assert.equal(md.requests.length, before);
  } finally { await s.close(); }
});

// ---- depth cap ----
const nestGemini = (levels, leaf) => { let parts = [leaf]; for (let i = 0; i < levels; i++) parts = [{ functionResponse: { name: `f${i}`, response: {}, parts } }]; return { contents: [{ role: "user", parts }] }; };
const nestAnthropic = (levels, leaf) => { let content = [leaf]; for (let i = 0; i < levels; i++) content = [{ type: "tool_result", tool_use_id: `t${i}`, content }]; return { messages: [{ role: "user", content }] }; };

test("fileParts: a blob nested past the depth cap is unscannable, not silently skipped", () => {
  const g = fileParts("gemini", nestGemini(40, { inlineData: { mimeType: "image/png", data: b64(BAD) } }));
  assert.equal(g.parts.length, 0);
  assert.ok(g.unscannable.length >= 1, "past the cap must be recorded");
  const a = fileParts("anthropic", nestAnthropic(40, { type: "image", source: { type: "base64", media_type: "image/png", data: b64(BAD) } }));
  assert.equal(a.parts.length, 0);
  assert.ok(a.unscannable.length >= 1);
  assert.equal(fileParts("gemini", nestGemini(3, { inlineData: { mimeType: "image/png", data: b64(BAD) } })).parts.length, 1, "within the cap it is scanned");
});

test("proxy enforce: a blob nested past the depth cap follows the fail mode (closed: refused as not scanned)", async () => {
  const px = await proxy("enforce", HASH, { resolveFailMode: () => ({ mode: "closed", source: "policy" }) });
  try {
    const n = fp.requests.length;
    const r = await gemini(px, nestGemini(40, { inlineData: { mimeType: "image/png", data: b64(BAD) } }));
    assert.equal(r.status, 403, String(r.raw));
    assert.match(r.raw.toString(), /not scanned \(unscannable\)/);
    assert.equal(fp.requests.length, n);
  } finally { await px.close(); }
});

// ---- duplicate keys ----
// The parser's last-wins view has no file; a reader that keeps the first "contents" would get BAD.
const DUP = `{"contents":[{"role":"user","parts":[{"inlineData":{"mimeType":"image/png","data":"${b64(BAD)}"}}]}],"contents":[{"role":"user","parts":[{"text":"hello"}]}]}`;
const rawGemini = (px, raw) => { fp.on((r, res) => sendJson(res, geminiResponse({ text: "ok" }))); return request(px.url, "/gemini/v1beta/models/gemini-fake:generateContent", { body: raw }); };

test("proxy: with file scanning on, a request body with duplicate keys is refused in enforce mode", async () => {
  const px = await proxy("enforce", HASH);
  try {
    const n = fp.requests.length;
    const r = await rawGemini(px, DUP);
    assert.equal(r.status, 403, String(r.raw));
    assert.match(r.raw.toString(), /duplicate/);
    assert.equal(fp.requests.length, n);
  } finally { await px.close(); }
});

test("proxy: report mode with a duplicate-key body forwards only the re-serialised body (what was scanned), never the hidden first occurrence", async () => {
  const px = await proxy("report", HASH, { resolveFailMode: () => ({ mode: "open", source: "policy" }) });
  try {
    const n = fp.requests.length;
    const r = await rawGemini(px, DUP);
    assert.equal(r.status, 200, String(r.raw));
    const sent = fp.requests[n].body.toString("utf8");
    assert.ok(!sent.includes(b64(BAD)), "the duplicate's hidden file reached the upstream");
    assert.equal(sent, JSON.stringify(JSON.parse(DUP)));
  } finally { await px.close(); }
});

test("proxy: with file scanning on, every parsed body is forwarded re-serialised, file or not; with it off, verbatim", async () => {
  const raw = `{ "contents" : [ { "role" : "user", "parts" : [ { "text" : "hi" } ] } ] }`;
  const on = await proxy("enforce", HASH);
  try {
    const n = fp.requests.length;
    assert.equal((await rawGemini(on, raw)).status, 200);
    assert.equal(fp.requests[n].body.toString("utf8"), JSON.stringify(JSON.parse(raw)));
  } finally { await on.close(); }
  const off = await proxy("enforce", undefined);
  try {
    const n = fp.requests.length;
    assert.equal((await rawGemini(off, raw)).status, 200);
    assert.equal(fp.requests[n].body.toString("utf8"), raw, "scanning off changes nothing");
  } finally { await off.close(); }
});
