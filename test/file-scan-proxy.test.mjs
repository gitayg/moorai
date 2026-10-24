// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/file-scan-proxy.test.mjs
//
// The model proxy scans every inline file, document or image part of a request with the policy's cloud
// file-scanning provider (policy.fileScan) before the request goes upstream: Anthropic image / document
// base64 blocks (also inside a tool_result), OpenAI Chat image_url data URLs, file parts and input_audio,
// Responses input_image / input_file, Gemini inlineData, Ollama images. In process, against the fake
// providers (test/file-scan-fakes.mjs) and the fake model upstream; streaming and not.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createProxy } from "../model-proxy/server.mjs";
import { fileParts } from "../model-proxy/file-parts.mjs";
import { startFakeProvider } from "../model-proxy/test/fake-provider.mjs";
import { request, waitFor } from "../model-proxy/test/harness.mjs";
import { API, pathOf, answer } from "../model-proxy/test/text-fixtures.mjs";
import { startMetaDefender, startVirusTotal, sha256, TEST_KEY } from "./file-scan-fakes.mjs";

const BAD = Buffer.from("pretend-malicious-sample-bytes-0001");
const GOOD = Buffer.from("an ordinary harmless document body");
const NEW = Buffer.from("never seen by any provider before 77");
const b64 = (b) => b.toString("base64");
const dataUrl = (b, mt) => `data:${mt};base64,${b64(b)}`;

// One request per adapter and file-part form, carrying `buf`.
const FORMS = {
  "anthropic image": { api: "anthropic", body: (buf, stream) => ({ ...API.anthropic.body("sys", "x", stream), messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: b64(buf) } }, { type: "text", text: "describe" }] }] }) },
  "anthropic document": { api: "anthropic", body: (buf, stream) => ({ ...API.anthropic.body("sys", "x", stream), messages: [{ role: "user", content: [{ type: "document", source: { type: "base64", media_type: "application/pdf", data: b64(buf) } }, { type: "text", text: "summarise" }] }] }) },
  "anthropic tool_result image": { api: "anthropic", body: (buf, stream) => ({ ...API.anthropic.body("sys", "x", stream), messages: [{ role: "user", content: "go" }, { role: "assistant", content: [{ type: "tool_use", id: "toolu_1", name: "screenshot", input: {} }] }, { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_1", content: [{ type: "image", source: { type: "base64", media_type: "image/jpeg", data: b64(buf) } }] }] }] }) },
  "openai image_url": { api: "openai", body: (buf, stream) => ({ ...API.openai.body("sys", "x", stream), messages: [{ role: "user", content: [{ type: "text", text: "what is this" }, { type: "image_url", image_url: { url: dataUrl(buf, "image/png") } }] }] }) },
  "openai file": { api: "openai", body: (buf, stream) => ({ ...API.openai.body("sys", "x", stream), messages: [{ role: "user", content: [{ type: "file", file: { filename: "a.pdf", file_data: dataUrl(buf, "application/pdf") } }, { type: "text", text: "summarise" }] }] }) },
  "openai input_audio": { api: "openai", body: (buf, stream) => ({ ...API.openai.body("sys", "x", stream), messages: [{ role: "user", content: [{ type: "input_audio", input_audio: { data: b64(buf), format: "wav" } }] }] }) },
  "responses input_image": { api: "responses", body: (buf, stream) => ({ model: "gpt-fake", ...(stream ? { stream: true } : {}), input: [{ role: "user", content: [{ type: "input_text", text: "what" }, { type: "input_image", image_url: dataUrl(buf, "image/webp") }] }] }) },
  "responses input_file": { api: "responses", body: (buf, stream) => ({ model: "gpt-fake", ...(stream ? { stream: true } : {}), input: [{ type: "message", role: "user", content: [{ type: "input_file", filename: "r.pdf", file_data: dataUrl(buf, "application/pdf") }] }] }) },
  "gemini inlineData": { api: "gemini", body: (buf) => ({ contents: [{ role: "user", parts: [{ text: "describe" }, { inlineData: { mimeType: "image/png", data: b64(buf) } }] }] }) },
  "gemini inline_data": { api: "gemini", body: (buf) => ({ contents: [{ role: "user", parts: [{ inline_data: { mime_type: "application/pdf", data: b64(buf) } }] }] }) },
  "ollama chat images": { api: "ollamaChat", body: (buf, stream) => ({ ...API.ollamaChat.body("sys", "x", stream), messages: [{ role: "user", content: "what is in this picture?", images: [b64(buf)] }] }) },
  "ollama generate images": { api: "ollamaGenerate", body: (buf, stream) => ({ ...API.ollamaGenerate.body("sys", "what is in this picture?", stream), images: [b64(buf)] }) }
};

let fp, md, vt;
before(async () => {
  fp = await startFakeProvider();
  md = await startMetaDefender({ known: { [sha256(BAD)]: { result: 1, detected: 12, total: 30, threat: "Trojan.FakeFamily" }, [sha256(GOOD)]: { result: 0, detected: 0, total: 30 } } });
  vt = await startVirusTotal({ known: { [sha256(BAD)]: { malicious: 40, undetected: 20, label: "trojan.fakefam" }, [sha256(GOOD)]: { malicious: 0, undetected: 60 } } });
});
after(async () => { await fp?.close(); await md?.close(); await vt?.close(); });

// A console that records alerts (the proxy is enrolled with a test install token, so alerts are posted).
async function startConsole() {
  const alerts = [];
  const srv = http.createServer((q, r) => { let b = ""; q.on("data", (d) => (b += d)); q.on("end", () => { if (q.url === "/api/alerts") alerts.push(b); r.writeHead(q.url.startsWith("/api/policy") ? 404 : 201); r.end("{}"); }); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, parsed: () => alerts.map((a) => JSON.parse(a)), close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(() => r()); }) };
}

async function proxy(mode, fileScan, extra = {}) {
  return createProxy({
    port: 0, mode, policy: { captureTier: "content-free", fileScan }, systemConfig: null, env: {},
    routes: { "/anthropic": fp.url, "/openai": `${fp.url}/v1`, "/gemini": fp.url, "/ollama": fp.url },
    fileScanKeys: { metadefender: TEST_KEY, virustotal: TEST_KEY }, fileScanEndpoints: { metadefender: md.base, virustotal: vt.base }, fileScanPollMs: 5,
    ...extra
  });
}
const send = (px, form, buf, stream) => {
  const f = FORMS[form];
  answer(fp, API[f.api], "Fine.", { stream });
  return request(px.url, pathOf(API[f.api], stream), { body: f.body(buf, stream) });
};

test("fileParts finds the one inline file in every adapter's form, with its media type and decoded bytes", () => {
  const KIND = { anthropic: "anthropic", openai: "openai-chat", responses: "openai-responses", gemini: "gemini", ollamaChat: "ollama", ollamaGenerate: "ollama" };
  for (const [name, f] of Object.entries(FORMS)) {
    const { parts } = fileParts(KIND[f.api], f.body(BAD, false));
    assert.equal(parts.length, 1, name);
    assert.deepEqual(parts[0].bytes, BAD, name);
    assert.equal(typeof parts[0].mediaType, "string", name);
  }
  assert.equal(fileParts("openai-chat", { messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: "https://example.com/cat.png" } }] }] }).parts.length, 0, "a URL reference carries no content here");
  assert.equal(fileParts("anthropic", { messages: [{ role: "user", content: [{ type: "document", source: { type: "text", media_type: "text/plain", data: "plain text" } }] }] }).parts.length, 0, "a text document is text, scanned as text");
  const many = { messages: [{ role: "user", images: Array.from({ length: 40 }, (_, i) => b64(Buffer.from(`img ${i}`))) }] };
  const r = fileParts("ollama", many);
  assert.equal(r.parts.length, 32);
  assert.equal(r.over, 8);
});

for (const stream of [false, true]) {
  for (const form of Object.keys(FORMS)) {
    test(`enforce: a malicious file in ${form}${stream ? " (stream)" : ""} is refused before the upstream; a clean one is forwarded`, async () => {
      const px = await proxy("enforce", { provider: "metadefender", mode: "hash" });
      try {
        const n = fp.requests.length;
        const r = await send(px, form, BAD, stream);
        assert.equal(r.status, 403, String(r.raw));
        assert.equal(r.headers["x-moorai-model-proxy"], "refused");
        assert.match(r.raw.toString(), /malicious file/);
        assert.equal(fp.requests.length, n, "a malicious file reached the upstream");
        const ok = await send(px, form, GOOD, stream);
        assert.equal(ok.status, 200, String(ok.raw));
        assert.equal(fp.requests.length, n + 1);
      } finally { await px.close(); }
    });
  }
}

test("report mode: a malicious file is forwarded and alerted (enforcement LIMITED), content-free", async () => {
  const con = await startConsole();
  const px = await proxy("report", { provider: "virustotal", mode: "hash" }, { console: { serverUrl: con.url, tenant: "t", installToken: "tok-fs-0001" } });
  try {
    const n = fp.requests.length;
    const r = await send(px, "anthropic image", BAD, false);
    assert.equal(r.status, 200);
    assert.equal(fp.requests.length, n + 1);
    assert.ok(await waitFor(() => con.parsed().some((a) => a.category === "File scan: malicious file")));
    const a = con.parsed().find((x) => x.category === "File scan: malicious file");
    assert.equal(a.threatId, 17);
    assert.equal(a.enforcement, "LIMITED");
    assert.equal(a.fileScan.provider, "virustotal");
    assert.equal(a.fileScan.detections, 40);
    assert.equal(a.fileScan.threat, "trojan.fakefam");
    assert.equal(a.fileScan.mimeClass, "image");
    assert.equal(a.tool, "model-proxy:file-scan");
    assert.equal(a.sha256, undefined);
    for (const raw of con.alerts) { assert.ok(!raw.includes(sha256(BAD)), "raw hash"); assert.ok(!raw.includes(b64(BAD)), "content"); assert.ok(!raw.includes(TEST_KEY), "key"); }
  } finally { await px.close(); await con.close(); }
});

test("iocHash: the raw SHA-256 goes in only for a malicious verdict", async () => {
  const con = await startConsole();
  const px = await proxy("enforce", { provider: "metadefender", mode: "hash", iocHash: true, onUnknown: "allow" }, { console: { serverUrl: con.url, tenant: "t", installToken: "tok-fs-0002" } });
  try {
    await send(px, "openai image_url", BAD, false);
    await send(px, "openai image_url", NEW, false);
    assert.ok(await waitFor(() => con.parsed().some((a) => a.category === "File scan: unknown file") && con.parsed().some((a) => a.category === "File scan: malicious file")));
    assert.equal(con.parsed().find((a) => a.category === "File scan: malicious file").sha256, sha256(BAD));
    assert.equal(con.parsed().find((a) => a.category === "File scan: unknown file").sha256, undefined);
  } finally { await px.close(); await con.close(); }
});

test("onMalicious report: the malicious file is forwarded even in enforce mode, with an alert", async () => {
  const px = await proxy("enforce", { provider: "metadefender", mode: "hash", onMalicious: "report" });
  try { assert.equal((await send(px, "gemini inlineData", BAD, false)).status, 200); } finally { await px.close(); }
});

test("hash mode, onUnknown: allow forwards, block refuses, ask is refused headless; the provider saw only GET by hash", async () => {
  for (const [onUnknown, status] of [["allow", 200], ["block", 403], ["ask", 403]]) {
    const before = md.requests.length;
    const px = await proxy("enforce", { provider: "metadefender", mode: "hash", onUnknown });
    try {
      const r = await send(px, "responses input_file", NEW, false);
      assert.equal(r.status, status, `${onUnknown}: ${r.raw}`);
      const seen = md.requests.slice(before);
      assert.ok(seen.length >= 1);
      for (const q of seen) { assert.equal(q.method, "GET"); assert.match(q.path, /^\/v4\/hash\//); assert.equal(q.body.length, 0); }
    } finally { await px.close(); }
  }
});

test("upload mode: an unknown file is uploaded and polled to a verdict before the request is forwarded", async () => {
  const up = await startMetaDefender({ pendingPolls: 1, uploadVerdict: { result: 1, detected: 2, total: 30, threat: "Fake.Uploaded" } });
  const px = await proxy("enforce", { provider: "metadefender", mode: "upload", timeoutMs: 5000 }, { fileScanEndpoints: { metadefender: up.base } });
  try {
    const n = fp.requests.length;
    const r = await send(px, "ollama chat images", NEW, true);
    assert.equal(r.status, 403, String(r.raw));
    assert.equal(fp.requests.length, n);
    assert.ok(up.requests.some((q) => q.method === "POST" && q.path === "/v4/file" && q.body.equals(NEW)));
  } finally { await px.close(); await up.close(); }
});

test("fail mode: a provider timeout under closed refuses with a FAIL_CLOSED alert; under open it follows onUnknown", async () => {
  const slow = await startMetaDefender({ delayMs: 1500 });
  const con = await startConsole();
  try {
    const closed = await proxy("report", { provider: "metadefender", mode: "hash", timeoutMs: 150 }, { fileScanEndpoints: { metadefender: slow.base }, resolveFailMode: () => ({ mode: "closed", source: "policy" }), console: { serverUrl: con.url, tenant: "t", installToken: "tok-fs-0003" } });
    try {
      const n = fp.requests.length;
      const t0 = Date.now();
      const r = await send(closed, "anthropic document", NEW, false);
      assert.equal(r.status, 403, String(r.raw));
      assert.ok(Date.now() - t0 < 1400, "never hangs past timeoutMs");
      assert.match(r.raw.toString(), /not scanned/);
      assert.equal(fp.requests.length, n);
      assert.ok(await waitFor(() => con.parsed().some((a) => a.reasonCode === "FAIL_CLOSED" && a.category === "Fail-closed: file not scanned")));
    } finally { await closed.close(); }
    const open = await proxy("enforce", { provider: "metadefender", mode: "hash", timeoutMs: 150 }, { fileScanEndpoints: { metadefender: slow.base }, resolveFailMode: () => ({ mode: "open", source: "policy" }) });
    try { assert.equal((await send(open, "anthropic document", NEW, false)).status, 200); } finally { await open.close(); }
  } finally { await slow.close(); await con.close(); }
});

test("rate limit: a provider 429 is an error that follows the fail mode", async () => {
  const limited = await startVirusTotal({ rateLimit: true });
  try {
    const closed = await proxy("enforce", { provider: "virustotal", mode: "hash" }, { fileScanEndpoints: { virustotal: limited.base } });
    try { assert.equal((await send(closed, "openai file", NEW, false)).status, 403, "enforce falls back to closed"); } finally { await closed.close(); }
    const open = await proxy("enforce", { provider: "virustotal", mode: "hash" }, { fileScanEndpoints: { virustotal: limited.base }, resolveFailMode: () => ({ mode: "open", source: "policy" }) });
    try { assert.equal((await send(open, "openai file", NEW, false)).status, 200); } finally { await open.close(); }
  } finally { await limited.close(); }
});

test("mode off (the default) never calls a provider", async () => {
  const before = md.requests.length + vt.requests.length;
  const px = await proxy("enforce", undefined);
  try {
    assert.equal((await send(px, "anthropic image", BAD, false)).status, 200);
    assert.equal(md.requests.length + vt.requests.length, before);
  } finally { await px.close(); }
});

test("the API key never appears in the proxy's log, its alerts or its error bodies", async () => {
  const con = await startConsole();
  const lines = [];
  const orig = process.stderr.write.bind(process.stderr);
  process.stderr.write = (c, ...rest) => { lines.push(String(c)); return orig(c, ...rest); };
  const wrongKeyMd = await startMetaDefender({ key: "the-only-accepted-key-123456" });
  try {
    for (const [ep, fm] of [[md.base, "closed"], [wrongKeyMd.base, "closed"]]) {
      const px = await proxy("enforce", { provider: "metadefender", mode: "hash", onUnknown: "block" }, { log: true, fileScanEndpoints: { metadefender: ep }, resolveFailMode: () => ({ mode: fm, source: "policy" }), console: { serverUrl: con.url, tenant: "t", installToken: "tok-fs-0004" } });
      try {
        for (const buf of [BAD, NEW]) { const r = await send(px, "anthropic image", buf, false); assert.ok(!r.raw.toString().includes(TEST_KEY)); assert.ok(!JSON.stringify(r.headers).includes(TEST_KEY)); }
      } finally { await px.close(); }
    }
    await waitFor(() => con.alerts.length >= 3);
    assert.ok(con.alerts.length >= 3);
    for (const a of con.alerts) assert.ok(!a.includes(TEST_KEY), "alert");
    assert.ok(lines.length > 0, "--log wrote lines");
    for (const l of lines) assert.ok(!l.includes(TEST_KEY), "log");
  } finally { process.stderr.write = orig; await wrongKeyMd.close(); await con.close(); }
});
