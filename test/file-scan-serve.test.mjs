// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/file-scan-serve.test.mjs
//
// moorai-serve's POST /v1/file-scan (cli/moorai-serve.mjs): for frameworks that send files to a model some
// other way than through the model proxy. Same token auth as /v1/tool-call; the file (base64) or only its
// SHA-256; a content-free verdict back. In process, against the fake providers.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createServer, parseArgs } from "../cli/moorai-serve.mjs";
import { startMetaDefender, startVirusTotal, sha256, TEST_KEY } from "./file-scan-fakes.mjs";

const BAD = Buffer.from("pretend-malicious-sample-bytes-0001");
const GOOD = Buffer.from("an ordinary harmless document body");
const NEW = Buffer.from("never seen by any provider before 77");
const TOKEN = "serve-token-0123456789abcdef";
let md, vt;
before(async () => {
  md = await startMetaDefender({ known: { [sha256(BAD)]: { result: 1, detected: 12, total: 30, threat: "Trojan.FakeFamily" }, [sha256(GOOD)]: { result: 0, detected: 0, total: 30 } } });
  vt = await startVirusTotal({ known: { [sha256(BAD)]: { malicious: 40, undetected: 20 } } });
});
after(async () => { await md?.close(); await vt?.close(); });

function req(url, body, { token = TOKEN, path = "/v1/file-scan" } = {}) {
  const u = new URL(path, url);
  const data = JSON.stringify(body);
  return new Promise((res, rej) => {
    const r = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data), ...(token ? { authorization: `Bearer ${token}` } : {}) } }, (resp) => {
      let s = ""; resp.on("data", (d) => (s += d)); resp.on("end", () => res({ status: resp.statusCode, raw: s, json: (() => { try { return JSON.parse(s); } catch { return null; } })() }));
    });
    r.on("error", rej); r.write(data); r.end();
  });
}
const serve = (fileScan, extra = {}) => createServer({ port: 0, tokens: [TOKEN], policy: { fileScan }, env: {}, systemConfig: null, fileScanKeys: { metadefender: TEST_KEY, virustotal: TEST_KEY }, fileScanEndpoints: { metadefender: md.base, virustotal: vt.base }, ...extra });

test("/v1/file-scan: malicious denied, clean allowed, unknown follows onUnknown; the verdict is content-free", async () => {
  const s = await serve({ provider: "metadefender", mode: "hash", onUnknown: "block" });
  try {
    const b = await req(s.url, { data: BAD.toString("base64"), mediaType: "application/pdf" });
    assert.equal(b.status, 200, b.raw);
    assert.deepEqual([b.json.decision, b.json.verdict, b.json.provider, b.json.detections, b.json.threat], ["deny", "malicious", "metadefender", 12, "Trojan.FakeFamily"]);
    assert.ok(!b.raw.includes(BAD.toString("base64")));
    assert.equal((await req(s.url, { data: GOOD.toString("base64") })).json.decision, "allow");
    const u = await req(s.url, { data: NEW.toString("base64") });
    assert.deepEqual([u.json.decision, u.json.verdict], ["deny", "unknown"]);
  } finally { await s.close(); }
});

test("/v1/file-scan: a bare sha256 is looked up (hash only); no content is ever sent", async () => {
  const s = await serve({ provider: "virustotal", mode: "upload" });
  try {
    const before = vt.requests.length;
    const r = await req(s.url, { sha256: sha256(BAD) });
    assert.deepEqual([r.json.decision, r.json.verdict], ["deny", "malicious"]);
    const n = await req(s.url, { sha256: sha256(NEW) });
    assert.equal(n.json.verdict, "unknown", "a hash alone cannot be uploaded");
    for (const q of vt.requests.slice(before)) assert.equal(q.method, "GET");
    assert.equal((await req(s.url, { sha256: "nothex" })).status, 400);
    assert.equal((await req(s.url, { data: "QQ==", sha256: sha256(BAD) })).status, 400, "exactly one of data / sha256");
    assert.equal((await req(s.url, {})).status, 400);
  } finally { await s.close(); }
});

test("/v1/file-scan: the same token auth as /v1/tool-call", async () => {
  const s = await serve({ provider: "metadefender", mode: "hash" });
  try {
    assert.equal((await req(s.url, { sha256: sha256(GOOD) }, { token: "" })).status, 401);
    assert.equal((await req(s.url, { sha256: sha256(GOOD) }, { token: "wrong-token-0123456789abc" })).status, 401);
  } finally { await s.close(); }
});

test("/v1/file-scan: mode off answers not-scanned without calling a provider", async () => {
  const s = await serve(undefined);
  try {
    const before = md.requests.length + vt.requests.length;
    const r = await req(s.url, { data: BAD.toString("base64") });
    assert.deepEqual([r.json.decision, r.json.verdict, r.json.mode], ["allow", "not-scanned", "off"]);
    assert.equal(md.requests.length + vt.requests.length, before);
  } finally { await s.close(); }
});

test("/v1/file-scan: a provider timeout under failMode.default closed is denied; the key is never in the answer", async () => {
  const slow = await startMetaDefender({ delayMs: 1500 });
  try {
    const s = await serve({ provider: "metadefender", mode: "hash", timeoutMs: 150 }, { policy: { fileScan: { provider: "metadefender", mode: "hash", timeoutMs: 150 }, failMode: { default: "closed" } }, fileScanEndpoints: { metadefender: slow.base } });
    try {
      const r = await req(s.url, { data: NEW.toString("base64") });
      assert.deepEqual([r.json.decision, r.json.verdict, r.json.why], ["deny", "error", "timeout"]);
      assert.ok(!r.raw.includes(TEST_KEY));
    } finally { await s.close(); }
  } finally { await slow.close(); }
});

test("parseArgs: --file-scan-key-file provider=path (repeatable); an unknown provider is refused", () => {
  const o = parseArgs(["--file-scan-key-file", "metadefender=/etc/moorai/md.key", "--file-scan-key-file", "virustotal=/etc/moorai/vt.key"], {});
  assert.deepEqual(o.fileScanKeyFiles, { metadefender: "/etc/moorai/md.key", virustotal: "/etc/moorai/vt.key" });
  assert.throws(() => parseArgs(["--file-scan-key-file", "other=/x"], {}), /metadefender|virustotal/);
});
