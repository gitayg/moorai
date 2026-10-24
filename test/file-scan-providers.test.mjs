// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/file-scan-providers.test.mjs
//
// The two cloud file-scanning providers behind one interface (cli/file-scan-metadefender.mjs,
// cli/file-scan-virustotal.mjs), against fake servers that answer in each provider's documented shapes
// (test/file-scan-fakes.mjs). No real API is called and no real key exists.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createMetaDefender, parseReport } from "../cli/file-scan-metadefender.mjs";
import { createVirusTotal, parseFile, parseAnalysis } from "../cli/file-scan-virustotal.mjs";
import { FileScanError } from "../cli/file-scan-http.mjs";
import { startMetaDefender, startVirusTotal, sha256, TEST_KEY } from "./file-scan-fakes.mjs";

const BAD = Buffer.from("pretend-malicious-sample-bytes-0001");
const GOOD = Buffer.from("an ordinary harmless document body");
const NEW = Buffer.from("never seen by any provider before 77");

// ---- MetaDefender Cloud ----
test("MetaDefender: a hash lookup hit is parsed from scan_results (infected, detections, threat name); the key rides the apikey header", async () => {
  const md = await startMetaDefender({ known: { [sha256(BAD)]: { result: 1, detected: 12, total: 30, threat: "Trojan.FakeFamily" }, [sha256(GOOD)]: { result: 0, detected: 0, total: 30 } } });
  try {
    const p = createMetaDefender({ key: TEST_KEY, base: md.base });
    const hit = await p.lookup(sha256(BAD), {});
    assert.deepEqual({ state: hit.state, verdict: hit.verdict, detections: hit.detections, engines: hit.engines, threat: hit.threat }, { state: "found", verdict: "malicious", detections: 12, engines: 30, threat: "Trojan.FakeFamily" });
    const clean = await p.lookup(sha256(GOOD), {});
    assert.equal(clean.verdict, "clean");
    assert.equal(md.requests[0].method, "GET");
    assert.equal(md.requests[0].path, `/v4/hash/${sha256(BAD)}`);
    assert.equal(md.requests[0].headers.apikey, TEST_KEY);
    assert.equal(md.requests[0].body.length, 0);
  } finally { await md.close(); }
});

test("MetaDefender: 404 'The hash was not found' is unknown, not an error", async () => {
  const md = await startMetaDefender();
  try {
    const r = await createMetaDefender({ key: TEST_KEY, base: md.base }).lookup(sha256(NEW), {});
    assert.equal(r.state, "unknown");
  } finally { await md.close(); }
});

test("MetaDefender: upload is POST /v4/file with the raw bytes and a filename header, then GET /v4/file/{data_id} polls to a verdict", async () => {
  const md = await startMetaDefender({ pendingPolls: 2, uploadVerdict: { result: 1, detected: 3, total: 30, threat: "Fake.Dropper" } });
  try {
    const p = createMetaDefender({ key: TEST_KEY, base: md.base });
    const { id } = await p.upload(NEW, { filename: "file.bin" });
    assert.ok(id);
    const up = md.requests.find((r) => r.method === "POST");
    assert.equal(up.path, "/v4/file");
    assert.deepEqual(up.body, NEW);
    assert.equal(up.headers.filename, "file.bin");
    assert.equal(up.headers.samplesharing, undefined, "samplesharing only when privateScan is set");
    assert.equal((await p.poll(id, {})).state, "pending");
    assert.equal((await p.poll(id, {})).state, "pending");
    const done = await p.poll(id, {});
    assert.equal(done.state, "found");
    assert.equal(done.verdict, "malicious");
    assert.equal(done.threat, "Fake.Dropper");
  } finally { await md.close(); }
});

test("MetaDefender: privateScan sends samplesharing: 0 on upload", async () => {
  const md = await startMetaDefender({ pendingPolls: 0 });
  try {
    await createMetaDefender({ key: TEST_KEY, base: md.base, privateScan: true }).upload(NEW, {});
    assert.equal(md.requests.find((r) => r.method === "POST").headers.samplesharing, "0");
  } finally { await md.close(); }
});

test("MetaDefender: scan_all_result_i codes map to verdicts (documented code table)", () => {
  const r = (i, extra = {}) => parseReport({ scan_results: { scan_all_result_i: i, total_detected_avs: 0, total_avs: 10, progress_percentage: 100, ...extra } });
  for (const i of [1, 8, 27, 28]) assert.equal(r(i).verdict, "malicious", `code ${i}`);
  for (const i of [0, 7]) assert.equal(r(i).verdict, "clean", `code ${i}`);
  for (const i of [2, 26, 18]) assert.deepEqual([r(i).state, r(i).why], ["unknown", "suspicious"], `code ${i}`);
  for (const i of [3, 9, 10, 12, 23, 252]) assert.deepEqual([r(i).state, r(i).why], ["unknown", "incomplete"], `code ${i}`);
  for (const i of [254, 255]) assert.equal(r(i).state, "pending", `code ${i}`);
  assert.equal(r(0, { progress_percentage: 40 }).state, "pending");
  assert.throws(() => r(253), (e) => e instanceof FileScanError && e.kind === "rate-limit");
  assert.equal(parseReport({}).state, "unknown", "a body with no scan_results is unknown");
});

test("MetaDefender: 429 is a rate-limit error carrying X-RateLimit-Reset-In; 401 is an auth error; neither message holds the key", async () => {
  const md = await startMetaDefender({ rateLimit: true });
  try {
    const p = createMetaDefender({ key: TEST_KEY, base: md.base });
    await assert.rejects(p.lookup(sha256(NEW), {}), (e) => e instanceof FileScanError && e.kind === "rate-limit" && e.retryAfterMs === 60000 && !String(e.message).includes(TEST_KEY) && !String(e.stack).includes(TEST_KEY));
    const wrong = createMetaDefender({ key: "wrong-key-also-not-real-123", base: md.base });
    md.state.rateLimit = false;
    await assert.rejects(wrong.lookup(sha256(NEW), {}), (e) => e instanceof FileScanError && e.kind === "auth" && !String(e.message).includes("wrong-key"));
  } finally { await md.close(); }
});

// ---- VirusTotal ----
test("VirusTotal: GET /api/v3/files/{sha256} parses last_analysis_stats and the suggested threat label; the key rides x-apikey", async () => {
  const vt = await startVirusTotal({ known: { [sha256(BAD)]: { malicious: 41, undetected: 20, label: "trojan.fakefam/generic" }, [sha256(GOOD)]: { malicious: 0, undetected: 55, harmless: 5 } } });
  try {
    const p = createVirusTotal({ key: TEST_KEY, base: vt.base });
    const hit = await p.lookup(sha256(BAD), {});
    assert.deepEqual({ state: hit.state, verdict: hit.verdict, detections: hit.detections, engines: hit.engines, threat: hit.threat }, { state: "found", verdict: "malicious", detections: 41, engines: 61, threat: "trojan.fakefam/generic" });
    assert.equal((await p.lookup(sha256(GOOD), {})).verdict, "clean");
    assert.equal(vt.requests[0].method, "GET");
    assert.equal(vt.requests[0].path, `/api/v3/files/${sha256(BAD)}`);
    assert.equal(vt.requests[0].headers["x-apikey"], TEST_KEY);
  } finally { await vt.close(); }
});

test("VirusTotal: 404 NotFoundError is unknown", async () => {
  const vt = await startVirusTotal();
  try { assert.equal((await createVirusTotal({ key: TEST_KEY, base: vt.base }).lookup(sha256(NEW), {})).state, "unknown"); } finally { await vt.close(); }
});

test("VirusTotal: parsing — suspicious-only is unknown/suspicious, no engine verdict yet is unknown, the label falls back to the most common engine result", () => {
  const f = (stats, extra = {}) => parseFile({ data: { attributes: { last_analysis_stats: stats, ...extra } } });
  assert.deepEqual([f({ malicious: 0, suspicious: 2, undetected: 50 }).state, f({ malicious: 0, suspicious: 2, undetected: 50 }).why], ["unknown", "suspicious"]);
  assert.equal(f({ malicious: 0, suspicious: 0, undetected: 0, harmless: 0 }).state, "unknown");
  const r = f({ malicious: 3, undetected: 10 }, { last_analysis_results: { A: { category: "malicious", result: "Win.Fake-1" }, B: { category: "malicious", result: "Win.Fake-1" }, C: { category: "malicious", result: "Other" }, D: { category: "undetected", result: null } } });
  assert.equal(r.threat, "Win.Fake-1");
  assert.equal(parseAnalysis({ data: { attributes: { status: "queued", stats: {} } } }).state, "pending");
  assert.equal(parseAnalysis({ data: { attributes: { status: "in-progress", stats: { malicious: 1 } } } }).state, "pending");
  assert.equal(parseAnalysis({ data: { attributes: { status: "completed", stats: { malicious: 2, undetected: 40 } } } }).verdict, "malicious");
});

test("VirusTotal: upload is multipart POST /api/v3/files (field `file`), then GET /api/v3/analyses/{id} polls to completed", async () => {
  const vt = await startVirusTotal({ pendingPolls: 1, uploadVerdict: { malicious: 5, undetected: 50, engineResult: "Fake.Uploaded" } });
  try {
    const p = createVirusTotal({ key: TEST_KEY, base: vt.base });
    const { id } = await p.upload(NEW, { filename: "a.pdf" });
    const up = vt.requests.find((r) => r.method === "POST");
    assert.equal(up.path, "/api/v3/files");
    assert.match(String(up.headers["content-type"]), /^multipart\/form-data; boundary=/);
    assert.ok(up.body.includes(NEW), "the file bytes are in the multipart body");
    assert.match(up.body.toString("latin1"), /name="file"/);
    assert.equal((await p.poll(id, {})).state, "pending");
    const done = await p.poll(id, {});
    assert.deepEqual([done.state, done.verdict, done.threat], ["found", "malicious", "Fake.Uploaded"]);
  } finally { await vt.close(); }
});

test("VirusTotal: a file over 32 MB goes through GET /files/upload_url, and only to a same-origin URL", async () => {
  const vt = await startVirusTotal({ pendingPolls: 0 });
  try {
    const p = createVirusTotal({ key: TEST_KEY, base: vt.base, directMax: 16 });
    await p.upload(NEW, {});
    assert.ok(vt.requests.some((r) => r.method === "GET" && r.path === "/api/v3/files/upload_url"));
    assert.ok(vt.requests.some((r) => r.method === "POST" && r.path === "/_ah/upload/fake-once"));
    // The upload URL is the provider's answer; the key is never sent to another origin.
    const evil = createVirusTotal({ key: TEST_KEY, base: vt.base, directMax: 16, fetch: async (url, init) => (String(url).endsWith("/files/upload_url") ? new Response(JSON.stringify({ data: "https://attacker.example/upload" }), { status: 200, headers: { "content-type": "application/json" } }) : fetch(url, init)) });
    await assert.rejects(evil.upload(NEW, {}), (e) => e instanceof FileScanError && e.kind === "provider");
  } finally { await vt.close(); }
});

test("VirusTotal: 429 QuotaExceededError is a rate-limit error; 401 is auth; no message holds the key", async () => {
  const vt = await startVirusTotal({ rateLimit: true });
  try {
    await assert.rejects(createVirusTotal({ key: TEST_KEY, base: vt.base }).lookup(sha256(NEW), {}), (e) => e.kind === "rate-limit" && !String(e.stack).includes(TEST_KEY));
    vt.state.rateLimit = false;
    await assert.rejects(createVirusTotal({ key: "wrong-key-also-not-real-123", base: vt.base }).lookup(sha256(NEW), {}), (e) => e.kind === "auth" && !String(e.stack).includes("wrong-key"));
  } finally { await vt.close(); }
});

test("an aborted signal is a timeout error, for both providers", async () => {
  const md = await startMetaDefender({ delayMs: 500 });
  const vt = await startVirusTotal({ delayMs: 500 });
  try {
    for (const p of [createMetaDefender({ key: TEST_KEY, base: md.base }), createVirusTotal({ key: TEST_KEY, base: vt.base })]) {
      await assert.rejects(p.lookup(sha256(NEW), { signal: AbortSignal.timeout(50) }), (e) => e instanceof FileScanError && e.kind === "timeout", p.name);
    }
  } finally { await md.close(); await vt.close(); }
});
