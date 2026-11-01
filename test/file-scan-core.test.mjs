// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/file-scan-core.test.mjs
//
// The file scanner (cli/file-scan.mjs): the policy (cli/file-scan-policy.mjs), where keys come from
// (cli/file-scan-keys.mjs), hash-only versus upload, the hash -> verdict cache, the rate limit and its bounded
// queue, the deadline, the decision and the content-free alert. Against the fake providers.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createFileScanner, fileScanDecision, fileScanAlert, mimeClass, sizeBucket } from "../cli/file-scan.mjs";
import { fileScanPolicy, FILE_SCAN_DEFAULTS } from "../cli/file-scan-policy.mjs";
import { loadFileScanKeys, KEY_ENV } from "../cli/file-scan-keys.mjs";
import { startMetaDefender, startVirusTotal, sha256, TEST_KEY } from "./file-scan-fakes.mjs";

const BAD = Buffer.from("pretend-malicious-sample-bytes-0001");
const GOOD = Buffer.from("an ordinary harmless document body");
const NEW = Buffer.from("never seen by any provider before 77");
const cfg = (over = {}) => fileScanPolicy({ fileScan: { provider: "metadefender", mode: "hash", ...over } });

// ---- policy ----
test("policy: default off; every field validated; a bad provider or mode turns scanning off", () => {
  assert.equal(fileScanPolicy(null).mode, "off");
  assert.equal(fileScanPolicy({}).mode, "off");
  assert.equal(FILE_SCAN_DEFAULTS.mode, "off");
  const d = fileScanPolicy({ fileScan: { mode: "hash" } });
  assert.deepEqual({ provider: d.provider, mode: d.mode, onMalicious: d.onMalicious, onUnknown: d.onUnknown, iocHash: d.iocHash }, { provider: "metadefender", mode: "hash", onMalicious: "block", onUnknown: "allow", iocHash: false });
  assert.equal(d.maxBytes, 33554432);
  assert.equal(d.timeoutMs, 10000);
  assert.equal(fileScanPolicy({ fileScan: { mode: "hash", provider: "somethingelse" } }).mode, "off");
  assert.equal(fileScanPolicy({ fileScan: { mode: "everything" } }).mode, "off");
  const v = fileScanPolicy({ fileScan: { provider: "virustotal", mode: "upload", onMalicious: "report", onUnknown: "ask", maxBytes: 1024, timeoutMs: 2500, iocHash: true } });
  assert.deepEqual([v.provider, v.mode, v.onMalicious, v.onUnknown, v.maxBytes, v.timeoutMs, v.iocHash, v.ratePerMinute], ["virustotal", "upload", "report", "ask", 1024, 2500, true, 4]);
  assert.equal(fileScanPolicy({ fileScan: { mode: "hash", onMalicious: "shrug" } }).onMalicious, "block");
  assert.equal(fileScanPolicy({ fileScan: { mode: "hash", iocHash: "yes" } }).iocHash, false, "only true turns on the raw IOC hash");
  assert.equal(fileScanPolicy({ fileScan: { mode: "hash", region: "eu-central" } }).region, "eu-central");
  assert.equal(fileScanPolicy({ fileScan: { mode: "hash", region: "https://attacker.example" } }).region, null, "a region is a name from the documented list, never a URL");
  assert.equal(fileScanPolicy({ fileScan: { mode: "hash", apiKey: "x" } }).apiKey, undefined, "the policy never carries a key");
});

// ---- keys ----
test("keys: the root-owned admin binding, then a root-owned key file, then the environment; never the policy", () => {
  const read = (p) => (p === "/etc/moorai/md.key" ? `${TEST_KEY}\n` : "");
  const a = loadFileScanKeys({ admin: { fileScanKeys: { metadefender: "admin-key-0123456789" } }, keyFiles: { metadefender: "/etc/moorai/md.key" }, env: { [KEY_ENV.metadefender]: "env-key-0123456789" }, read });
  assert.equal(a.keys.metadefender, "admin-key-0123456789");
  assert.equal(a.sources.metadefender, "admin");
  const f = loadFileScanKeys({ admin: null, keyFiles: { metadefender: "/etc/moorai/md.key" }, env: { [KEY_ENV.metadefender]: "env-key-0123456789" }, read });
  assert.deepEqual([f.keys.metadefender, f.sources.metadefender], [TEST_KEY, "file"]);
  const e = loadFileScanKeys({ env: { [KEY_ENV.virustotal]: "env-key-0123456789" }, read });
  assert.deepEqual([e.keys.virustotal, e.sources.virustotal, e.keys.metadefender], ["env-key-0123456789", "env", undefined]);
  // readRootOwned returns "" for a file the agent's user could have written: no key from it.
  assert.equal(loadFileScanKeys({ keyFiles: { virustotal: "/home/u/vt.key" }, read: () => "", env: {} }).keys.virustotal, undefined);
  assert.equal(loadFileScanKeys({ env: { [KEY_ENV.virustotal]: "has a space in it" } }).keys.virustotal, undefined, "a malformed key is ignored");
  assert.equal(loadFileScanKeys.length <= 1, true);
});

// ---- scanner ----
test("hash mode: a malicious hash hit, a clean one and an unknown one; only GET by hash leaves (no content)", async () => {
  const md = await startMetaDefender({ known: { [sha256(BAD)]: { result: 1, detected: 9, total: 30, threat: "Trojan.FakeFamily" }, [sha256(GOOD)]: { result: 0, detected: 0, total: 30 } } });
  try {
    const s = createFileScanner({ keys: { metadefender: TEST_KEY }, endpoints: { metadefender: md.base } });
    const b = await s.scan(BAD, cfg());
    assert.deepEqual([b.verdict, b.detections, b.threat, b.uploaded, b.provider, b.sha256], ["malicious", 9, "Trojan.FakeFamily", false, "metadefender", sha256(BAD)]);
    assert.equal((await s.scan(GOOD, cfg())).verdict, "clean");
    const u = await s.scan(NEW, cfg());
    assert.deepEqual([u.verdict, u.why, u.uploaded], ["unknown", "not-found", false]);
    assert.equal(md.requests.length, 3);
    for (const r of md.requests) { assert.equal(r.method, "GET"); assert.match(r.path, /^\/v4\/hash\/[0-9a-f]{64}$/); assert.equal(r.body.length, 0); }
    for (const buf of [BAD, GOOD, NEW]) assert.ok(!md.requests.some((r) => r.url.includes(buf.toString("hex")) || r.body.includes(buf)), "no file content left");
  } finally { await md.close(); }
});

test("upload mode: an unknown hash is uploaded, then polled to a verdict; a known hash is not uploaded", async () => {
  for (const [start, provider] of [[startMetaDefender, "metadefender"], [startVirusTotal, "virustotal"]]) {
    const f = await start(provider === "metadefender" ? { pendingPolls: 2, known: { [sha256(GOOD)]: { result: 0, detected: 0, total: 30 } }, uploadVerdict: { result: 1, detected: 4, total: 30, threat: "Fake.Up" } } : { pendingPolls: 2, known: { [sha256(GOOD)]: { malicious: 0, undetected: 60 } }, uploadVerdict: { malicious: 4, undetected: 50, engineResult: "Fake.Up" } });
    try {
      const s = createFileScanner({ keys: { [provider]: TEST_KEY }, endpoints: { [provider]: f.base }, pollMs: 10 });
      const c = { ...cfg({ provider, mode: "upload", timeoutMs: 5000 }), ratePerMinute: 600 };
      const r = await s.scan(NEW, c);
      assert.deepEqual([r.verdict, r.uploaded, r.threat], ["malicious", true, "Fake.Up"], provider);
      const n = f.requests.filter((q) => q.method === "POST").length;
      assert.equal(n, 1, provider);
      await s.scan(GOOD, c);
      assert.equal(f.requests.filter((q) => q.method === "POST").length, 1, `${provider}: a known file is not uploaded`);
    } finally { await f.close(); }
  }
});

test("upload mode: a file over maxBytes is not uploaded and is unknown/too-large", async () => {
  const md = await startMetaDefender();
  try {
    const s = createFileScanner({ keys: { metadefender: TEST_KEY }, endpoints: { metadefender: md.base } });
    const r = await s.scan(NEW, cfg({ mode: "upload", maxBytes: 8 }));
    assert.deepEqual([r.verdict, r.why, r.uploaded], ["unknown", "too-large", false]);
    assert.ok(!md.requests.some((q) => q.method === "POST"));
  } finally { await md.close(); }
});

test("cache: the same file is not re-queried inside the TTL; concurrent scans of one file share one query; unknown expires sooner", async () => {
  const md = await startMetaDefender({ known: { [sha256(BAD)]: { result: 1, detected: 9, total: 30 } } });
  try {
    let t = 1000;
    const s = createFileScanner({ keys: { metadefender: TEST_KEY }, endpoints: { metadefender: md.base }, now: () => t, cacheTtlMs: 60000, unknownTtlMs: 5000 });
    const [a, b] = await Promise.all([s.scan(BAD, cfg()), s.scan(Buffer.from(BAD), cfg())]);
    assert.equal(md.requests.length, 1, "single flight");
    assert.equal(a.verdict, "malicious"); assert.equal(b.verdict, "malicious");
    const c = await s.scan(BAD, cfg());
    assert.equal(c.cached, true);
    assert.equal(md.requests.length, 1);
    await s.scan(NEW, cfg());
    await s.scan(NEW, cfg());
    assert.equal(md.requests.length, 2, "unknown cached too");
    t += 6000;
    await s.scan(NEW, cfg());
    assert.equal(md.requests.length, 3, "unknown re-queried after its shorter TTL");
    await s.scan(BAD, cfg());
    assert.equal(md.requests.length, 3, "malicious still cached");
    t += 60000;
    await s.scan(BAD, cfg());
    assert.equal(md.requests.length, 4);
  } finally { await md.close(); }
});

test("the cache is keyed by provider and mode: a hash-mode unknown does not stop an upload-mode scan", async () => {
  const md = await startMetaDefender({ pendingPolls: 0 });
  try {
    const s = createFileScanner({ keys: { metadefender: TEST_KEY }, endpoints: { metadefender: md.base }, pollMs: 5 });
    assert.equal((await s.scan(NEW, cfg())).verdict, "unknown");
    assert.equal((await s.scan(NEW, cfg({ mode: "upload" }))).uploaded, true);
  } finally { await md.close(); }
});

test("timeout: a provider slower than timeoutMs is error/timeout, and the scan returns within the deadline", async () => {
  const md = await startMetaDefender({ delayMs: 1500 });
  try {
    const s = createFileScanner({ keys: { metadefender: TEST_KEY }, endpoints: { metadefender: md.base } });
    const t0 = Date.now();
    const r = await s.scan(NEW, cfg({ timeoutMs: 200 }));
    assert.deepEqual([r.verdict, r.why], ["error", "timeout"]);
    assert.ok(Date.now() - t0 < 1000, `took ${Date.now() - t0} ms`);
  } finally { await md.close(); }
});

test("rate limit: requests past ratePerMinute wait in a bounded queue and never past the deadline; past the queue bound they fail at once", async () => {
  const md = await startMetaDefender();
  try {
    const s = createFileScanner({ keys: { metadefender: TEST_KEY }, endpoints: { metadefender: md.base }, queueMax: 2 });
    const c = { ...cfg({ timeoutMs: 300 }), ratePerMinute: 2 };
    const files = Array.from({ length: 6 }, (_, i) => Buffer.from(`distinct file number ${i}`));
    const t0 = Date.now();
    const rs = await Promise.all(files.map((f) => s.scan(f, c)));
    const took = Date.now() - t0;
    assert.equal(md.requests.length, 2, "only the rate's worth reached the provider");
    assert.equal(rs.filter((r) => r.verdict === "unknown").length, 2);
    const limited = rs.filter((r) => r.verdict === "error" && r.why === "rate-limit");
    assert.equal(limited.length, 4);
    assert.ok(took < 1000, `bounded by the deadline, took ${took} ms`);
  } finally { await md.close(); }
});

test("rate limit: a provider 429 pauses that provider until its reset; the next scans fail fast as rate-limit without a request", async () => {
  const md = await startMetaDefender({ rateLimit: true });
  try {
    const s = createFileScanner({ keys: { metadefender: TEST_KEY }, endpoints: { metadefender: md.base } });
    assert.deepEqual([(await s.scan(NEW, cfg())).verdict, (await s.scan(GOOD, cfg())).why], ["error", "rate-limit"]);
    assert.equal(md.requests.length, 1, "paused after the 429 (X-RateLimit-Reset-In: 60s)");
  } finally { await md.close(); }
});

test("no key for the chosen provider is error/no-key, and nothing is sent", async () => {
  const md = await startMetaDefender();
  try {
    const r = await createFileScanner({ keys: {}, endpoints: { metadefender: md.base } }).scan(BAD, cfg());
    assert.deepEqual([r.verdict, r.why], ["error", "no-key"]);
    assert.equal(md.requests.length, 0);
  } finally { await md.close(); }
});

// ---- decision ----
test("decision: block on malicious, report on malicious, onUnknown allow/ask/block, and errors under each fail mode", () => {
  const d = (verdict, over, opts = {}) => fileScanDecision({ verdict, why: verdict === "error" ? "timeout" : undefined }, cfg(over), { failMode: "open", headless: "deny", ...opts });
  assert.deepEqual([d("clean").action, d("clean").alert], ["allow", false]);
  assert.deepEqual([d("malicious").action, d("malicious").decision], ["deny", "deny"]);
  assert.deepEqual([d("malicious", { onMalicious: "report" }).action, d("malicious", { onMalicious: "report" }).decision], ["allow", "notify"]);
  assert.deepEqual([d("unknown").action, d("unknown").alert], ["allow", true]);
  assert.equal(d("unknown", { onUnknown: "block" }).action, "deny");
  assert.equal(d("unknown", { onUnknown: "ask" }).action, "deny", "an ask with no approver is denied (headless default)");
  assert.equal(d("unknown", { onUnknown: "ask" }, { headless: "allow-with-report" }).action, "allow");
  const closed = d("error", {}, { failMode: "closed" });
  assert.deepEqual([closed.action, closed.failClosed], ["deny", true]);
  assert.deepEqual([d("error").action, d("error").failClosed], ["allow", false], "open: an error is treated as unknown (onUnknown allow)");
  assert.equal(d("error", { onUnknown: "block" }).action, "deny", "open: onUnknown block still blocks an unscanned file");
});

// ---- alert ----
test("alert: content-free — provider, verdict, detections, threat, MIME class, size bucket, keyed hash; the raw SHA-256 only for malicious with iocHash", () => {
  const hash = (s) => `kh:${s.length}`;
  const res = { verdict: "malicious", provider: "metadefender", sha256: sha256(BAD), detections: 9, engines: 30, threat: "Trojan.FakeFamily", uploaded: false };
  const dec = fileScanDecision(res, cfg(), { failMode: "open", headless: "deny" });
  const a = fileScanAlert({ result: res, cfg: cfg(), decision: dec, hash, tool: "model-proxy:file-scan", mime: "application/pdf", size: 200000 });
  assert.equal(a.threatId, 17);
  assert.equal(a.category, "File scan: malicious file");
  assert.equal(a.riskLevel, "Blocked");
  assert.equal(a.decision, "deny");
  assert.equal(a.tool, "model-proxy:file-scan");
  assert.deepEqual(a.fileScan, { provider: "metadefender", verdict: "malicious", mode: "hash", detections: 9, engines: 30, threat: "Trojan.FakeFamily", mimeClass: "pdf", sizeBucket: "64KB-1MB", uploaded: false });
  assert.equal(a.contentHash, hash(`file-scan:${sha256(BAD)}`));
  assert.equal(a.sha256, undefined, "no raw hash without iocHash");
  assert.ok(!JSON.stringify(a).includes(sha256(BAD)));
  const ioc = fileScanAlert({ result: res, cfg: cfg({ iocHash: true }), decision: dec, hash, tool: "t", mime: "image/png", size: 10 });
  assert.equal(ioc.sha256, sha256(BAD));
  const unk = { verdict: "unknown", why: "not-found", provider: "virustotal", sha256: sha256(NEW), uploaded: false };
  const u = fileScanAlert({ result: unk, cfg: cfg({ iocHash: true }), decision: fileScanDecision(unk, cfg(), { failMode: "open" }), hash, tool: "t", mime: "image/png", size: 10 });
  assert.equal(u.sha256, undefined, "an unknown file's hash is not an IOC");
  assert.equal(u.threatId, 0);
  assert.equal(u.category, "File scan: unknown file");
  const err = { verdict: "error", why: "timeout", provider: "metadefender", sha256: sha256(NEW) };
  const fc = fileScanAlert({ result: err, cfg: cfg(), decision: fileScanDecision(err, cfg(), { failMode: "closed" }), hash, tool: "t", mime: "text/plain", size: 10 });
  assert.equal(fc.category, "Fail-closed: file not scanned");
  assert.equal(fc.reasonCode, "FAIL_CLOSED");
  assert.equal(fc.decision, "deny");
  assert.equal(fc.failWhy, "timeout");
});

test("MIME classes and size buckets", () => {
  assert.deepEqual(["image/png", "application/pdf", "text/plain", "audio/wav", "application/zip", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/x-msdownload", ""].map(mimeClass), ["image", "pdf", "text", "audio", "archive", "document", "other", "other"]);
  assert.deepEqual([10, 65536, 1048576, 10485760, 10485761].map(sizeBucket), ["<64KB", "64KB-1MB", "1-10MB", "1-10MB", ">10MB"]);
});
