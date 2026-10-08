// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/index-scan-serve.test.mjs
//
// moorai-serve's POST /v1/index-scan (cli/moorai-serve.mjs): any RAG framework calls it with the chunks it
// is about to embed and gets one content-free verdict per chunk. Real HTTP on loopback against the real
// CLI process. Fixtures are vector-3 corpus samples labelled stage "index".
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SERVE = join(ROOT, "cli", "moorai-serve.mjs");
const V3 = JSON.parse(readFileSync(join(ROOT, "test", "redteam", "vector3-supply-chain.json"), "utf8"));
const v3 = (id) => [...V3.attacks, ...V3.benign].find((s) => s.id === id).text;
const POISONED = v3("v3-cfg-013");
const BENIGN = v3("v3-benign-019");
const SOURCE = "s3://acme-kb/handbook/onboarding.md";

function sandbox(policy) {
  const home = mkdtempSync(join(tmpdir(), "moorai-idxserve-"));
  mkdirSync(join(home, "proj"), { recursive: true });
  if (policy) writeFileSync(join(home, "policy.json"), JSON.stringify(policy));
  return home;
}
function start(home, args = [], env = {}) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [SERVE, "--port", "0", ...args], { cwd: join(home, "proj"), env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, MOORAI_SERVICE_ID: "rag-ingest", MOORAI_SERVER_URL: "http://127.0.0.1:1", ...env } });
    let out = "", err = "";
    const t = setTimeout(() => { c.kill(); rej(new Error(`serve did not start: ${err}`)); }, 15000);
    c.stderr.on("data", (d) => (err += d));
    c.stdout.on("data", (d) => {
      out += d;
      const nl = out.indexOf("\n");
      if (nl < 0) return;
      clearTimeout(t);
      res({ ...JSON.parse(out.slice(0, nl)), stop: () => new Promise((r) => { c.once("close", r); c.kill("SIGTERM"); }) });
    });
    c.on("close", (code) => { clearTimeout(t); if (!out) rej(new Error(`serve exited ${code}: ${err}`)); });
  });
}
function req(url, { method = "POST", path = "/v1/index-scan", body, headers = {} } = {}) {
  const u = new URL(path, url);
  const data = body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body);
  return new Promise((res, rej) => {
    const r = http.request({ host: u.hostname, port: u.port, path: u.pathname, method, headers: { ...(data !== undefined ? { "content-type": "application/json", "content-length": Buffer.byteLength(data) } : {}), ...headers } }, (resp) => {
      let s = ""; resp.on("data", (d) => (s += d)); resp.on("end", () => res({ status: resp.statusCode, raw: s, json: (() => { try { return JSON.parse(s); } catch { return null; } })() }));
    });
    r.on("error", rej);
    if (data !== undefined) r.write(data);
    r.end();
  });
}

test("index-scan: one verdict per chunk; report-first by default; nothing about the content comes back", async () => {
  const home = sandbox();
  const s = await start(home);
  try {
    const r = await req(s.listening, { body: { chunks: [BENIGN, POISONED, { pageContent: POISONED, metadata: { page: 3 } }], source: SOURCE } });
    assert.equal(r.status, 200, r.raw);
    assert.equal(r.json.action, "report");
    assert.deepEqual(r.json.allowed, [0]);
    assert.deepEqual(r.json.flagged, [1, 2]);
    assert.deepEqual(r.json.denied, []);
    assert.equal(r.json.results[1].verdict, "flag");
    assert.ok(r.json.results[1].threatIds.includes(40));
    assert.ok(r.json.results[1].findings.every((f) => f.stage === "index"));
    for (const s2 of ["attacker-cdn", "Storybook", "acme-kb", "onboarding"]) assert.ok(!r.raw.includes(s2), `leaked ${s2}: ${r.raw}`);
  } finally { await s.stop(); rmTree(home); }
});

test("index-scan: policy indexScanAction block denies the poisoned chunk and keeps the benign one", async () => {
  const home = sandbox({ captureTier: "content-free", indexScanAction: "block" });
  const s = await start(home, ["--policy-file", join(home, "policy.json")]);
  try {
    const r = await req(s.listening, { body: { chunks: [BENIGN, POISONED] } });
    assert.equal(r.status, 200, r.raw);
    assert.equal(r.json.action, "block");
    assert.deepEqual(r.json.denied, [1]);
    assert.deepEqual(r.json.allowed, [0]);
    assert.match(r.json.results[1].reasons.join(","), /#40/);
  } finally { await s.stop(); rmTree(home); }
});

test("index-scan: the server's conventions hold — validation, content type, method, body cap, Host check", async () => {
  const home = sandbox();
  const s = await start(home, ["--max-body", "4096"]);
  try {
    assert.equal((await req(s.listening, { body: { chunks: "not an array" } })).status, 400);
    assert.equal((await req(s.listening, { body: { chunks: [42] } })).status, 400);
    assert.equal((await req(s.listening, { body: { chunks: ["x"], source: 7 } })).status, 400);
    assert.equal((await req(s.listening, { body: { chunks: ["x"] }, headers: { "content-type": "text/plain" } })).status, 415);
    assert.equal((await req(s.listening, { method: "GET" })).status, 405);
    assert.equal((await req(s.listening, { body: { chunks: ["a".repeat(8192)] } })).status, 413);
    assert.equal((await req(s.listening, { body: { chunks: ["x"] }, headers: { host: "attacker.example:80" } })).status, 421);
    const ok = await req(s.listening, { body: { chunks: [] } });
    assert.deepEqual({ s: ok.status, n: ok.json.results.length }, { s: 200, n: 0 });
  } finally { await s.stop(); rmTree(home); }
});

test("index-scan: content-free alerts at stage index; the source only as a keyed hash", async () => {
  const alerts = [];
  const srv = http.createServer((q, r) => { let b = ""; q.on("data", (d) => (b += d)); q.on("end", () => { if (q.url === "/api/alerts") alerts.push(b); r.writeHead(q.url.startsWith("/api/policy") ? 404 : 201); r.end("{}"); }); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const home = sandbox();
  const s = await start(home, [], { MOORAI_SERVER_URL: `http://127.0.0.1:${srv.address().port}`, MOORAI_INSTALL_TOKEN: "tok-index-serve-1", MOORAI_TENANT: "t-idx" });
  try {
    await req(s.listening, { body: { chunks: [POISONED], source: SOURCE } });
    await s.stop();
    const idx = alerts.map((b) => JSON.parse(b)).filter((a) => a.stage === "index");
    assert.ok(idx.length >= 1, `alerts: ${alerts.join("\n")}`);
    for (const b of alerts) for (const s2 of ["attacker-cdn", "Storybook", "acme-kb"]) assert.ok(!b.includes(s2), b);
    assert.ok(idx.every((a) => a.surface === "serve" && /^h2:/.test(a.indexSource) && [40, 21].includes(a.threatId)), JSON.stringify(idx));
  } finally { srv.close(); rmTree(home); }
});
