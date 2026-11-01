// moorai-guard (the `claude -p` wrapper) loads its policy the way the hook and the MCP guard do:
// loadVerifiedPolicy (cli/hook-core.mjs) sends X-Install-Token, verifies the console signature against the
// anchor or the TOFU pin, caches, and falls back to the cache or the last-known-good copy when the console
// is down. Before this, the guard fetched /api/policy with no token (the console answered 401), never
// checked a signature, and so always ran with no tenant policy.
//
// Real guard subprocess, a stand-in console that signs and requires the install token, a throwaway HOME.
// PATH is an empty directory, so `claude` is never found and nothing reaches a model.
//
//   node --test --import ./test/hermetic-env.mjs test/guard-policy.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import net from "node:net";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "cli", "moorai-guard.mjs");
const TENANT = "acme-guard-policy";
const TOKEN = "tok-guard-policy";
const AWS = "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // threat #39 (test/guard-delivery.test.mjs)
const PROMPT = `deploy with ${AWS}`;

const key = generateKeyPairSync("ed25519");
const PUBKEY = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) });
function signed(policy, iat = new Date().toISOString()) {
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), key.privateKey).toString("base64");
  return { ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } };
}
const BLOCK_39 = () => JSON.stringify(signed({ captureTier: "content-free", threatPolicy: { 39: "block" } }));

// The console: /api/policy answers 401 without the install token (as the real one does), alerts are stored.
async function consoleStub(t) {
  const st = { policy: BLOCK_39(), alerts: [], policyNoToken: 0, policyFetches: 0 };
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(PUBKEY); }
      if (req.headers["x-install-token"] !== TOKEN) {
        if (req.url.startsWith("/api/policy")) st.policyNoToken++;
        res.writeHead(401, { "Content-Type": "application/json" }); return res.end(JSON.stringify({ error: "enrollment required" }));
      }
      if (req.method === "POST" && req.url === "/api/alerts") { try { st.alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(201); return res.end("{}"); }
      if (req.url.startsWith("/api/policy")) { st.policyFetches++; res.writeHead(200, { "Content-Type": "application/json" }); return res.end(st.policy); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  let closed = false;
  const close = () => closed ? Promise.resolve() : (closed = true, new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }));
  t.after(close);
  return { url: `http://127.0.0.1:${port}`, st, close };
}
async function deadUrl() {
  const s = net.createServer();
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  const port = s.address().port;
  await new Promise((r) => s.close(r));
  return `http://127.0.0.1:${port}`;
}
function sandbox(t, url) {
  const h = mkdtempSync(join(tmpdir(), "moorai-guard-policy-"));
  t.after(() => rmTree(h));
  mkdirSync(join(h, ".moorai"), { recursive: true });
  setUrl(h, url);
  return h;
}
const setUrl = (h, url) => writeFileSync(join(h, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: TENANT, installToken: TOKEN }));
const CACHE = (h) => join(h, ".moorai", "hook-policy.json");
// The cache as an idle device leaves it: older than its 60 s window, so the guard fetches.
const ageCache = (h) => { const s = (Date.now() - 5 * 60000) / 1000; utimesSync(CACHE(h), s, s); };

function guard(h, args, env = {}) {
  const bin = mkdtempSync(join(tmpdir(), "moorai-guard-nopath-"));
  const t0 = Date.now();
  return new Promise((res) => {
    const c = spawn(process.execPath, [GUARD, ...args], { cwd: h, env: { HOME: h, USERPROFILE: h, PATH: bin, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let err = "";
    c.stderr.on("data", (d) => (err += d));
    c.stdout.on("data", () => {});
    c.on("close", (status) => { rmTree(bin); res({ status, err, ms: Date.now() - t0 }); });
  });
}
// Exit 3 + "blocked by threat policy (#39)": the policy's block was enforced and nothing went to claude -p.
const blocked39 = (r) => r.status === 3 && /blocked by threat policy \(#39\)/.test(r.err);

test("signed policy from a console that requires the install token: its threatPolicy block is enforced", async (t) => {
  const c = await consoleStub(t);
  const h = sandbox(t, c.url);
  const r = await guard(h, ["--decide", "proceed", PROMPT]);
  assert.equal(c.st.policyNoToken, 0, "the guard fetched /api/policy without X-Install-Token (the console answers 401)");
  assert.ok(c.st.policyFetches >= 1, "the guard never fetched the policy with its token");
  assert.ok(blocked39(r), `the signed block on #39 was not enforced: status ${r.status}\n${r.err}`);
});

test("a policy whose signature does not verify is not applied, and the rejection is reported", async (t) => {
  const c = await consoleStub(t);
  const h = sandbox(t, c.url);
  // First contact pins the console key and records the signed policy (block #39) as last-known-good.
  assert.ok(blocked39(await guard(h, ["--decide", "proceed", PROMPT])), "phase 1: the signed block was not enforced");
  // The console (or whatever serverUrl now points at) serves the same signature over a relaxed body.
  const tampered = signed({ captureTier: "content-free", threatPolicy: { 39: "block" } });
  tampered.threatPolicy = { 39: "notify" };
  c.st.policy = JSON.stringify(tampered);
  rmSync(CACHE(h), { force: true });
  c.st.alerts.length = 0;
  const r = await guard(h, ["--decide", "proceed", PROMPT]);
  assert.ok(blocked39(r), `the tampered policy's relaxation was applied: status ${r.status}\n${r.err}`);
  const rej = c.st.alerts.find((a) => a.contentHash === "policy:server:untrusted");
  assert.ok(rej, `no signature-rejected alert; got ${JSON.stringify(c.st.alerts.map((a) => a.contentHash))}`);
  assert.equal(rej.riskLevel, "Critical");
  assert.equal(rej.stage, "policy");
  assert.ok(!JSON.stringify(rej).includes("notify"), "the rejected policy's content left the device");
  assert.ok(c.st.alerts.some((a) => a.contentHash === "policy:lkg:applied"), "the last-known-good fallback was not reported");
});

test("console down: the guard starts promptly and enforces the cached, then the last-known-good, policy", async (t) => {
  const c = await consoleStub(t);
  const h = sandbox(t, c.url);
  assert.ok(blocked39(await guard(h, ["--decide", "proceed", PROMPT])), "phase 1: the signed block was not enforced");
  await c.close();
  setUrl(h, await deadUrl());
  ageCache(h);
  // "Promptly" is measured against the same guard's own start-up on this machine (it prints its usage and
  // exits before any policy load), so a loaded host does not read as a hang. The policy fetch is bounded at
  // 1500 ms and an alert post at 5000 ms; a run that waited on either would exceed the 4000 ms margin.
  const base = await guard(h, []);
  assert.equal(base.status, 2);
  const offline = await guard(h, ["--decide", "proceed", PROMPT]);
  assert.ok(blocked39(offline), `the cached policy was not enforced offline: status ${offline.status}\n${offline.err}`);
  assert.ok(offline.ms - base.ms < 4000, `the guard took ${offline.ms} ms with the console down (start-up alone ${base.ms} ms)`);
  rmSync(CACHE(h), { force: true });
  const lkg = await guard(h, ["--decide", "proceed", PROMPT]);
  assert.ok(blocked39(lkg), `the last-known-good policy was not enforced offline: status ${lkg.status}\n${lkg.err}`);
  assert.ok(lkg.ms - base.ms < 4000, `the guard took ${lkg.ms} ms with the console down (start-up alone ${base.ms} ms)`);
});

test("no verified policy on a fail-closed device: the guard applies the offline fail-closed default, like the hook", async (t) => {
  const h = sandbox(t, await deadUrl());
  const r = await guard(h, ["--decide", "proceed", PROMPT], { MOORAI_OFFLINE_MODE: "fail-closed" });
  assert.ok(blocked39(r), `the offline default (#39 block) was not applied: status ${r.status}\n${r.err}`);
});

test("no verified policy on a fail-open device: the guard keeps its no-policy behaviour (notify, proceed)", async (t) => {
  const h = sandbox(t, await deadUrl());
  const r = await guard(h, ["--decide", "proceed", PROMPT]);
  assert.notEqual(r.status, 3, `blocked with no policy on a fail-open device:\n${r.err}`);
  assert.match(r.err, /proceeding as-is/);
});
