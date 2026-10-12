// Trust-anchor design phase 1B: policy freshness from the signed iat, not the cache file's mtime.
//
//   node --test --import ./test/hermetic-env.mjs test/policy-freshness.test.mjs
//
// The cache (~/.moorai/hook-policy.json) is the agent's to `touch`, so a young mtime proves nothing about a
// policy's age. The console signs every policy response with iat = now, and iat is inside the signed bytes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync, mkdirSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId, policyFreshByIat, policyMaxAgeMs, policyAgeMs, policyIatIso, POLICY_MAX_AGE_MS } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";
const key = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) });

function sign(policy, iat) {
  const digest = policyDigest(policy);
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest })), key.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
const STRICT = (iat) => sign({ captureTier: "content-free", mcpAllow: ["something-else"] }, iat);

// ---- unit ----

test("freshness: a policy is fresh while its signed iat is younger than the maximum age (15 min default)", () => {
  const now = Date.parse("2026-10-12T12:00:00.000Z");
  const at = (min) => ({ policySig: { iat: new Date(now - min * 60000).toISOString() } });
  assert.equal(POLICY_MAX_AGE_MS, 15 * 60000);
  assert.equal(policyFreshByIat(at(14), now), true);
  assert.equal(policyFreshByIat(at(16), now), false);
  assert.equal(Math.floor(policyAgeMs(at(125), now) / 60000), 125);
  assert.equal(policyIatIso(at(0)), "2026-10-12T12:00:00.000Z");
  assert.equal(policyFreshByIat({ captureTier: "content-free" }, now), true, "no signed iat: nothing to measure, the mtime window decides as before");
  assert.equal(policyIatIso({}), "");
});

test("freshness: only the signed policy can change the maximum age, within 1 minute to 7 days", () => {
  assert.equal(policyMaxAgeMs({ policyMaxAgeMinutes: 60 }), 3600000);
  assert.equal(policyMaxAgeMs({ policyMaxAgeMinutes: 0 }), POLICY_MAX_AGE_MS);
  assert.equal(policyMaxAgeMs({ policyMaxAgeMinutes: 99999 }), POLICY_MAX_AGE_MS);
  assert.equal(policyMaxAgeMs({ policyMaxAgeMinutes: "x" }), POLICY_MAX_AGE_MS);
});

// ---- end to end ----

async function run(home, { policy = null, pubkey = null, policyStatus = 200 } = {}) {
  const requests = [], alerts = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      requests.push(`${req.method} ${req.url.split("?")[0]}`);
      if (req.method === "POST") { try { if (req.url === "/api/alerts") alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(200); return res.end("{}"); }
      if (req.url.startsWith("/api/policy/pubkey")) { if (!pubkey) { res.writeHead(404); return res.end(); } res.writeHead(200); return res.end(pubkey); }
      if (policy == null || policyStatus !== 200) { res.writeHead(policyStatus === 200 ? 500 : policyStatus); return res.end("down"); }
      res.writeHead(200, { "Content-Type": "application/json" }); res.end(policy);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${server.address().port}`, tenant: TENANT, installToken: "tok-fresh" }));
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "fail-open" };
    for (const k of ["MOORAI_POLICY_PUBKEY", "MOORAI_BREAKGLASS_PUBKEY", "XDG_CONFIG_HOME", "XDG_STATE_HOME"]) delete env[k];
    const child = spawn(process.execPath, [HOOK], { env, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ tool_name: "mcp__probe__ping", tool_input: {}, hook_event_name: "PreToolUse", session_id: "fresh" }));
    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c));
    await new Promise((r) => child.on("close", r));
    await new Promise((r) => setTimeout(r, 150));
    return { requests, alerts, stdout };
  } finally { await new Promise((r) => server.close(r)); }
}
function newHome() {
  const home = mkdtempSync(join(tmpdir(), "moorai-fresh-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  return home;
}
const CACHE = (home) => join(home, ".moorai", "hook-policy.json");
const touchNow = (p) => { const t = Date.now() / 1000; utimesSync(p, t, t); };
const enforced = (r) => /"permissionDecision":"deny"/.test(r.stdout);

test("E2E: a validly signed cache with iat = now-2h and a freshly touched mtime is refetched — GET /api/policy happens", async () => {
  const home = newHome();
  try {
    // The newest policy this device has seen was issued two hours ago (so it is not a rollback, which the
    // pin's high-water mark would refuse anyway). The agent's move: keep the cache's mtime young forever.
    const r1 = await run(home, { policy: STRICT(new Date(Date.now() - 2 * 3600000).toISOString()), pubkey: pubkeyBody });
    assert.ok(enforced(r1), `first contact pins and enforces: ${r1.stdout}`);
    touchNow(CACHE(home));
    const r2 = await run(home, { policy: STRICT(new Date().toISOString()), pubkey: pubkeyBody });
    assert.ok(r2.requests.includes("GET /api/policy"), `no refetch: ${JSON.stringify(r2.requests)}`);
    assert.ok(enforced(r2));
  } finally { rmTree(home); }
});

test("E2E control: a cache whose signed iat is young is served from the window, with no fetch", async () => {
  const home = newHome();
  try {
    await run(home, { policy: STRICT(new Date().toISOString()), pubkey: pubkeyBody });
    const r = await run(home, { policy: STRICT(new Date().toISOString()), pubkey: pubkeyBody });
    assert.ok(!r.requests.includes("GET /api/policy"), JSON.stringify(r.requests));
  } finally { rmTree(home); }
});

test("E2E: when the refetch fails the old policy is still enforced, and POLICY_STALE reports its age; every alert carries policyIat", async () => {
  const home = newHome();
  try {
    // The last policy this device got was issued two hours ago (not a rollback: it is the newest it has
    // seen), and the console has been unreachable since.
    const iat = new Date(Date.now() - 2 * 3600000).toISOString();
    await run(home, { policy: STRICT(iat), pubkey: pubkeyBody });
    touchNow(CACHE(home));
    const r = await run(home, { policy: null, policyStatus: 503 });
    assert.ok(r.requests.includes("GET /api/policy"));
    assert.ok(enforced(r), `the verified old policy still enforces: ${r.stdout}`);
    const stale = r.alerts.find((a) => a.reasonCode === "POLICY_STALE");
    assert.ok(stale, `no POLICY_STALE alert: ${JSON.stringify(r.alerts.map((a) => a.contentHash))}`);
    assert.ok(Number.isInteger(stale.ageMinutes) && stale.ageMinutes >= 119 && stale.ageMinutes <= 121, `ageMinutes ${stale.ageMinutes}`);
    assert.ok(r.alerts.length >= 2);
    for (const a of r.alerts) assert.equal(a.policyIat, iat, `alert ${a.contentHash} carries policyIat ${a.policyIat}`);
  } finally { rmTree(home); }
});
