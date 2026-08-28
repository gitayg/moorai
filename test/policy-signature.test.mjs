// Policy-cache authenticity tests. The policy cache (~/.curaiq/hook-policy.json) is read by the hook
// and TRUSTED — a policy is an authorized relaxation, so it outranks the offline posture ratchet by
// design. It also lives in the governed agent's own write scope, so before this change one already-
// permitted Bash call —
//
//     echo '{}' > ~/.curaiq/hook-policy.json
//
// — was a total enforcement bypass: `{}` flips the posture AND flattens every detector to "notify" via
// threatActionFor's fallback, and it is not bounded by the 60s freshness window, because a failed fetch
// falls back to the same file ("cache-offline") for the whole outage.
//
// These tests pin the replacement contract: the console signs each tenant's policy with ed25519, and a
// device holding the trust anchor OUTSIDE the agent's write scope treats anything that does not verify
// as NO policy at all — falling through to the posture ratchet / OFFLINE_DEFAULT_POLICY.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { verifyPolicySignature, policyCanonical, policyDigest, canonicalJson, POLICY_SIG_VERSION } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";

const console_ = generateKeyPairSync("ed25519"); // the tenant's console signing key
const rogue = generateKeyPairSync("ed25519");
const PUB_B64 = console_.publicKey.export({ type: "spki", format: "der" }).toString("base64");
const ANCHORED = { keys: [console_.publicKey], tenant: TENANT };

// Mint a signed policy exactly the way server/policy-sign.js does.
function sign(policy, { tenant = TENANT, iat = "2026-08-21T00:00:00.000Z", key = console_.privateKey } = {}) {
  const digest = policyDigest(policy);
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant, iat, digest })), key).toString("base64");
  return { ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant, iat, sig } };
}

// ---- the wire format ----

// The canonical string and the digest are a WIRE FORMAT the console signs over out-of-band. A silent
// change here invalidates every policy already signed, so both are pinned literally rather than derived
// from the implementation agreeing with itself.
test("the signed canonical bytes and the body digest are a pinned wire format", () => {
  assert.equal(POLICY_SIG_VERSION, 1);
  assert.equal(
    policyCanonical({ v: 1, tenant: "acme", iat: "2026-08-21T00:00:00.000Z", digest: "abc123" }),
    "moorai-policy|v1|acme|2026-08-21T00:00:00.000Z|abc123"
  );
  // key-sorted, so JSON key order on the wire or in the cache file cannot change the digest
  assert.equal(canonicalJson({ b: 1, a: [3, { z: 1, y: 2 }] }), '{"a":[3,{"y":2,"z":1}],"b":1}');
  assert.equal(policyDigest({ b: 1, a: 2 }), policyDigest({ a: 2, b: 1 }));
  // the envelope itself is excluded from what it covers
  assert.equal(policyDigest({ a: 1 }), policyDigest({ a: 1, policySig: { sig: "x" } }));
});

// ---- the vulnerability itself ----

test("FORGED: the `echo '{}'` policy an agent can write does NOT verify on an anchored device", () => {
  const r = verifyPolicySignature({}, ANCHORED);
  assert.equal(r.trusted, false);
  assert.equal(r.status, "unsigned");
});

test("FORGED: a wide-open policy an agent wrote is unsigned, however plausible it looks", () => {
  const r = verifyPolicySignature({ offlineMode: "fail-open", threatPolicy: {}, mcpAllow: [] }, ANCHORED);
  assert.equal(r.trusted, false);
  assert.equal(r.status, "unsigned");
});

test("FORGED: a policy signed by a key that is not the console's is untrusted", () => {
  const r = verifyPolicySignature(sign({ offlineMode: "fail-open" }, { key: rogue.privateKey }), ANCHORED);
  assert.equal(r.trusted, false);
  assert.equal(r.status, "untrusted");
});

test("FORGED: editing ANY field of a genuinely signed policy breaks the signature", () => {
  const p = sign({ offlineMode: "fail-closed", captureTier: "content-free", threatPolicy: { 39: "block" } });
  assert.equal(verifyPolicySignature(p, ANCHORED).trusted, true);
  for (const mutate of [
    (q) => { q.offlineMode = "fail-open"; },          // the posture flip
    (q) => { q.threatPolicy = {}; },                  // flatten every detector to notify
    (q) => { q.threatPolicy[39] = "notify"; },        // downgrade one detector
    (q) => { q.mcpAllow = ["anything"]; },            // widen the MCP allow-list
    (q) => { q.captureTier = "full-capture"; },       // raise capture above what the admin set
    (q) => { delete q.captureTier; },                 // deletion is tampering too
    (q) => { q.policySig.iat = "2099-01-01T00:00:00.000Z"; },
    (q) => { q.policySig.tenant = "other-corp"; }
  ]) {
    const q = JSON.parse(JSON.stringify(p));
    mutate(q);
    const r = verifyPolicySignature(q, ANCHORED);
    assert.equal(r.trusted, false, `mutation was accepted: ${JSON.stringify(q)}`);
    assert.equal(r.status, "untrusted");
  }
});

test("FORGED: a policy validly signed for ANOTHER tenant does not apply here", () => {
  // Replay across tenants: genuinely console-signed, just not for this device's tenant. Caught because
  // the tenant is INSIDE the signed bytes, not merely alongside them.
  const r = verifyPolicySignature(sign({ offlineMode: "fail-open" }, { tenant: "other-corp" }), ANCHORED);
  assert.equal(r.trusted, false);
  assert.equal(r.status, "mismatch");
});

// ---- fail-closed on ambiguity ----

test("MALFORMED: a truncated / bogus envelope is not trusted", () => {
  const bad = [
    { policySig: { v: 1, alg: "ed25519", tenant: TENANT, iat: "x" } },          // no sig
    { policySig: { v: 99, alg: "ed25519", tenant: TENANT, iat: "x", sig: "A" } }, // unknown version
    { policySig: { v: 1, alg: "rsa", tenant: TENANT, iat: "x", sig: "A" } },      // wrong alg
    { policySig: { v: 1, alg: "ed25519", tenant: TENANT, sig: "A" } }             // no issued-at
  ];
  for (const p of bad) assert.equal(verifyPolicySignature(p, ANCHORED).trusted, false, JSON.stringify(p));
  assert.equal(verifyPolicySignature(null, ANCHORED).status, "malformed");
  assert.equal(verifyPolicySignature([], ANCHORED).status, "malformed");
});

test("COMPATIBILITY: with NO anchor the device verifies nothing and behaves exactly as before", () => {
  // Deliberate choice (a). /etc/moorai is optional today, so a hard requirement would brick every
  // existing install. Shipping the anchor IS the opt-in — and an anchored device never accepts an
  // unsigned policy (the tests above).
  const r = verifyPolicySignature({}, { keys: [], tenant: TENANT });
  assert.equal(r.trusted, true);
  assert.equal(r.status, "unanchored");
});

test("VALID: a console-signed policy for this tenant IS trusted", () => {
  const r = verifyPolicySignature(sign({ offlineMode: "fail-closed", mcpAllow: ["ok"] }), ANCHORED);
  assert.equal(r.trusted, true);
  assert.equal(r.status, "ok");
});

test("VALID: signing is interoperable with tooling that only has the pinned wire format", () => {
  // Signed over bytes assembled by hand — proves real interop with the console rather than the
  // implementation agreeing with itself.
  const policy = { offlineMode: "fail-closed", mcpAllow: ["ok"] };
  const iat = "2026-08-21T00:00:00.000Z";
  const digest = policyDigest(policy);
  const sig = edSign(null, Buffer.from(`moorai-policy|v1|${TENANT}|${iat}|${digest}`), console_.privateKey).toString("base64");
  const p = { ...policy, policySig: { v: 1, alg: "ed25519", tenant: TENANT, iat, sig } };
  assert.equal(verifyPolicySignature(p, ANCHORED).trusted, true);
});

// ---- end-to-end through the real hook process ----

// Runs cli/moorai-hook.mjs with HOME pointed at a throwaway dir and no reachable policy server, with the
// durable posture forced to fail-closed — the exact situation the poisoned cache exists to escape. The
// probe is an MCP tool-call, so the hook's OWN stdout states the trust decision:
//   ""    (exit 0)  → no enforcement: the planted policy was trusted (BYPASSED)
//   "ask"           → OFFLINE_DEFAULT_POLICY applied (mcpFloor) — the cache was refused
//   "deny"          → a signed policy whose mcpAllow excludes the probe was applied and ENFORCED
// That is the real decision, not a log line that could race process.exit.
async function runHook({ cache, cacheAgeMs = 0, anchorPub, tenant = TENANT, serve = null }) {
  const home = mkdtempSync(join(tmpdir(), "moorai-pol-"));
  const alerts = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.method === "POST") { try { alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(200, { "Content-Type": "application/json" }); return res.end("{}"); }
      if (serve) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(serve); }
      res.writeHead(500); res.end("offline"); // /api/policy unreachable → the offline path
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}`;
  try {
    mkdirSync(join(home, ".curaiq"), { recursive: true }); mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: url, tenant }));
    const cachePath = join(home, ".moorai", "hook-policy.json");
    if (cache != null) {
      writeFileSync(cachePath, cache);
      if (cacheAgeMs) { const t = (Date.now() - cacheAgeMs) / 1000; utimesSync(cachePath, t, t); }
    }
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "fail-closed" };
    if (anchorPub) env.MOORAI_POLICY_PUBKEY = anchorPub; else delete env.MOORAI_POLICY_PUBKEY;
    delete env.MOORAI_BREAKGLASS_PUBKEY;
    const child = spawn(process.execPath, [HOOK], { env, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ tool_name: "mcp__probe__ping", tool_input: {} }));
    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c));
    const code = await new Promise((r) => child.on("close", r));
    await new Promise((r) => setTimeout(r, 150)); // let in-flight alert POSTs land
    return { alerts, stdout, code, categories: alerts.map((a) => a.category), hashes: alerts.map((a) => a.contentHash) };
  } finally {
    await new Promise((r) => server.close(r));
    rmSync(home, { recursive: true, force: true });
  }
}

const bypassed = (r) => r.stdout === "";
const refused = (r) => /"permissionDecision":"ask"/.test(r.stdout);   // offline fail-closed default
const enforced = (r) => /"permissionDecision":"deny"/.test(r.stdout); // a signed policy's own rule

test("E2E CONTROL: with no cache at all, a fail-closed device enforces the offline default", async () => {
  const r = await runHook({ cache: null });
  assert.ok(refused(r), `stdout was ${JSON.stringify(r.stdout)}`);
});

test("E2E: the exact `echo '{}' > ~/.curaiq/hook-policy.json` attack does NOT bypass enforcement", async () => {
  const r = await runHook({ cache: "{}", anchorPub: PUB_B64 });
  assert.ok(!bypassed(r), "poisoned cache was trusted — enforcement bypassed");
  assert.ok(refused(r), `device must fall through to the offline default; stdout was ${JSON.stringify(r.stdout)}`);
});

test("E2E: the poisoned cache is refused OUTSIDE the 60s window too (the whole-outage path)", async () => {
  // The original exposure was never bounded by the freshness window: a failed fetch re-reads the same
  // file as "cache-offline" for as long as the server is unreachable.
  const r = await runHook({ cache: "{}", cacheAgeMs: 2 * 3600 * 1000, anchorPub: PUB_B64 });
  assert.ok(refused(r), `stdout was ${JSON.stringify(r.stdout)}`);
});

test("E2E: a rejected cache raises ONE Critical, content-free tamper alert", async () => {
  const r = await runHook({ cache: '{"offlineMode":"fail-open","threatPolicy":{}}', anchorPub: PUB_B64 });
  const tamper = r.alerts.filter((a) => String(a.contentHash || "").startsWith("policy:"));
  assert.equal(tamper.length, 1, `expected exactly one policy tamper alert, got: ${JSON.stringify(r.hashes)}`);
  assert.equal(tamper[0].contentHash, "policy:cache:unsigned");
  assert.equal(tamper[0].riskLevel, "Critical");
  assert.equal(tamper[0].stage, "policy");
  // content-free: only the source name and the failure status leave the device
  assert.ok(!JSON.stringify(tamper[0]).includes("fail-open"));
  assert.ok(!JSON.stringify(tamper[0]).includes("threatPolicy"));
});

test("E2E: a TAMPERED signed policy is rejected and the device falls back to the offline default", async () => {
  const p = sign({ offlineMode: "fail-closed", mcpAllow: ["nothing-else"] });
  p.mcpAllow = ["probe"]; // attacker widens the allow-list, keeps the console's signature
  const r = await runHook({ cache: JSON.stringify(p), anchorPub: PUB_B64 });
  assert.ok(refused(r), `tampered policy must not be applied; stdout was ${JSON.stringify(r.stdout)}`);
  const tamper = r.alerts.find((a) => String(a.contentHash || "").startsWith("policy:"));
  assert.equal(tamper.contentHash, "policy:cache:untrusted");
});

test("E2E: a policy signed for ANOTHER tenant is rejected on this device", async () => {
  const p = sign({ offlineMode: "fail-closed", mcpAllow: ["probe"] }, { tenant: "other-corp" });
  const r = await runHook({ cache: JSON.stringify(p), anchorPub: PUB_B64 });
  assert.ok(refused(r), `cross-tenant policy must not apply; stdout was ${JSON.stringify(r.stdout)}`);
  const tamper = r.alerts.find((a) => String(a.contentHash || "").startsWith("policy:"));
  assert.equal(tamper.contentHash, "policy:cache:mismatch");
});

test("E2E: a VALIDLY signed policy is accepted and its own rules are enforced", async () => {
  // mcpAllow excludes the probe server, so the hook must DENY — proving the signed policy was not just
  // accepted but actually applied, distinct from the offline default's "ask".
  const p = sign({ offlineMode: "fail-closed", captureTier: "content-free", mcpAllow: ["something-else"] });
  const r = await runHook({ cache: JSON.stringify(p), anchorPub: PUB_B64 });
  assert.ok(enforced(r), `signed policy must be applied; stdout was ${JSON.stringify(r.stdout)}`);
  assert.match(r.stdout, /not on your organization's allow-list/);
  assert.ok(!r.hashes.some((h) => String(h).startsWith("policy:")), "a valid policy must raise no tamper alert");
});

test("E2E: a signed policy served FRESH by the server is accepted and cached", async () => {
  const p = sign({ offlineMode: "fail-closed", mcpAllow: ["something-else"] });
  const r = await runHook({ cache: null, anchorPub: PUB_B64, serve: JSON.stringify(p) });
  assert.ok(enforced(r), `stdout was ${JSON.stringify(r.stdout)}`);
});

test("E2E: an UNSIGNED policy from a repointed serverUrl is refused too", async () => {
  // ~/.curaiq/config.json is in the same write scope as the cache, so pointing serverUrl at an
  // attacker-run server is the identical bypass wearing a different hat.
  const r = await runHook({ cache: null, anchorPub: PUB_B64, serve: "{}" });
  assert.ok(refused(r), `stdout was ${JSON.stringify(r.stdout)}`);
  const tamper = r.alerts.find((a) => String(a.contentHash || "").startsWith("policy:"));
  assert.equal(tamper.contentHash, "policy:server:unsigned");
});

test("E2E COMPATIBILITY: an UNANCHORED device still accepts an unsigned policy (documented choice (a))", async () => {
  // This is the pre-existing behavior every install without /etc/moorai/policy.pub keeps. It is also
  // the bypass, stated plainly: an unanchored device has no key, so it can verify nothing.
  const r = await runHook({ cache: "{}" }); // no anchorPub
  assert.ok(bypassed(r), `stdout was ${JSON.stringify(r.stdout)}`);
  assert.ok(!r.hashes.some((h) => String(h).startsWith("policy:")), "nothing to report without an anchor");
});

test("E2E: an unanchored device still ENFORCES a signed policy (no anchor required to benefit)", async () => {
  const p = sign({ offlineMode: "fail-closed", mcpAllow: ["something-else"] });
  const r = await runHook({ cache: JSON.stringify(p) }); // no anchorPub
  assert.ok(enforced(r), `stdout was ${JSON.stringify(r.stdout)}`);
});
