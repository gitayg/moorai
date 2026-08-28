// F-201 (signing-key REVOCATION) + F-202 (policy `iat` HIGH-WATER MARK).
//
// F-201 — THE GAP. writePolicyPin unioned every learned key into the pin and never removed one, while
// verifyPolicySignature accepts a signature from ANY key in the set. So a leaked K1 stayed trusted
// forever on every already-pinned device, even after the operator completed the documented rotation to
// K2 — rotation was a continuity mechanism, not a compromise-recovery one. The channel added here is a
// `revokedKeys` array INSIDE the signed policy body, so it inherits the console's existing signature.
//
// F-202 — THE GAP. verifyPolicySignature checked signature, alg and tenant, but nothing compared `iat`
// against anything and no monotonic state existed anywhere. An old-but-validly-signed policy could be
// replayed — most directly by the governed agent itself, via an already-permitted write to
// ~/.curaiq/hook-policy.json — to roll a tightening back with a signature that still verifies.
//
// WHAT IS PROVEN AND AT WHAT STRENGTH. Both pin copies are under the user's home, so on an UNANCHORED
// device an attacker who can write the policy cache can also rewind the pin: these tests prove
// tamper-EVIDENCE (refusal + a content-free alert), not prevention. The hard guarantee belongs to the
// root-owned anchors — /etc/moorai/policy.pub for keys, /etc/moorai/policy-hwm.json for the mark — which
// are outside the agent's write scope. Nothing below claims otherwise.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync, existsSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import {
  policyCanonical, policyDigest, POLICY_SIG_VERSION, POLICY_PIN_VERSION,
  parsePolicyPin, reconcilePolicyPins, publicKeyId,
  parseRevokedKeys, applyKeyRevocation, iatOrder, isPolicyRollback, maxIat, parsePolicyHwm
} from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";

// A root-owned machine latch on the DEV box would pin every case to fail-closed, so the fail-open E2E
// cases are skipped there rather than asserting something false. Same guard as policy-lkg.test.mjs.
const SYSTEM_LATCH = process.platform === "win32"
  ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "offline-posture")
  : "/etc/moorai/offline-posture";
const HOST_LATCHED = existsSync(SYSTEM_LATCH);

const K1 = generateKeyPairSync("ed25519");   // the leaked key
const K2 = generateKeyPairSync("ed25519");   // the key the operator rotates to
const id = (kp) => publicKeyId(kp.publicKey);
const pubkeyBody = (kp) => JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: id(kp) });

const T1 = "2026-08-01T00:00:00.000Z";       // superseded
const T2 = "2026-08-21T00:00:00.000Z";       // current
const T3 = "2026-08-22T00:00:00.000Z";       // newer still

function sign(policy, { tenant = TENANT, iat = T2, key = K1.privateKey } = {}) {
  const digest = policyDigest(policy);
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant, iat, digest })), key).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant, iat, sig } });
}

// STRICT denies the probe server (its own mcpAllow excludes it) → "deny" proves THIS policy applied.
// RELAXED allows it → exit(0) proves the RELAXED one applied.
const STRICT = (over = {}, opts) => sign({ captureTier: "content-free", mcpAllow: ["something-else"], ...over }, opts);
const RELAXED = (over = {}, opts) => sign({ captureTier: "content-free", mcpAllow: ["probe"], ...over }, opts);

// ---- unit: revocation list parsing ----

test("REVOKE PARSE: absent, non-array and junk entries all yield an empty list (forward-compatible)", () => {
  for (const p of [null, {}, { revokedKeys: null }, { revokedKeys: "abc" }, { revokedKeys: {} }, { revokedKeys: [] }, { revokedKeys: [1, "", "   ", true] }]) {
    assert.deepEqual(parseRevokedKeys(p), [], `accepted: ${JSON.stringify(p)}`);
  }
});

test("REVOKE PARSE: strings are trimmed and de-duplicated", () => {
  assert.deepEqual(parseRevokedKeys({ revokedKeys: [" a ", "a", "b"] }), ["a", "b"]);
});

// ---- unit: the pruning rules ----

test("REVOKE: a key named in the list is pruned out of the pin", () => {
  const r = applyKeyRevocation({ keys: ["k1", "k2"], revoked: ["k1"], verifiedBy: "k2" });
  assert.deepEqual(r.keys, ["k2"]);
  assert.deepEqual(r.pruned, ["k1"]);
  assert.equal(r.refused, "");
});

test("REVOKE: an empty or absent list is a no-op — behaviour is unchanged for today's console", () => {
  for (const revoked of [[], undefined, ["not-pinned-here"]]) {
    const r = applyKeyRevocation({ keys: ["k1", "k2"], revoked, verifiedBy: "k1" });
    assert.deepEqual(r.keys, ["k1", "k2"]);
    assert.equal(r.refused, "");
  }
});

test("REVOKE RULE 1: a key cannot revoke ITSELF — a stolen key must not lock the operator out", () => {
  // The whole list is refused, not just the self-entry: a policy that tries this is not a policy whose
  // revocation intent can be trusted at all.
  const r = applyKeyRevocation({ keys: ["k1", "k2"], revoked: ["k1", "k2"], verifiedBy: "k1" });
  assert.equal(r.refused, "self");
  assert.deepEqual(r.keys, ["k1", "k2"], "NOTHING may be pruned when the list is refused");
  assert.deepEqual(r.pruned, []);
});

test("REVOKE RULE 1: an unidentified signer is treated the same as a revoked one", () => {
  const r = applyKeyRevocation({ keys: ["k1"], revoked: ["k1"], verifiedBy: "" });
  assert.equal(r.refused, "self");
  assert.deepEqual(r.keys, ["k1"]);
});

test("REVOKE RULE 2: pruning to an EMPTY set is refused — an empty pin reads as 'unanchored'", () => {
  // The single most dangerous failure mode in F-201: policyTrust reports an empty key set as "unpinned"
  // and verifyPolicySignature answers { trusted: true, status: "unanchored" } for it, so an over-broad
  // revocation would not tighten the device — it would accept every future unsigned policy.
  const r = applyKeyRevocation({ keys: ["k1", "k2"], revoked: ["k1", "k2"], verifiedBy: "k3" });
  assert.equal(r.refused, "empty");
  assert.deepEqual(r.keys, ["k1", "k2"]);
  assert.deepEqual(r.pruned, []);
});

// ---- unit: the iat high-water mark ----

test("IAT: strictly older is a rollback; EQUAL is not, or every steady-state re-fetch would break", () => {
  assert.equal(isPolicyRollback(T1, T2), true);
  assert.equal(isPolicyRollback(T2, T2), false, "an unchanged policy re-fetched with the same iat MUST still be accepted");
  assert.equal(isPolicyRollback(T3, T2), false);
});

test("IAT: no mark, or a date neither side can parse, means no comparison — never a refusal", () => {
  assert.equal(isPolicyRollback(T1, ""), false);
  assert.equal(isPolicyRollback("", T2), false);
  assert.equal(isPolicyRollback("not-a-date", T2), false);
  assert.equal(isPolicyRollback(T1, "not-a-date"), false);
  assert.ok(Number.isNaN(iatOrder("")));
  assert.ok(Number.isNaN(iatOrder(null)));
});

test("IAT: maxIat keeps the higher mark and tolerates a missing side", () => {
  assert.equal(maxIat(T1, T2), T2);
  assert.equal(maxIat(T2, T1), T2);
  assert.equal(maxIat("", T2), T2);
  assert.equal(maxIat(T2, ""), T2);
  assert.equal(maxIat("", ""), "");
  assert.equal(maxIat(undefined, "junk"), "");
});

test("HWM FILE: the root-owned mark parses; wrong version, wrong tenant and junk read as no mark", () => {
  const good = JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, iat: T2 });
  assert.equal(parsePolicyHwm(good, { tenant: TENANT }), T2);
  assert.equal(parsePolicyHwm(good, { tenant: "other" }), "", "another tenant's mark must not apply here");
  assert.equal(parsePolicyHwm(JSON.stringify({ v: 99, tenant: TENANT, iat: T2 }), { tenant: TENANT }), "");
  for (const bad of ["", "not json", "[]", "null", JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, iat: "nope" })]) {
    assert.equal(parsePolicyHwm(bad, { tenant: TENANT }), "", `accepted: ${bad}`);
  }
});

test("PIN: the mark rides inside the pin record, is optional, and reconciles as the MAX of both copies", () => {
  const rec = (iat) => JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, keys: [id(K1)], ...(iat ? { iat } : {}) });
  assert.equal(parsePolicyPin(rec(T2)).iat, T2);
  assert.equal(parsePolicyPin(rec()).iat, "", "a pin written before F-202 is still a valid pin, with no mark");
  // Rewinding ONE copy must not lower the device's mark, for the same reason a pin in one copy is still
  // a pin. (Rewinding BOTH is the residual risk an unanchored device cannot close — see the header.)
  assert.equal(reconcilePolicyPins({ primary: rec(T1), secondary: rec(T3) }).iat, T3);
  assert.equal(reconcilePolicyPins({ primary: rec(T3), secondary: rec(T1) }).iat, T3);
  assert.equal(reconcilePolicyPins({ primary: rec(), secondary: rec() }).iat, "");
});

// ---- end-to-end through the real hook process ----
//
// Same harness contract as policy-lkg.test.mjs; HOME persists across runs. The probe is an MCP call:
//   ""    (exit 0) → the call was allowed (no policy on a fail-open device, or a policy that permits it)
//   "ask"          → OFFLINE_DEFAULT_POLICY applied (mcpFloor)
//   "deny"         → a policy whose mcpAllow excludes the probe was applied and ENFORCED

function newHome() {
  const home = mkdtempSync(join(tmpdir(), "moorai-revoke-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true }); mkdirSync(join(home, ".moorai"), { recursive: true });
  return home;
}
const CACHE = (home) => join(home, ".moorai", "hook-policy.json");
const PIN_STATE = (home) => join(home, ".moorai", "policy-pin.json");
const PIN_LATCH = (home) => join(home, ".config", "moorai", "policy-pin.json");
const PIN_LEGACY = (home) => join(home, ".curaiq", "policy-pin.json");
const LKG_STATE = (home) => join(home, ".moorai", "policy-lkg.json");
const pin = (home) => (existsSync(PIN_STATE(home)) ? parsePolicyPin(readFileSync(PIN_STATE(home), "utf8")) : null);

function ageCache(home) { const t = (Date.now() - 2 * 3600 * 1000) / 1000; try { utimesSync(CACHE(home), t, t); } catch { /* no cache */ } }

async function run(home, { serve = null, pubkey = null, tenant = TENANT, offlineMode = "fail-open", installToken = "tok-1" } = {}) {
  const alerts = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.method === "POST") { try { alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(200, { "Content-Type": "application/json" }); return res.end("{}"); }
      const want = req.url.startsWith("/api/policy/pubkey") ? pubkey : serve;
      if (want == null) { res.writeHead(req.url.startsWith("/api/policy/pubkey") ? 404 : 500); return res.end("offline"); }
      res.writeHead(200, { "Content-Type": "application/json" }); res.end(want);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${server.address().port}`, tenant, installToken }));
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: offlineMode };
    delete env.MOORAI_POLICY_PUBKEY;
    delete env.MOORAI_BREAKGLASS_PUBKEY;
    delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME; // latch/breadcrumb resolve under the throwaway HOME
    const child = spawn(process.execPath, [HOOK], { env, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ tool_name: "mcp__probe__ping", tool_input: {} }));
    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c));
    const code = await new Promise((r) => child.on("close", r));
    await new Promise((r) => setTimeout(r, 150)); // let in-flight alert POSTs land
    return { alerts, stdout, code, hashes: alerts.map((a) => a.contentHash) };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

const bypassed = (r) => r.stdout === "";
const enforced = (r) => /"permissionDecision":"deny"/.test(r.stdout);
const withHome = async (fn) => { const home = newHome(); try { return await fn(home); } finally { rmSync(home, { recursive: true, force: true }); } };

// Steady state used by most cases: the device pins K1, then rotates so it trusts BOTH K1 and K2.
async function rotated(home) {
  await run(home, { serve: STRICT({}, { iat: T2 }), pubkey: pubkeyBody(K1) });
  assert.deepEqual(pin(home).keys, [id(K1)], "first contact must pin the console's key");
  ageCache(home);
  await run(home, { serve: STRICT({}, { iat: T2 }), pubkey: pubkeyBody(K2) });
  assert.deepEqual(pin(home).keys.sort(), [id(K1), id(K2)].sort(), "the overlap window must roll the pin forward");
  ageCache(home);
}

// ---- F-201 end-to-end ----

test("E2E REVOKE: a revoked key stops verifying — the leaked K1 can no longer serve a policy", { skip: HOST_LATCHED && "host has a root-owned posture latch" }, async () => {
  await withHome(async (home) => {
    await rotated(home);

    // The operator cuts over to K2 and, in the same signed body, revokes the leaked K1.
    const r = await run(home, { serve: STRICT({ revokedKeys: [id(K1)] }, { iat: T3, key: K2.privateKey }), pubkey: pubkeyBody(K2) });
    assert.ok(enforced(r), `the K2 policy must apply; stdout was ${JSON.stringify(r.stdout)}`);
    assert.deepEqual(pin(home).keys, [id(K2)], "K1 must be gone from the pin");
    assert.ok(existsSync(LKG_STATE(home)), "the revoking policy is itself the new last-known-good");

    // The attack the revocation exists to stop: the thief holding K1 signs a policy that opens the probe
    // up and plants it in the cache. Before F-201 K1 was still pinned, so this was accepted and the
    // device exited 0. Now it is NO policy, and the last-known-good K2 policy keeps enforcing.
    writeFileSync(CACHE(home), RELAXED({}, { iat: T3, key: K1.privateKey }));
    const r2 = await run(home, {});
    assert.ok(!bypassed(r2), "REVOCATION BYPASS: a policy signed by the revoked key still produced exit(0)");
    assert.ok(enforced(r2), `the last-known-good policy must keep enforcing; stdout was ${JSON.stringify(r2.stdout)}`);
    assert.ok(r2.hashes.includes("policy:cache:untrusted"), `expected a content-free tamper alert, got ${JSON.stringify(r2.hashes)}`);
  });
});

test("E2E REVOKE: a key may not revoke ITSELF — a stolen key cannot lock the operator out", { skip: HOST_LATCHED && "host has a root-owned posture latch" }, async () => {
  await withHome(async (home) => {
    await rotated(home);

    // The thief holds K1 and tries to evict the operator's real key by revoking everything, itself
    // included. Refused wholesale, reported, and the pin is left exactly as it was.
    const r = await run(home, { serve: STRICT({ revokedKeys: [id(K1), id(K2)] }, { iat: T3, key: K1.privateKey }), pubkey: pubkeyBody(K1) });
    assert.deepEqual(pin(home).keys.sort(), [id(K1), id(K2)].sort(), "SELF-REVOCATION: the operator's key was evicted by a stolen one");
    assert.ok(r.hashes.includes("policy:revocation:self"), `expected a content-free tamper alert, got ${JSON.stringify(r.hashes)}`);

    // The operator's own key still works — the lock-out did not happen.
    ageCache(home);
    const r2 = await run(home, { serve: STRICT({}, { iat: T3, key: K2.privateKey }), pubkey: pubkeyBody(K2) });
    assert.ok(enforced(r2), `K2 must still be trusted; stdout was ${JSON.stringify(r2.stdout)}`);
  });
});

test("E2E REVOKE: the pin is never emptied — the whole keyring cannot be revoked at once", { skip: HOST_LATCHED && "host has a root-owned posture latch" }, async () => {
  await withHome(async (home) => {
    await rotated(home);
    // Revoking every pinned key is the path to an empty pin, which reads as "unpinned" and would make
    // the NEXT unsigned policy acceptable. Whichever guard catches it (here: rule 1, because the signer
    // is necessarily inside the set it is trying to empty), the pin must survive intact and non-empty.
    await run(home, { serve: STRICT({ revokedKeys: [id(K1), id(K2)] }, { iat: T3, key: K2.privateKey }), pubkey: pubkeyBody(K2) });
    assert.ok(pin(home).keys.length > 0, "EMPTY PIN: the device was returned to the unpinned state");

    // Proof that an empty pin really would be a bypass, i.e. that the guard above is load-bearing: with
    // the pin erased, an unsigned policy IS accepted.
    ageCache(home);
    rmSync(PIN_STATE(home), { force: true }); rmSync(PIN_LATCH(home), { force: true }); rmSync(PIN_LEGACY(home), { force: true }); // full erasure across all legs
    writeFileSync(CACHE(home), JSON.stringify({ captureTier: "content-free", mcpAllow: ["probe"] }));
    const r = await run(home, {});
    assert.ok(bypassed(r), `an unpinned device accepts an unsigned policy — that is what an emptied pin becomes; stdout was ${JSON.stringify(r.stdout)}`);
  });
});

// ---- F-202 end-to-end ----

test("E2E ROLLBACK: the accepted iat is recorded as a high-water mark", async () => {
  await withHome(async (home) => {
    await run(home, { serve: STRICT({}, { iat: T2 }), pubkey: pubkeyBody(K1) });
    assert.equal(pin(home).iat, T2, "the mark must be persisted beside the pin");
    ageCache(home);
    await run(home, { serve: STRICT({}, { iat: T3 }), pubkey: pubkeyBody(K1) });
    assert.equal(pin(home).iat, T3, "a newer policy must advance the mark");
  });
});

test("E2E ROLLBACK: a strictly OLDER validly-signed policy is refused, and the device keeps enforcing", { skip: HOST_LATCHED && "host has a root-owned posture latch" }, async () => {
  await withHome(async (home) => {
    // Steady state: a tightening is fetched and accepted at T2. It is both the cache and the LKG.
    const r1 = await run(home, { serve: STRICT({}, { iat: T2 }), pubkey: pubkeyBody(K1) });
    assert.ok(enforced(r1), `stdout was ${JSON.stringify(r1.stdout)}`);
    assert.equal(pin(home).iat, T2);

    // The attack: replay the SUPERSEDED but still validly signed T1 policy into the cache — the write is
    // one the agent is already permitted to make — to undo the tightening. Nothing about its signature
    // is wrong; only its age is.
    writeFileSync(CACHE(home), RELAXED({}, { iat: T1 }));
    const r2 = await run(home, {});
    assert.ok(!bypassed(r2), "ROLLBACK: the replayed policy re-opened the probe and produced exit(0)");
    assert.ok(r2.hashes.includes("policy:cache:rollback"), `expected a content-free rollback alert, got ${JSON.stringify(r2.hashes)}`);

    // #33 — a refused rollback must fall back to the last-known-good and KEEP ENFORCING, never fall
    // through to "no policy". The LKG copy's own iat IS the mark, and the comparison is strict, so it
    // passes rather than being caught by the very check that refused the replay.
    assert.ok(enforced(r2), `the offline/LKG path must still enforce; stdout was ${JSON.stringify(r2.stdout)}`);
    assert.ok(r2.hashes.includes("policy:lkg:applied"), `expected the LKG path, got ${JSON.stringify(r2.hashes)}`);
  });
});

test("E2E ROLLBACK: an EQUAL iat is still accepted — the steady-state re-fetch must not break", { skip: HOST_LATCHED && "host has a root-owned posture latch" }, async () => {
  await withHome(async (home) => {
    await run(home, { serve: STRICT({}, { iat: T2 }), pubkey: pubkeyBody(K1) });
    assert.equal(pin(home).iat, T2);

    // The same policy, re-served with the same iat. `<` and not `<=` is the whole difference between a
    // rollback check and an outage: this must be accepted, and it must be accepted from the CACHE too.
    writeFileSync(CACHE(home), RELAXED({}, { iat: T2 }));
    const r = await run(home, {});
    assert.ok(bypassed(r), `an equal iat must still be accepted; stdout was ${JSON.stringify(r.stdout)}`);
    assert.ok(!r.hashes.includes("policy:cache:rollback"), `no rollback alert expected, got ${JSON.stringify(r.hashes)}`);

    // And a NEWER one is of course fine — a console re-signing is normal, not an attack.
    ageCache(home);
    const r2 = await run(home, { serve: STRICT({}, { iat: T3 }), pubkey: pubkeyBody(K1) });
    assert.ok(enforced(r2), `stdout was ${JSON.stringify(r2.stdout)}`);
    assert.ok(!r2.hashes.some((h) => String(h).startsWith("policy:")), `no tamper alert expected, got ${JSON.stringify(r2.hashes)}`);
  });
});

test("E2E ROLLBACK: a device that has never recorded a mark is unaffected (the no-brick property)", { skip: HOST_LATCHED && "host has a root-owned posture latch" }, async () => {
  await withHome(async (home) => {
    // No pin, no mark, no anchor — a console that does not sign. An old iat is not a rollback because
    // there is nothing to roll back from, and the device behaves exactly as it did before F-202.
    writeFileSync(CACHE(home), RELAXED({}, { iat: T1 }));
    const r = await run(home, {});
    assert.ok(bypassed(r), `stdout was ${JSON.stringify(r.stdout)}`);
    assert.ok(!r.hashes.includes("policy:cache:rollback"), `got ${JSON.stringify(r.hashes)}`);
  });
});
