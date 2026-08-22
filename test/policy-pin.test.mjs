// Policy-key PINNING (Trust On First Use) tests — the follow-up that closes the hole
// policy-signature.test.mjs deliberately left open.
//
// That change made the device verify the policy cache, but only "when an anchor is present". The
// anchor (/etc/moorai/policy.pub or an MDM-injected MOORAI_POLICY_PUBKEY) has to be deployed by hand,
// so on the majority of installs — every device with no anchor — the original attack still worked:
//
//     echo '{}' > ~/.curaiq/hook-policy.json
//
// still collapsed enforcement, because a device with no key can verify nothing. Protection that has to
// be switched on is protection most fleets never get.
//
// The contract these tests pin: verification ARMS ITSELF. The first time a device sees a policy its
// console really signed, it pins that signing key (TOFU — the same pattern the console already uses for
// device keys) into two user-scope copies, mirroring the posture ratchet. From then on an unsigned
// policy, a policy signed by another key, and a policy signed for another tenant are all NO policy:
// the device falls through to durablePosture()/OFFLINE_DEFAULT_POLICY and raises a Critical, content-
// free tamper alert. A console that does not sign yet never forms a pin, so it never bricks.
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
  policyCanonical, policyDigest, POLICY_SIG_VERSION, verifyPolicySignature,
  POLICY_PIN_VERSION, parsePolicyPin, reconcilePolicyPins, policyTrust, parsePublishedKeys, publicKeyId
} from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";

const consoleKey = generateKeyPairSync("ed25519");   // the tenant's console signing key (K1)
const rotatedKey = generateKeyPairSync("ed25519");   // the key it rotates to (K2)
const rogueKey = generateKeyPairSync("ed25519");     // an attacker's key
const id = (kp) => publicKeyId(kp.publicKey);
const pubkeyBody = (kp) => JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: id(kp) });

function sign(policy, { tenant = TENANT, iat = "2026-08-21T00:00:00.000Z", key = consoleKey.privateKey } = {}) {
  const digest = policyDigest(policy);
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant, iat, digest })), key).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant, iat, sig } });
}

// A signed policy whose OWN mcpAllow excludes the probe server, so "deny" proves the signed policy was
// applied, distinct from the offline default's "ask".
const SIGNED = (over = {}) => sign({ offlineMode: "fail-closed", captureTier: "content-free", mcpAllow: ["something-else"], ...over });

// ---- unit: the pure pin logic ----

test("PIN FORMAT: a well-formed pin parses; anything else is not a pin", () => {
  const good = JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, keys: [id(consoleKey)] });
  assert.deepEqual(parsePolicyPin(good).keys, [id(consoleKey)]);
  assert.equal(parsePolicyPin(good).tenant, TENANT);
  for (const bad of ["", "   ", "not json", "[]", "null",
    JSON.stringify({ v: 99, tenant: TENANT, keys: ["k"] }),          // unknown version
    JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT }),        // no keys
    JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, keys: [] }), // empty keys
    JSON.stringify({ v: POLICY_PIN_VERSION, keys: ["k"] })            // no tenant
  ]) assert.equal(parsePolicyPin(bad), null, `accepted: ${bad}`);
});

test("PIN RECONCILE: two agreeing copies are one pin, with no tamper signal", () => {
  const p = JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, keys: [id(consoleKey)] });
  const r = reconcilePolicyPins({ primary: p, secondary: p });
  assert.equal(r.pinned, true);
  assert.deepEqual(r.keys, [id(consoleKey)]);
  assert.equal(r.evidenceMissing, false);
  assert.equal(r.corrupt, false);
});

test("PIN RECONCILE: erasing ONE copy still leaves the pin, and is flagged as evidence-missing", () => {
  const p = JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, keys: [id(consoleKey)] });
  for (const r of [reconcilePolicyPins({ primary: p, secondary: "" }), reconcilePolicyPins({ primary: "", secondary: p })]) {
    assert.equal(r.pinned, true, "one surviving copy is still a pin");
    assert.deepEqual(r.keys, [id(consoleKey)]);
    assert.equal(r.evidenceMissing, true);
  }
});

test("PIN RECONCILE: a copy that exists but is unreadable is CORRUPT — never silently 'no pin'", () => {
  const r = reconcilePolicyPins({ primary: "{}", secondary: "" });
  assert.equal(r.corrupt, true);
  assert.equal(r.pinned, true, "a mangled pin file is still evidence a pin existed");
});

test("PIN RECONCILE: a never-pinned device has no pin and no tamper signal (no brick)", () => {
  const r = reconcilePolicyPins({ primary: "", secondary: "" });
  assert.equal(r.pinned, false);
  assert.equal(r.corrupt, false);
  assert.equal(r.evidenceMissing, false);
  assert.deepEqual(r.keys, []);
});

test("PIN RECONCILE: the union of both copies is used, so a rotation recorded in one still counts", () => {
  const a = JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, keys: [id(consoleKey)] });
  const b = JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, keys: [id(consoleKey), id(rotatedKey)] });
  assert.deepEqual(reconcilePolicyPins({ primary: a, secondary: b }).keys.sort(), [id(consoleKey), id(rotatedKey)].sort());
});

test("TRUST: the explicit anchor OUTRANKS the pin, even a pin holding a different key", () => {
  const pin = reconcilePolicyPins({ primary: JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, keys: [id(rogueKey)] }), secondary: "" });
  const t = policyTrust({ anchorKeys: [consoleKey.publicKey], pin, tenant: TENANT });
  assert.equal(t.mode, "anchored");
  assert.deepEqual(t.keys.map(publicKeyId), [id(consoleKey)]);
});

test("TRUST: a pin becomes the verification key set when there is no anchor", () => {
  const pin = reconcilePolicyPins({ primary: JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, keys: [id(consoleKey)] }), secondary: "" });
  const t = policyTrust({ anchorKeys: [], pin, tenant: TENANT });
  assert.equal(t.mode, "pinned");
  assert.deepEqual(t.keys.map(publicKeyId), [id(consoleKey)]);
});

test("TRUST: an unpinned, unanchored device verifies nothing — unchanged legacy behavior", () => {
  const t = policyTrust({ anchorKeys: [], pin: reconcilePolicyPins({}), tenant: TENANT });
  assert.equal(t.mode, "unpinned");
  assert.deepEqual(t.keys, []);
});

test("TRUST: repointing config.json's tenant away from the pinned one REFUSES, it does not downgrade", () => {
  // ~/.curaiq/config.json is in the same write scope as the cache. If a tenant rename silently dropped
  // the pin, the pin would be one `sed` away from useless.
  const pin = reconcilePolicyPins({ primary: JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, keys: [id(consoleKey)] }), secondary: "" });
  const t = policyTrust({ anchorKeys: [], pin, tenant: "other-corp" });
  assert.equal(t.mode, "rebind");
  assert.deepEqual(t.keys, []);
});

test("TRUST: a corrupt pin refuses everything rather than falling back to 'verify nothing'", () => {
  const t = policyTrust({ anchorKeys: [], pin: reconcilePolicyPins({ primary: "{}", secondary: "" }), tenant: TENANT });
  assert.equal(t.mode, "corrupt");
  assert.deepEqual(t.keys, []);
});

test("TRUST: a pin whose stored keys are unusable is corrupt, NOT 'unanchored'", () => {
  const pin = reconcilePolicyPins({ primary: JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, keys: ["not-a-key"] }), secondary: "" });
  assert.equal(policyTrust({ anchorKeys: [], pin, tenant: TENANT }).mode, "corrupt");
});

test("PUBKEY: the console's /api/policy/pubkey body yields the key it publishes", () => {
  assert.deepEqual(parsePublishedKeys(pubkeyBody(consoleKey), { tenant: TENANT }), [id(consoleKey)]);
  const pem = consoleKey.publicKey.export({ type: "spki", format: "pem" });
  assert.deepEqual(parsePublishedKeys(JSON.stringify({ tenant: TENANT, pem }), { tenant: TENANT }), [id(consoleKey)]);
  // a body published for a different tenant is not this device's key
  assert.deepEqual(parsePublishedKeys(JSON.stringify({ tenant: "other-corp", publicKey: id(consoleKey) }), { tenant: TENANT }), []);
  for (const junk of ["", "not json", "{}", "<html>404</html>"]) assert.deepEqual(parsePublishedKeys(junk, { tenant: TENANT }), []);
});

test("VERIFY: a successful verification reports WHICH key verified, so it can be pinned", () => {
  const p = JSON.parse(SIGNED());
  const r = verifyPolicySignature(p, { keys: [rogueKey.publicKey, consoleKey.publicKey], tenant: TENANT });
  assert.equal(r.trusted, true);
  assert.equal(r.keyId, id(consoleKey));
});

// ---- end-to-end through the real hook process ----
//
// Same contract as break-glass.test.mjs / posture.test.mjs: HOME is a throwaway dir and the probe is an
// MCP tool-call, so the hook's OWN stdout states the trust decision.
//   ""    (exit 0) → no enforcement: the policy on disk was trusted (BYPASSED)
//   "ask"          → OFFLINE_DEFAULT_POLICY applied (mcpFloor) — the policy was refused
//   "deny"         → a signed policy whose mcpAllow excludes the probe was applied and ENFORCED
// Unlike those files the HOME here PERSISTS across runs, because self-arming is a property of run N+1.

function newHome() {
  const home = mkdtempSync(join(tmpdir(), "moorai-pin-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  return home;
}
const CACHE = (home) => join(home, ".curaiq", "hook-policy.json");
const PIN_A = (home) => join(home, ".curaiq", "policy-pin.json");
const PIN_B = (home) => join(home, ".moorai", "policy-pin.json");
const pinKeys = (home, p = PIN_A(home)) => (existsSync(p) ? parsePolicyPin(readFileSync(p, "utf8")).keys : null);

// Age the cache past the 60s freshness window, so the next run actually goes to the network. Without
// this a second run inside a minute short-circuits on the cache and never re-fetches.
function ageCache(home) { const t = (Date.now() - 2 * 3600 * 1000) / 1000; try { utimesSync(CACHE(home), t, t); } catch { /* no cache */ } }

// One hook invocation against a throwaway console. `serve`/`pubkey` null → that endpoint is unreachable.
async function run(home, { serve = null, pubkey = null, anchorPub = null, tenant = TENANT, offlineMode = "fail-closed" } = {}) {
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
    writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${server.address().port}`, tenant }));
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: offlineMode };
    if (anchorPub) env.MOORAI_POLICY_PUBKEY = anchorPub; else delete env.MOORAI_POLICY_PUBKEY;
    delete env.MOORAI_BREAKGLASS_PUBKEY;
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
const refused = (r) => /"permissionDecision":"ask"/.test(r.stdout);   // offline fail-closed default
const enforced = (r) => /"permissionDecision":"deny"/.test(r.stdout); // a signed policy's own rule
const withHome = async (fn) => { const home = newHome(); try { return await fn(home); } finally { rmSync(home, { recursive: true, force: true }); } };

// ---- the gap this change closes ----

test("E2E SELF-ARMING: seeing a signed policy ONCE makes `echo '{}'` fail forever after — NO anchor", async () => {
  await withHome(async (home) => {
    // Run 1 — an ordinary device with no anchor anywhere. Its console signs, so the key gets pinned.
    const r1 = await run(home, { serve: SIGNED(), pubkey: pubkeyBody(consoleKey) });
    assert.ok(enforced(r1), `the signed policy must apply on first contact; stdout was ${JSON.stringify(r1.stdout)}`);
    assert.deepEqual(pinKeys(home), [id(consoleKey)], "first contact must pin the console's signing key");
    assert.deepEqual(pinKeys(home, PIN_B(home)), [id(consoleKey)], "the pin must be written to BOTH directories");

    // Run 2 — the exact attack, on the same still-unanchored device, with the console unreachable.
    writeFileSync(CACHE(home), "{}");
    const r2 = await run(home, {});
    assert.ok(!bypassed(r2), "poisoned cache was trusted — enforcement bypassed on an unanchored device");
    assert.ok(refused(r2), `must fall through to the offline default; stdout was ${JSON.stringify(r2.stdout)}`);
    const tamper = r2.alerts.filter((a) => String(a.contentHash || "").startsWith("policy:cache:"));
    assert.equal(tamper.length, 1, `expected one policy tamper alert, got ${JSON.stringify(r2.hashes)}`);
    assert.equal(tamper[0].contentHash, "policy:cache:unsigned");
    assert.equal(tamper[0].riskLevel, "Critical");
    assert.equal(tamper[0].stage, "policy");
  });
});

test("E2E SELF-ARMING: the pin also survives the whole-outage path (cache outside the 60s window)", async () => {
  await withHome(async (home) => {
    await run(home, { serve: SIGNED(), pubkey: pubkeyBody(consoleKey) });
    writeFileSync(CACHE(home), '{"offlineMode":"fail-open","threatPolicy":{}}');
    ageCache(home);
    const r = await run(home, {});
    assert.ok(refused(r), `stdout was ${JSON.stringify(r.stdout)}`);
  });
});

test("E2E SELF-ARMING: after pinning, a policy signed by ANOTHER key is refused", async () => {
  await withHome(async (home) => {
    await run(home, { serve: SIGNED(), pubkey: pubkeyBody(consoleKey) });
    writeFileSync(CACHE(home), sign({ offlineMode: "fail-open", mcpAllow: ["probe"] }, { key: rogueKey.privateKey }));
    const r = await run(home, {});
    assert.ok(refused(r), `a rogue-signed policy must not apply; stdout was ${JSON.stringify(r.stdout)}`);
    assert.ok(r.hashes.includes("policy:cache:untrusted"), `got ${JSON.stringify(r.hashes)}`);
  });
});

test("E2E SELF-ARMING: after pinning, a policy signed for ANOTHER tenant is refused", async () => {
  await withHome(async (home) => {
    await run(home, { serve: SIGNED(), pubkey: pubkeyBody(consoleKey) });
    writeFileSync(CACHE(home), sign({ offlineMode: "fail-open", mcpAllow: ["probe"] }, { tenant: "other-corp" }));
    const r = await run(home, {});
    assert.ok(refused(r), `a cross-tenant policy must not apply; stdout was ${JSON.stringify(r.stdout)}`);
    assert.ok(r.hashes.includes("policy:cache:mismatch"), `got ${JSON.stringify(r.hashes)}`);
  });
});

test("E2E SELF-ARMING: repointing serverUrl at an attacker console cannot re-pin around the pin", async () => {
  // The other half of the same write scope: if a freshly-fetched policy could always re-pin, then
  // `sed -i s/serverUrl/…/ ~/.curaiq/config.json` would defeat the pin in one call.
  await withHome(async (home) => {
    await run(home, { serve: SIGNED(), pubkey: pubkeyBody(consoleKey) });
    rmSync(CACHE(home), { force: true });
    const r = await run(home, { serve: sign({ offlineMode: "fail-open", mcpAllow: ["probe"] }, { key: rogueKey.privateKey }), pubkey: pubkeyBody(rogueKey) });
    assert.ok(refused(r), `an attacker console must not be able to re-pin; stdout was ${JSON.stringify(r.stdout)}`);
    assert.deepEqual(pinKeys(home), [id(consoleKey)], "the pin must not have learned the attacker's key");
    assert.ok(r.hashes.includes("policy:server:untrusted"), `got ${JSON.stringify(r.hashes)}`);
  });
});

// ---- the pin is tamper-EVIDENT, and says so ----

test("E2E: erasing ONE pin copy neither downgrades the device nor passes silently", async () => {
  await withHome(async (home) => {
    await run(home, { serve: SIGNED(), pubkey: pubkeyBody(consoleKey) });
    rmSync(PIN_A(home), { force: true }); // `rm ~/.curaiq/policy-pin.json`
    writeFileSync(CACHE(home), "{}");
    const r = await run(home, {});
    assert.ok(refused(r), `the surviving copy must still enforce; stdout was ${JSON.stringify(r.stdout)}`);
    assert.ok(r.hashes.includes("policy:pin:evidence-missing"), `expected an evidence-missing alert, got ${JSON.stringify(r.hashes)}`);
  });
});

test("E2E: a pin file that exists but is mangled is refused as corrupt, not read as 'no pin'", async () => {
  await withHome(async (home) => {
    await run(home, { serve: SIGNED(), pubkey: pubkeyBody(consoleKey) });
    writeFileSync(PIN_A(home), "{}");
    writeFileSync(PIN_B(home), "{}");
    writeFileSync(CACHE(home), "{}");
    const r = await run(home, {});
    assert.ok(refused(r), `a corrupt pin must fail closed; stdout was ${JSON.stringify(r.stdout)}`);
    assert.ok(r.hashes.includes("policy:pin:corrupt"), `got ${JSON.stringify(r.hashes)}`);
  });
});

test("E2E: renaming the tenant in config.json is refused, not treated as a fresh unpinned device", async () => {
  await withHome(async (home) => {
    await run(home, { serve: SIGNED(), pubkey: pubkeyBody(consoleKey) });
    writeFileSync(CACHE(home), "{}");
    const r = await run(home, { tenant: "other-corp" });
    assert.ok(refused(r), `a tenant rebind must not drop the pin; stdout was ${JSON.stringify(r.stdout)}`);
    assert.ok(r.hashes.includes("policy:pin:tenant-rebind"), `got ${JSON.stringify(r.hashes)}`);
  });
});

test("E2E RESIDUAL RISK: erasing BOTH copies DOES return the device to first contact", async () => {
  // Stated as a test rather than a footnote. The hook runs as the user, so an attacker who can write
  // ~/.curaiq/hook-policy.json can also `rm ~/.curaiq/policy-pin.json ~/.moorai/policy-pin.json`. Two
  // copies in two directories defeat the one-liner and the ~/.curaiq wipe; they are tamper-EVIDENCE,
  // not tamper-proofing. The root-owned /etc/moorai/policy.pub anchor is the only hard guarantee.
  await withHome(async (home) => {
    await run(home, { serve: SIGNED(), pubkey: pubkeyBody(consoleKey) });
    rmSync(PIN_A(home), { force: true });
    rmSync(PIN_B(home), { force: true });
    writeFileSync(CACHE(home), "{}");
    const r = await run(home, {});
    assert.ok(bypassed(r), "documented residual risk: a fully erased pin is indistinguishable from a new device");
  });
});

// ---- no brick: a console that does not sign keeps working exactly as before ----

test("E2E NO BRICK: a console that never signs forms no pin and keeps working", async () => {
  await withHome(async (home) => {
    const r1 = await run(home, { serve: JSON.stringify({ captureTier: "content-free", mcpAllow: ["something-else"] }) });
    assert.ok(enforced(r1), `an unsigned policy must still apply on a never-signing console; stdout was ${JSON.stringify(r1.stdout)}`);
    assert.equal(existsSync(PIN_A(home)), false, "no signature ever verified — nothing may be pinned");
    assert.equal(existsSync(PIN_B(home)), false);
    assert.ok(!r1.hashes.some((h) => String(h).startsWith("policy:")), `no tamper signal expected, got ${JSON.stringify(r1.hashes)}`);

    // ...and the pre-existing (documented) unsigned-cache behavior is unchanged on such a device.
    writeFileSync(CACHE(home), "{}");
    const r2 = await run(home, {});
    assert.ok(bypassed(r2), `an unarmed device must behave exactly as before; stdout was ${JSON.stringify(r2.stdout)}`);
    assert.ok(!r2.hashes.some((h) => String(h).startsWith("policy:")));
  });
});

test("E2E NO BRICK: a console whose pubkey endpoint is missing (older build) forms no pin", async () => {
  await withHome(async (home) => {
    const r = await run(home, { serve: SIGNED(), pubkey: null }); // 404 on /api/policy/pubkey
    assert.ok(enforced(r), `the signed policy must still apply; stdout was ${JSON.stringify(r.stdout)}`);
    assert.equal(existsSync(PIN_A(home)), false, "no published key to TOFU against — no pin may form");
  });
});

// ---- the explicit anchor still wins, and still works ----

test("E2E ANCHOR: the explicit anchor is honored on FIRST contact, before any pin can exist", async () => {
  await withHome(async (home) => {
    writeFileSync(CACHE(home), "{}");
    const r = await run(home, { anchorPub: id(consoleKey) });
    assert.ok(refused(r), `the anchor removes the first-contact window; stdout was ${JSON.stringify(r.stdout)}`);
    assert.ok(r.hashes.includes("policy:cache:unsigned"), `got ${JSON.stringify(r.hashes)}`);
  });
});

test("E2E ANCHOR: the anchor OUTRANKS a pin, including a pin holding a rogue key", async () => {
  await withHome(async (home) => {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    const rogue = JSON.stringify({ v: POLICY_PIN_VERSION, tenant: TENANT, keys: [id(rogueKey)] });
    writeFileSync(PIN_A(home), rogue);
    writeFileSync(PIN_B(home), rogue);
    writeFileSync(CACHE(home), SIGNED()); // signed by the real console, which only the ANCHOR knows
    const r = await run(home, { anchorPub: id(consoleKey) });
    assert.ok(enforced(r), `the anchor must decide, not the pin; stdout was ${JSON.stringify(r.stdout)}`);
  });
});

test("E2E ANCHOR: an anchored device also pins, so removing the MDM env var cannot downgrade it", async () => {
  await withHome(async (home) => {
    await run(home, { serve: SIGNED(), anchorPub: id(consoleKey) });
    assert.deepEqual(pinKeys(home), [id(consoleKey)], "an anchored device records the key it verified");
    writeFileSync(CACHE(home), "{}");
    const r = await run(home, {}); // MOORAI_POLICY_PUBKEY unset — the shell-profile attack
    assert.ok(refused(r), `dropping the env anchor must not re-open the bypass; stdout was ${JSON.stringify(r.stdout)}`);
  });
});

// ---- key rotation without bricking the fleet ----

test("E2E ROTATION: publishing the new key while still signing with the old one rolls the pin forward", async () => {
  await withHome(async (home) => {
    // 1. steady state — the console signs with K1 and publishes K1
    await run(home, { serve: SIGNED(), pubkey: pubkeyBody(consoleKey) });
    assert.deepEqual(pinKeys(home), [id(consoleKey)]);

    // 2. overlap window — the console publishes K2 but keeps signing with K1. The policy still verifies
    //    under the pinned key, and THAT is what vouches for adding K2. An attacker cannot reach this
    //    branch without already holding K1.
    ageCache(home);
    const r2 = await run(home, { serve: SIGNED(), pubkey: pubkeyBody(rotatedKey) });
    assert.ok(enforced(r2), `stdout was ${JSON.stringify(r2.stdout)}`);
    assert.deepEqual(pinKeys(home).sort(), [id(consoleKey), id(rotatedKey)].sort(), "the new key must join the pin");

    // 3. cutover — the console signs with K2. The device already trusts it, offline included.
    writeFileSync(CACHE(home), sign({ offlineMode: "fail-closed", captureTier: "content-free", mcpAllow: ["something-else"] }, { key: rotatedKey.privateKey }));
    const r3 = await run(home, {});
    assert.ok(enforced(r3), `the rotated key must be accepted offline; stdout was ${JSON.stringify(r3.stdout)}`);
    assert.ok(!r3.hashes.some((h) => String(h).startsWith("policy:")), `no tamper alert expected, got ${JSON.stringify(r3.hashes)}`);
  });
});

test("E2E ROTATION: publishing a new key does NOT let an unsigned-by-anyone policy through", async () => {
  await withHome(async (home) => {
    await run(home, { serve: SIGNED(), pubkey: pubkeyBody(consoleKey) });
    ageCache(home);
    // The console publishes K2 but serves an UNSIGNED policy that would open the probe server up. The
    // pin refuses it, so the device keeps enforcing the last-known SIGNED policy from its cache — which
    // still denies the probe. Publishing a key is not, on its own, permission to be believed.
    const r = await run(home, { serve: '{"mcpAllow":["probe"]}', pubkey: pubkeyBody(rotatedKey) });
    assert.ok(enforced(r), `the unsigned fetch must not apply; stdout was ${JSON.stringify(r.stdout)}`);
    assert.ok(r.hashes.includes("policy:server:unsigned"), `got ${JSON.stringify(r.hashes)}`);
    assert.deepEqual(pinKeys(home), [id(consoleKey)], "an unsigned fetch must not roll the pin forward");
  });
});
