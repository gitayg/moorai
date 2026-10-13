// Policy-key ROTATION on a pinned device: only through a signed `nextKeys` list.
//
// The flaw this file pins shut (v1.13.6): in pinned mode armPolicyPin learned every key the console's
// UNSIGNED GET /api/policy/pubkey published, as long as the policy fetched alongside it verified under a
// pinned key. And the rollback rule is deliberately non-strict (an equal iat is the steady-state refetch).
// So anyone who can answer as the console — on an unmanaged device the agent can point serverUrl at its
// own localhost — could REPLAY the device's current signed policy (equal iat, verifies, not a rollback),
// publish its own key on the pubkey endpoint, get that key pinned, and from then on sign any policy.
//
// The contract (same as guardd/src/policy.rs arm_pin and docs/proposals/guardd-contract.md §13.3 item 1):
//   * a pinned device never fetches /api/policy/pubkey and never learns a key from it;
//   * a new key joins the pin only from `nextKeys` (array of SPKI base64 / PEM) inside a policy that
//     verifies under an already-pinned key, with iat STRICTLY greater than the high-water mark;
//   * an equal-iat replay is still ACCEPTED as the current policy, but teaches nothing;
//   * an unpinned device keeps trust-on-first-use from the endpoint.
//
//   node --test --test-reporter=spec test/policy-key-rotation.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync, existsSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import * as core from "../cli/hook-core.mjs";
const { policyCanonical, policyDigest, POLICY_SIG_VERSION, parsePolicyPin, publicKeyId } = core;

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";

const K1 = generateKeyPairSync("ed25519");    // the tenant's pinned console key
const K2 = generateKeyPairSync("ed25519");    // the key the console legitimately rotates to
const K3 = generateKeyPairSync("ed25519");    // a key a replay tries to teach
const EVIL = generateKeyPairSync("ed25519");  // an impersonating console's own key
const id = (kp) => publicKeyId(kp.publicKey);
const pubkeyBody = (...kps) => JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: id(kps[0]), keys: kps.map(id) });

// iats near "now", so no fixture trips the signed-freshness rule (policy:stale) and every alert seen
// below is one this change is about.
const BASE = Date.now() - 10 * 60 * 1000;
const at = (min) => new Date(BASE + min * 60 * 1000).toISOString();

function sign(policy, { iat = at(0), key = K1.privateKey, tenant = TENANT } = {}) {
  const digest = policyDigest(policy);
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant, iat, digest })), key).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant, iat, sig } });
}
// STRICT denies the probe MCP server → "deny" proves a strict policy is in force (fresh or last-known-good).
// RELAXED allows it → stdout "" proves THAT relaxed policy was accepted.
const STRICT = (over = {}, opts) => sign({ offlineMode: "fail-closed", captureTier: "content-free", mcpAllow: ["something-else"], ...over }, opts);
const RELAXED = (over = {}, opts) => sign({ offlineMode: "fail-closed", captureTier: "content-free", mcpAllow: ["probe"], ...over }, opts);

function newHome() {
  const home = mkdtempSync(join(tmpdir(), "moorai-rot-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true }); mkdirSync(join(home, ".moorai"), { recursive: true });
  return home;
}
const CACHE = (home) => join(home, ".moorai", "hook-policy.json");
const PIN_STATE = (home) => join(home, ".moorai", "policy-pin.json");
const PIN_LATCH = (home) => join(home, ".config", "moorai", "policy-pin.json");
const pinKeys = (home, p = PIN_STATE(home)) => (existsSync(p) ? [...parsePolicyPin(readFileSync(p, "utf8")).keys].sort() : null);
const ids = (...kps) => kps.map(id).sort();
function ageCache(home) { const t = (Date.now() - 2 * 3600 * 1000) / 1000; try { utimesSync(CACHE(home), t, t); } catch { /* no cache */ } }

async function run(home, { serve = null, pubkey = null } = {}) {
  const alerts = [], paths = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.method === "POST") { try { alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(200, { "Content-Type": "application/json" }); return res.end("{}"); }
      paths.push(req.url.split("?")[0]);
      const isPub = req.url.startsWith("/api/policy/pubkey");
      const want = isPub ? pubkey : serve;
      if (want == null) { res.writeHead(isPub ? 404 : 500); return res.end("offline"); }
      res.writeHead(200, { "Content-Type": "application/json" }); res.end(want);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${server.address().port}`, tenant: TENANT, installToken: "tok-enrolled-test" }));
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "fail-closed" };
    delete env.MOORAI_POLICY_PUBKEY; delete env.MOORAI_BREAKGLASS_PUBKEY;
    delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME;
    const child = spawn(process.execPath, [HOOK], { env, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ tool_name: "mcp__probe__ping", tool_input: {} }));
    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c));
    const code = await new Promise((r) => child.on("close", r));
    await new Promise((r) => setTimeout(r, 150));
    return { alerts, paths, stdout, code, hashes: alerts.map((a) => a.contentHash) };
  } finally {
    await new Promise((r) => server.close(r));
  }
}
const accepted = (r) => r.stdout === "";
const enforced = (r) => /"permissionDecision":"deny"/.test(r.stdout);
const policyAlerts = (r) => r.hashes.filter((h) => String(h || "").startsWith("policy:"));
const withHome = async (fn) => { const home = newHome(); try { return await fn(home); } finally { rmTree(home); } };

// First contact: pin K1 at iat at(0).
async function pinned(home) {
  const r = await run(home, { serve: STRICT({}, { iat: at(0) }), pubkey: pubkeyBody(K1) });
  assert.ok(enforced(r), `first contact must apply the signed policy; stdout ${JSON.stringify(r.stdout)}`);
  assert.deepEqual(pinKeys(home), ids(K1), "first contact pins the console key");
  ageCache(home);
}

// ---- (a) the attack ----

test("(a) ATTACK: an impersonating console replays the current signed policy and publishes its own key — the key is NOT pinned and its policy is refused", async () => {
  await withHome(async (home) => {
    await pinned(home);
    // The replay: byte-identical to what the device already accepted (equal iat → not a rollback), and
    // the pubkey endpoint publishes the attacker's key next to the real one.
    const replay = STRICT({}, { iat: at(0) });
    const r1 = await run(home, { serve: replay, pubkey: pubkeyBody(K1, EVIL) });
    assert.deepEqual(pinKeys(home), ids(K1), "the published key must not join the pin");
    assert.deepEqual(pinKeys(home, PIN_LATCH(home)), ids(K1), "nor the second pin copy");
    assert.ok(!r1.paths.includes("/api/policy/pubkey"), `a pinned device must not fetch the unsigned pubkey endpoint; fetched ${JSON.stringify(r1.paths)}`);
    // The attacker now signs a relaxed policy with its own key.
    rmSync(CACHE(home), { force: true });
    const r2 = await run(home, { serve: RELAXED({}, { iat: at(1), key: EVIL.privateKey }), pubkey: pubkeyBody(EVIL) });
    assert.ok(!accepted(r2), "the attacker-signed policy was accepted — the impersonator rotated the pin");
    assert.ok(enforced(r2), `must keep enforcing the last verified policy; stdout ${JSON.stringify(r2.stdout)}`);
    assert.ok(r2.hashes.includes("policy:server:untrusted"), `got ${JSON.stringify(r2.hashes)}`);
    assert.deepEqual(pinKeys(home), ids(K1));
  });
});

// ---- (b) legitimate rotation ----

test("(b) ROTATION: a policy signed by the pinned key carrying nextKeys [K2] with iat > mark teaches K2; a later K2-signed policy is accepted", async () => {
  await withHome(async (home) => {
    await pinned(home);
    const r1 = await run(home, { serve: STRICT({ nextKeys: [id(K2)] }, { iat: at(1) }) });
    assert.ok(enforced(r1), `stdout ${JSON.stringify(r1.stdout)}`);
    assert.deepEqual(pinKeys(home), ids(K1, K2), "signed nextKeys newer than the mark must join the pin");
    assert.deepEqual(pinKeys(home, PIN_LATCH(home)), ids(K1, K2));
    assert.deepEqual(policyAlerts(r1), [], "a legitimate rotation raises no tamper alert");
    ageCache(home);
    // Cutover: the console now signs with K2.
    const r2 = await run(home, { serve: RELAXED({}, { iat: at(2), key: K2.privateKey }) });
    assert.ok(accepted(r2), `the rotated-to key must be accepted; stdout ${JSON.stringify(r2.stdout)} alerts ${JSON.stringify(r2.hashes)}`);
    assert.deepEqual(policyAlerts(r2), []);
  });
});

test("(b) ROTATION: nextKeys in PEM form is the same list (shared canonical form with guardd)", async () => {
  await withHome(async (home) => {
    await pinned(home);
    const pem = K2.publicKey.export({ type: "spki", format: "pem" }).toString();
    await run(home, { serve: STRICT({ nextKeys: [pem] }, { iat: at(1) }) });
    assert.deepEqual(pinKeys(home), ids(K1, K2));
  });
});

// ---- (c) replayed nextKeys ----

test("(c) REPLAY: a nextKeys policy at iat EQUAL to the mark is accepted as current but teaches nothing; an OLDER one is refused outright", async () => {
  await withHome(async (home) => {
    await pinned(home);
    // Equal iat, signed by K1, carrying nextKeys [K3] — and the pubkey endpoint publishes K3 too, so
    // neither channel may teach it.
    const r1 = await run(home, { serve: STRICT({ nextKeys: [id(K3)] }, { iat: at(0) }), pubkey: pubkeyBody(K1, K3) });
    assert.ok(enforced(r1), `stdout ${JSON.stringify(r1.stdout)}`);
    assert.deepEqual(pinKeys(home), ids(K1), "an equal-iat replay must not rotate the pin");
    assert.ok(r1.hashes.includes("policy:nextKeys:not-newer"), `a not-newer nextKeys is reported; got ${JSON.stringify(r1.hashes)}`);
    ageCache(home);
    const r2 = await run(home, { serve: STRICT({ nextKeys: [id(K3)] }, { iat: at(-1) }) });
    assert.ok(r2.hashes.includes("policy:server:rollback"), `got ${JSON.stringify(r2.hashes)}`);
    assert.deepEqual(pinKeys(home), ids(K1));
    rmSync(CACHE(home), { force: true });
    const r3 = await run(home, { serve: RELAXED({}, { iat: at(2), key: K3.privateKey }) });
    assert.ok(!accepted(r3), "a K3-signed policy was accepted — a replay taught K3");
    assert.ok(r3.hashes.includes("policy:server:untrusted"), `got ${JSON.stringify(r3.hashes)}`);
  });
});

// ---- (d) steady state ----

test("(d) STEADY STATE: an equal-iat refetch of the current policy is still accepted, with no tamper alert", async () => {
  await withHome(async (home) => {
    const p = RELAXED({}, { iat: at(0) });
    const r0 = await run(home, { serve: p, pubkey: pubkeyBody(K1) });
    assert.ok(accepted(r0), `stdout ${JSON.stringify(r0.stdout)}`);
    assert.deepEqual(pinKeys(home), ids(K1));
    ageCache(home);
    const r1 = await run(home, { serve: p, pubkey: pubkeyBody(K1) });
    assert.ok(accepted(r1), `the identical refetch must be accepted; stdout ${JSON.stringify(r1.stdout)} alerts ${JSON.stringify(r1.hashes)}`);
    assert.deepEqual(policyAlerts(r1), [], "steady state raises no policy alert");
    assert.deepEqual(pinKeys(home), ids(K1));
  });
});

// ---- (e) first contact ----

test("(e) TOFU: an unpinned device still fetches the pubkey endpoint and pins the key that verifies", async () => {
  await withHome(async (home) => {
    const r = await run(home, { serve: STRICT({ nextKeys: [id(K2)] }, { iat: at(0) }), pubkey: pubkeyBody(K1) });
    assert.ok(r.paths.includes("/api/policy/pubkey"), `an unpinned device must fetch the pubkey endpoint; fetched ${JSON.stringify(r.paths)}`);
    assert.ok(enforced(r));
    // First contact pins only the key that verified; nextKeys is honoured from the NEXT (pinned) fetch.
    assert.deepEqual(pinKeys(home), ids(K1));
    ageCache(home);
    await run(home, { serve: STRICT({ nextKeys: [id(K2)] }, { iat: at(1) }) });
    assert.deepEqual(pinKeys(home), ids(K1, K2));
  });
});

// ---- the pure decision, so each half of the fix is pinned on its own ----
//
// End to end, the two halves (no pubkey fetch once pinned; no learning from it) each close the attack by
// themselves, so an E2E test cannot see one of them reverted while the other holds. These call the pure
// decision directly with a published body in hand.

test("(a) UNIT: a pinned device learns nothing from a published key even when handed one", () => {
  const policy = JSON.parse(STRICT({}, { iat: at(0) }));
  const d = core.policyKeysToLearn({ mode: "pinned", verdict: { keyId: id(K1), status: "ok" }, policy, publishedRaw: pubkeyBody(K1, EVIL), tenant: TENANT, mark: at(0) });
  assert.deepEqual(d.learn, [id(K1)]);
  assert.deepEqual(d.rejected, []);
});

test("(b)/(c) UNIT: nextKeys teaches only when the iat is strictly above the mark", () => {
  const verdict = { keyId: id(K1), status: "ok" };
  const policy = JSON.parse(STRICT({ nextKeys: [id(K2)] }, { iat: at(1) }));
  assert.deepEqual(core.policyKeysToLearn({ mode: "pinned", verdict, policy, mark: at(0) }).learn, [id(K1), id(K2)], "newer");
  assert.deepEqual(core.policyKeysToLearn({ mode: "pinned", verdict, policy, mark: "" }).learn, [id(K1), id(K2)], "no mark yet");
  for (const mark of [at(1), at(2)]) {
    const d = core.policyKeysToLearn({ mode: "pinned", verdict, policy, mark });
    assert.deepEqual(d.learn, [id(K1)], `mark ${mark}`);
    assert.deepEqual(d.rejected, [{ source: "nextKeys", status: "not-newer" }]);
  }
  assert.deepEqual(core.policyKeysToLearn({ mode: "unpinned", verdict: { status: "unanchored" }, policy, publishedRaw: pubkeyBody(K1), tenant: TENANT }).learn, [id(K1)], "TOFU learns the verifying key only");
  assert.deepEqual(core.policyKeysToLearn({ mode: "anchored", verdict, policy, mark: at(0) }).learn, [id(K1)], "an anchored device does not take nextKeys into its pin");
});

// ---- (f) JS–Rust parity on the rotation decision ----
//
// test/fixtures/guardd/policy-rotation-vectors.json (generated by gen-rotation-vectors.mjs beside it) holds
// the same scenarios as guardd's policy.rs tests — a_pinned_device_never_learns_a_key_from_the_unsigned_
// pubkey_endpoint, rotation_is_accepted_only_through_signed_next_keys_newer_than_the_mark,
// a_replayed_next_keys_policy_at_or_below_the_mark_teaches_nothing — as signed bytes plus the expected pin,
// acceptance and rejected (source, status) pairs after each fetch. Here every step goes end to end through
// the real hook against a throwaway console; the same file feeds guardd's PolicyStore::apply.
const VECTORS = JSON.parse(readFileSync(join(ROOT, "test", "fixtures", "guardd", "policy-rotation-vectors.json"), "utf8"));
const CHANNELS = /^policy:(server|nextKeys|revocation):/;

test("(f) PARITY: nextKeys canonical form — SPKI base64 or PEM strings, normalised to base64 SPKI DER ids, junk dropped", () => {
  assert.equal(typeof core.parseNextKeys, "function", "hook-core must export parseNextKeys");
  for (const v of VECTORS.canonical) assert.deepEqual(core.parseNextKeys(v.policy), v.keys, v.name);
});

for (const sc of VECTORS.scenarios) {
  test(`(f) PARITY vector: ${sc.name}`, async () => {
    await withHome(async (home) => {
      for (const [i, st] of sc.steps.entries()) {
        rmSync(CACHE(home), { force: true }); // every step is a real fetch; acceptance = the cache now holds these bytes
        const r = await run(home, { serve: st.policy, pubkey: st.published });
        const where = `step ${i}`;
        assert.deepEqual(pinKeys(home) || [], st.expect.pin, `${where}: pin`);
        const cached = existsSync(CACHE(home)) ? readFileSync(CACHE(home), "utf8") : null;
        assert.equal(cached === st.policy, st.expect.accepted, `${where}: accepted`);
        const got = r.hashes.filter((h) => CHANNELS.test(String(h || ""))).map((h) => { const [, source, status] = h.split(":"); return { source, status }; });
        assert.deepEqual(got, st.expect.rejected, `${where}: rejected`);
      }
    });
  });
}
