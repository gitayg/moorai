// The `contentHash` on every alert used to be an unsalted 32-bit DJB2 of the LITERAL matched span —
// i.e. of the phone number / SSN / card / API key the product exists to protect. That is not a
// one-way hash of a secret, it is an ENCODING of it: the candidate space for those values is small
// enough to enumerate, so anyone holding the console DB, the SIEM stream, or a copied audit.jsonl
// could recover the plaintext. The README's "only category, risk and a one-way hash leave the
// device — never the matched span" was therefore false as shipped.
//
// This file pins the replacement: a per-tenant-keyed HMAC-SHA-256, `h2:`-prefixed and truncated.
// The load-bearing test is `brute force`, which runs the SAME enumeration attack twice — once
// against the old DJB2, where it MUST succeed (the control that proves the attack and this harness
// are real), and once against the new keyed hash, where it MUST fail.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { contentHash, hashWithKey, deriveKey, HASH_PREFIX, NO_KEY, KEY_LABEL } from "../cli/content-hash.mjs";
import * as browserHash from "../src/content-hash.js";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const require = createRequire(import.meta.url);
const extHash = require(join(ROOT, "browser-ext", "content-hash.js"));

// The exact hash the agent shipped before this change. Reproduced here, not imported, so the test
// still describes the vulnerability after the last djb2 content call site is gone.
function legacyDjb2(s) {
  let h = 5381;
  for (let i = 0; i < String(s).length; i++) h = ((h << 5) + h + String(s).charCodeAt(i)) >>> 0;
  return "h" + h.toString(16);
}

const TOKEN_A = "it_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // tenant A's enroll token
const TOKEN_B = "it_live_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; // tenant B's
const KEY_A = deriveKey(TOKEN_A);
const KEY_B = deriveKey(TOKEN_B);

const SSN = "123-45-6789";
const PHONE = "415-555-0142";
const AWS = "AKIAIOSFODNN7EXAMPLE";

// ---------------------------------------------------------------------------------------------
// 1. Correlation is PRESERVED — that is the field's whole purpose.
// ---------------------------------------------------------------------------------------------

test("CORRELATION: the same value under the same key always yields the same hash", () => {
  for (const v of [SSN, PHONE, AWS, "", "unicode: naïve café 🔑"]) {
    assert.equal(hashWithKey(KEY_A, v), hashWithKey(KEY_A, v), v);
  }
});

test("CORRELATION: two DEVICES in one tenant hash a shared secret identically (fleet-wide dedup)", () => {
  // Both devices derive their key from the same per-tenant installToken, so the console/SIEM can
  // still answer "this same credential was seen on N machines" — the reason the key is per-tenant
  // and not per-device.
  const deviceOne = deriveKey(TOKEN_A);
  const deviceTwo = deriveKey(TOKEN_A);
  assert.equal(hashWithKey(deviceOne, AWS), hashWithKey(deviceTwo, AWS));
  assert.notEqual(hashWithKey(deviceOne, AWS), hashWithKey(deviceOne, SSN)); // distinct values stay distinct
});

test("UNLINKABILITY: two TENANTS hash the same secret differently", () => {
  assert.notEqual(KEY_A.toString("hex"), KEY_B.toString("hex"));
  for (const v of [SSN, PHONE, AWS]) {
    assert.notEqual(hashWithKey(KEY_A, v), hashWithKey(KEY_B, v), v);
  }
});

test("FORMAT: h2:-prefixed, 16 hex chars, and never contains the input", () => {
  const h = hashWithKey(KEY_A, AWS);
  assert.ok(h.startsWith(HASH_PREFIX), h);
  assert.match(h, /^h2:[0-9a-f]{16}$/);
  assert.ok(!h.includes(AWS));
  // The version prefix is what lets old (bare "h<hex>") and new values coexist in one column.
  assert.ok(!legacyDjb2(AWS).startsWith(HASH_PREFIX));
});

// ---------------------------------------------------------------------------------------------
// 2. THE VULNERABILITY ITSELF: run the enumeration attack, twice.
// ---------------------------------------------------------------------------------------------

test("BRUTE FORCE: the attack that reverses the OLD hash finds nothing against the new one", () => {
  // The candidate space an attacker with the alert stream actually enumerates. Every US phone
  // number of the form NPA-NXX-XXXX with a known exchange is 10^4 candidates; a full US phone
  // sweep is 10^10 and still trivial offline. 10^4 is enough to make the point in a unit test.
  const candidates = [];
  for (let i = 0; i < 10000; i++) candidates.push(`415-555-${String(i).padStart(4, "0")}`);
  assert.ok(candidates.includes(PHONE), "the plaintext must be inside the searched space");

  // (a) CONTROL — the old hash. If this ever stops recovering the plaintext, the test below proves
  //     nothing, because it would mean the attack itself no longer works.
  const oldHash = legacyDjb2(PHONE);
  const oldHits = candidates.filter((c) => legacyDjb2(c) === oldHash);
  assert.ok(oldHits.includes(PHONE), "CONTROL FAILED: the old DJB2 hash is supposed to be reversible");

  // (b) THE FIX — same attacker, same space, same algorithm knowledge, no key.
  const newHash = hashWithKey(KEY_A, PHONE);
  const keyless = candidates.filter((c) => hashWithKey(null, c) === newHash);
  assert.equal(keyless.length, 0, "an attacker with no key must recover nothing");

  // (c) …and knowing the ALGORITHM is not enough either: a guessed/wrong key recovers nothing.
  const wrongKey = deriveKey("it_live_attackers_guess");
  const wrong = candidates.filter((c) => hashWithKey(wrongKey, c) === newHash);
  assert.equal(wrong.length, 0, "a wrong key must recover nothing");

  // (d) with the RIGHT key the search does succeed — which is exactly why the key must never sit
  //     next to the hashes. This is the residual risk, asserted rather than hand-waved.
  const withKey = candidates.filter((c) => hashWithKey(KEY_A, c) === newHash);
  assert.deepEqual(withKey, [PHONE]);
});

test("BRUTE FORCE: an SSN is not recoverable from its keyed hash", () => {
  const target = hashWithKey(KEY_A, SSN);
  let found = null;
  for (let i = 0; i < 10000; i++) {
    const c = `123-45-${String(i).padStart(4, "0")}`;
    if (legacyDjb2(c) === legacyDjb2(SSN) && c === SSN) found = "control-ok";
    if (hashWithKey(null, c) === target) assert.fail(`keyless search recovered ${c}`);
  }
  assert.equal(found, "control-ok", "the control arm must have located the plaintext");
});

// ---------------------------------------------------------------------------------------------
// 3. Fail-safe when there is no key.
// ---------------------------------------------------------------------------------------------

test("NO KEY: emits an explicit sentinel and NEVER falls back to the reversible hash", () => {
  for (const v of [SSN, PHONE, AWS]) {
    const h = hashWithKey(null, v);
    assert.equal(h, NO_KEY);
    assert.notEqual(h, legacyDjb2(v), "an unenrolled device must not emit the old reversible hash");
    assert.ok(!/^h[0-9a-f]+$/.test(h), "the sentinel must not be mistakable for a legacy hash");
    assert.ok(!h.includes(v));
  }
  // A constant, not a random value: a random per-alert value is indistinguishable from a real
  // fingerprint and would silently inflate any "distinct values seen" count downstream.
  assert.equal(hashWithKey(null, SSN), hashWithKey(null, AWS));
  assert.equal(deriveKey(""), null);
  assert.equal(deriveKey(undefined), null);
});

// ---------------------------------------------------------------------------------------------
// 4. The three runtimes must agree byte-for-byte.
// ---------------------------------------------------------------------------------------------

test("PARITY: node:crypto, the renderer copy and the extension copy produce identical hashes", () => {
  const samples = ["", SSN, PHONE, AWS, "naïve café 🔑", "x".repeat(200)];
  assert.equal(browserHash.KEY_LABEL, KEY_LABEL);
  assert.equal(extHash.KEY_LABEL, KEY_LABEL);
  const kRenderer = browserHash.deriveKey(TOKEN_A);
  const kExt = extHash.deriveKey(TOKEN_A);
  assert.equal(Buffer.from(kRenderer).toString("hex"), KEY_A.toString("hex"));
  assert.equal(Buffer.from(kExt).toString("hex"), KEY_A.toString("hex"));
  for (const s of samples) {
    const node = hashWithKey(KEY_A, s);
    assert.equal(browserHash.hashWithKey(kRenderer, s), node, `renderer diverged on ${JSON.stringify(s)}`);
    assert.equal(extHash.hashWithKey(kExt, s), node, `extension diverged on ${JSON.stringify(s)}`);
  }
  assert.equal(browserHash.hashWithKey(null, SSN), NO_KEY);
  assert.equal(extHash.hashWithKey(null, SSN), NO_KEY);
});

// ---------------------------------------------------------------------------------------------
// 5. End-to-end through the real hook process — the shipped enforcement path.
//
// The assertion target is the on-device evidence log (~/.curaiq/action-audit.jsonl), not the alert
// POST. `report()` fires the POST and the hook then calls process.exit() without awaiting it, so a
// network capture here is a race; the ledger write is a synchronous appendFileSync of the SAME alert
// object. It is also the more relevant artefact for this vulnerability — a copied audit log was one
// of the three ways the plaintext was recoverable.
// ---------------------------------------------------------------------------------------------

const TENANT = "acme";
const consoleKey = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(consoleKey.publicKey) });
function signPolicy(policy) {
  const iat = "2026-08-21T00:00:00.000Z";
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), consoleKey.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}

const SYSTEM_LATCH = process.platform === "win32"
  ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "offline-posture")
  : "/etc/moorai/offline-posture";
const HOST_LATCHED = existsSync(SYSTEM_LATCH);

const POLICY = signPolicy({ captureTier: "content-free", mcpAllow: ["something-else"] });

async function runHook(hookInput, { installToken = TOKEN_A } = {}) {
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(req.method === "POST" ? "{}" : req.url.startsWith("/api/policy/pubkey") ? pubkeyBody : POLICY);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const home = mkdtempSync(join(tmpdir(), "moorai-ch-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  try {
    writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${server.address().port}`, tenant: TENANT, installToken }));
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "fail-open" };
    delete env.MOORAI_POLICY_PUBKEY;
    delete env.MOORAI_BREAKGLASS_PUBKEY;
    const child = spawn(process.execPath, [HOOK], { env, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify(hookInput(home)));
    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c));
    await new Promise((r) => child.on("close", r));
    const read = (f) => { try { return readFileSync(join(home, ".curaiq", f), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } };
    return { stdout, actions: read("action-audit.jsonl"), events: read("agent-events.jsonl") };
  } finally {
    await new Promise((r) => server.close(r));
    rmSync(home, { recursive: true, force: true });
  }
}

const secretFile = (home) => {
  const f = join(home, "leak.env");
  writeFileSync(f, `AWS_ACCESS_KEY_ID=${AWS}\nSSN=${SSN}\nPHONE=${PHONE}\n`);
  return f;
};

test("E2E: a Read that exposes a secret records the KEYED hash, never the reversible DJB2", { skip: HOST_LATCHED && "host has a root-owned posture latch" }, async () => {
  const { actions, events } = await runHook((home) => ({ tool_name: "Read", tool_input: { file_path: secretFile(home) } }));
  assert.ok(actions.length > 0, `expected recorded findings, got ${JSON.stringify(actions)}`);
  for (const a of actions) assert.match(String(a.contentHash), /^h2:[0-9a-f]{16}$/, `${a.category} recorded ${a.contentHash}`);
  // Not just "starts with h2:" — the exact keyed hash of the matched span, computed independently.
  assert.ok(actions.some((a) => a.contentHash === hashWithKey(KEY_A, AWS)), "the AWS key's matched span must carry its keyed hash");
  // The behaviour log fingerprints the file path / command line; that is content-bearing too.
  for (const e of events) assert.match(String(e.sig), /\|h2:[0-9a-f]{16}$/, `agent-event sig ${e.sig}`);
  const wire = JSON.stringify({ actions, events });
  for (const v of [AWS, SSN, PHONE]) {
    assert.ok(!wire.includes(v), `the matched span ${v} reached the on-device log`);
    assert.ok(!wire.includes(legacyDjb2(v)), `the reversible DJB2 of ${v} is still being written`);
  }
  // The actor fingerprint is deliberately NOT converted: it hashes user@device, which the very same
  // record already carries in cleartext, so keying it would buy nothing and break actor dedup.
  for (const a of actions) assert.match(String(a.actor), /^h[0-9a-f]{1,8}$/, "actor must stay the plain DJB2");
});

test("E2E: MCP tool ARGUMENTS are keyed too", { skip: HOST_LATCHED && "host has a root-owned posture latch" }, async () => {
  const { actions } = await runHook(() => ({ tool_name: "mcp__probe__ping", tool_input: { note: SSN } }));
  const call = actions.find((a) => a.category === "MCP tool call");
  assert.ok(call, `expected an MCP tool-call record, got ${JSON.stringify(actions.map((a) => a.category))}`);
  assert.match(String(call.contentHash), /^h2:[0-9a-f]{16}$/, `MCP args recorded as ${call.contentHash}`);
  assert.equal(call.contentHash, hashWithKey(KEY_A, JSON.stringify({ note: SSN })));
  assert.ok(!JSON.stringify(actions).includes(SSN));
});

test("E2E: an UNENROLLED device records the sentinel, not a reversible hash", { skip: HOST_LATCHED && "host has a root-owned posture latch" }, async () => {
  const { actions } = await runHook((home) => ({ tool_name: "Read", tool_input: { file_path: secretFile(home) } }), { installToken: "" });
  assert.ok(actions.length > 0, "expected recorded findings even without an install token");
  for (const a of actions) assert.equal(a.contentHash, NO_KEY, `${a.category} fell back to ${a.contentHash}`);
  assert.ok(!JSON.stringify(actions).includes(legacyDjb2(AWS)), "an unenrolled device must not emit the old hash");
});

// ---------------------------------------------------------------------------------------------
// 6. Classification guard — the remaining djb2 call sites must all be NON-content.
//
// The fix is only complete if no content-bearing value is still fed to the reversible hash, and it
// is only correct if the non-content ones were LEFT ALONE (converting a server name or a policy
// fingerprint would break dedup for no confidentiality gain). Both halves are pinned here so a new
// `djb2(...)` on a matched span fails the suite instead of silently reintroducing the bug.
// ---------------------------------------------------------------------------------------------

const EXPECTED_DJB2_ARGS = {
  "cli/moorai-hook.mjs": [
    "bg.raw",                                   // break-glass marker (operator artefact, not user data)
    "`${os.userInfo().username}@${os.hostname()}`", // actor — the same record carries both in clear
    "String(d.usedGrants)",                     // JIT grant names (policy vocabulary)
    "d.reasons.join(\"|\")",                     // entitlement-drift reasons (policy vocabulary)
    "epD.hosts.join(\",\")",                     // model-endpoint hostnames (Bash path)
    "epD.hosts.join(\",\")",                     // model-endpoint hostnames (MCP path)
    "server",                                   // MCP server name
    "text"                                      // rules-file fingerprint (whole agent config file)
  ],
  "cli/moorai-guard.mjs": [
    "`${os.userInfo().username}@${os.hostname()}`",
    "epD.hosts.join(\",\")"
  ],
  "mcp-proxy/moorai-mcp-guard.mjs": [
    "`${os.userInfo().username}@${os.hostname()}`"
  ]
};

test("CLASSIFICATION: every surviving djb2() call site is non-content, and no new one appears", () => {
  for (const [file, expected] of Object.entries(EXPECTED_DJB2_ARGS)) {
    const src = readFileSync(join(ROOT, file), "utf8");
    const args = [...src.matchAll(/(?<!function )\bdjb2\(((?:[^()]|\([^()]*\))*)\)/g)].map((m) => m[1]);
    assert.deepEqual(args.sort(), [...expected].sort(), `${file} djb2 call sites changed`);
  }
});

test("CLASSIFICATION: no content site still reaches for the reversible hash", () => {
  for (const file of ["cli/moorai-hook.mjs", "cli/moorai-guard.mjs", "mcp-proxy/moorai-mcp-guard.mjs", "cli/secret-egress.mjs", "src/audit.js", "browser-ext/detectors.js"]) {
    const src = readFileSync(join(ROOT, file), "utf8");
    for (const forbidden of [/djb2\(f\.match/, /djb2\(c\.match/, /djb2\(prompt\)/, /djb2\(content\)/, /djb2\(args\)/, /djb2\(span\)/, /djb2\(v\)/]) {
      assert.ok(!forbidden.test(src), `${file} still hashes content with djb2: ${forbidden}`);
    }
  }
  // secret-egress fingerprints REAL credential values read off the disk — the highest-value input in
  // the product. It must not define or use a local djb2 at all any more.
  assert.ok(!/5381/.test(readFileSync(join(ROOT, "cli/secret-egress.mjs"), "utf8")), "secret-egress still carries a DJB2");
  assert.ok(!/5381/.test(readFileSync(join(ROOT, "browser-ext/detectors.js"), "utf8")), "the extension still carries a DJB2");
  assert.ok(!/5381/.test(readFileSync(join(ROOT, "src/audit.js"), "utf8")), "the Tauri audit log still carries a DJB2");
});

// The in-process default export reads ~/.curaiq/config.json once. On a dev box with no enrollment
// that is the no-key path, which is exactly the fail-safe behaviour asserted above; either way it is
// never a legacy hash.
test("the module-level contentHash() never returns a legacy-format value", () => {
  const h = contentHash(SSN);
  assert.ok(h === NO_KEY || /^h2:[0-9a-f]{16}$/.test(h), h);
  assert.ok(!/^h[0-9a-f]{1,8}$/.test(h), h);
});
