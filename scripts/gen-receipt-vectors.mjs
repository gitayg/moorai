#!/usr/bin/env node
// Regenerates test/fixtures/approval-receipts/vectors.json: approval-receipt test vectors (docs/approval-receipts.md)
// for a hub verifier. Deterministic: a fixed test key from a public seed (ed25519 signatures are deterministic),
// fixed nonces and times. test/approval-receipts.test.mjs fails if the committed file and this output differ.
//
//   node scripts/gen-receipt-vectors.mjs
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalJson } from "../cli/canonical-json.mjs";
import { argsSha256, buildPayload, encodeWire, signingInput, rawPublicKey, receiptKeyId, receiptActionHashInput, verifyReceipt, SIGN_PREFIX, MAX_TTL_SEC } from "../cli/approval-receipts.mjs";
import { deriveKey, hashWithKey } from "../cli/content-hash.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const OUT = join(ROOT, "test", "fixtures", "approval-receipts", "vectors.json");
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
// One deterministic test key per source: the hub pins each with its keySource, and trust follows the key.
const SEED_LABELS = { console: "moorai-approval-receipt-test-vector-console-key-v1", helper: "moorai-approval-receipt-test-vector-helper-key-v1", device: "moorai-approval-receipt-test-vector-device-key-v1" };
const MODEL_SEED_LABEL = "moorai-approval-receipt-test-vector-model-key-v1";
const seedOf = (label) => createHash("sha256").update(label, "utf8").digest();
const keyOf = (label) => createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seedOf(label)]), format: "der", type: "pkcs8" });
const TEST_INSTALL_TOKEN = "test-install-token-not-a-secret";

const AUD = "it-ai-test-hub";
const IAT = 1790000000;
const NOW = 1790000030;
const DEVICE = "h2:1a2b3c4d5e6f7081";
const SESSION = "h2:90a1b2c3d4e5f607";
const APR = "apr_01JD7Z3Q4R5S6T7V8W9X0YZABC";
const APPROVER = "h2:aa11bb22cc33dd44";
const nonce = (i) => createHash("sha256").update(`nonce-${i}`).digest("hex").slice(0, 32);

// Sign any payload object (also ones mintReceipt would refuse), for the invalid cases.
function signRaw(payload, key) {
  const sig = edSign(null, signingInput(payload), key);
  return { sig, wire: encodeWire(payload, sig) };
}

export function buildVectors() {
  const K = {};
  for (const [src, label] of Object.entries(SEED_LABELS)) {
    const priv = keyOf(label), pub = createPublicKey(priv);
    K[src] = { priv, seedLabel: label, seedHex: seedOf(label).toString("hex"), publicKey: rawPublicKey(pub), keyId: receiptKeyId(pub) };
  }
  const pinned = ["console", "helper", "device"].map((src) => ({ keyId: K[src].keyId, publicKey: K[src].publicKey, keySource: src }));
  const modelKey = keyOf(MODEL_SEED_LABEL);
  const tokenKey = deriveKey(TEST_INSTALL_TOKEN);
  const cases = [];

  // A case: the receipt is minted over `signedArgs` (parsed) and the hub receives `argumentsJson` (the exact text,
  // with _moorai holding the wire string inserted as the last key).
  function add({ name, note, tool = "run_command", hubTool, signedArgs, receivedArgs, payloadOver = {}, ttl = 60, iat = IAT, fields = {}, signWith, tamper, seen, expect }) {
    const claimed = fields.keySource || "console";
    const sk = signWith || K[claimed].priv;
    const p0 = buildPayload({ aud: AUD, tool, input: signedArgs, device: DEVICE, session: SESSION, nonce: nonce(cases.length), iat, ttlSec: Math.min(ttl, MAX_TTL_SEC), basis: "approved", keySource: "console", approvalId: APR, keyId: receiptKeyId(createPublicKey(sk)), ...fields });
    if (!p0) throw new Error(`payload refused: ${name}`);
    const payload = { ...p0, ...payloadOver };
    if (ttl > MAX_TTL_SEC) payload.exp = payload.iat + ttl;
    for (const k of Object.keys(payload)) if (payload[k] === undefined) delete payload[k];
    let { sig, wire } = signRaw(payload, sk);
    if (tamper) { const s = Buffer.from(sig); s[0] ^= 0x01; sig = s; wire = encodeWire(payload, s); }
    const recv = receivedArgs || signedArgs;
    const argumentsJson = recv.__json ? `${recv.__json.slice(0, -1)},"_moorai":{"receipt":"${wire}"}}` : JSON.stringify({ ...recv, _moorai: { receipt: wire } });
    const parsed = JSON.parse(argumentsJson);
    const bare = recv.__json ? JSON.parse(recv.__json) : recv;
    const c = {
      name, ...(note ? { note } : {}),
      tool: hubTool || tool,
      argumentsJson,
      argsCanonical: canonicalJson(bare),
      argsSha256: argsSha256(parsed),
      actionHashInput: receiptActionHashInput(tool, argsSha256(signedArgs.__json ? JSON.parse(signedArgs.__json) : signedArgs), payload.aud),
      payload,
      payloadCanonical: canonicalJson(payload),
      signingInput: SIGN_PREFIX + canonicalJson(payload),
      signatureB64url: sig.toString("base64url"),
      wire,
      ...(seen ? { seen } : {}),
      expect
    };
    c.actionHash = hashWithKey(tokenKey, c.actionHashInput);
    const got = verifyReceipt(wire, { keys: pinned, aud: AUD, tool: c.tool, input: parsed, nowSec: NOW, seen: new Set(seen || []) });
    for (const k of ["receiptValid", "reason", "hubAction", "queueReason"]) {
      const g = k === "receiptValid" ? got.ok : k === "hubAction" ? (got.skipQueue ? "skip-queue" : "queue") : got[k];
      if (g !== expect[k]) throw new Error(`vector ${name}: ${k} is ${g}, expected ${expect[k]}`);
    }
    cases.push(c);
  }
  const SKIP = { receiptValid: true, reason: null, hubAction: "skip-queue", queueReason: null };
  const rej = (reason) => ({ receiptValid: false, reason, hubAction: "queue", queueReason: "invalid receipt" });
  const BASE = { device: "lab-01", command: "whoami" };
  // Received in a key order that is not canonical; the hash is over the canonical form of the parsed object.
  const UNSORTED = { __json: '{"timeout_secs":30,"command":"ls -la","dry_run":false,"device":"lab-01"}' };

  add({ name: "console-approved", note: "A person approved the call in the console; the hub skips its queue.", signedArgs: BASE, expect: SKIP });
  add({ name: "console-approved-int-bool-approver", note: "Arguments with an integer and a boolean, received in non-canonical key order; argsSha256 is over the canonical JSON of the parsed arguments, never the received bytes. Carries the optional approver pseudonym.", signedArgs: { timeout_secs: 30, command: "ls -la", dry_run: false, device: "lab-01" }, receivedArgs: UNSORTED, fields: { approver: APPROVER }, expect: SKIP });
  add({ name: "helper", note: "keySource helper (reserved for the privileged local helper): the hub skips its queue.", signedArgs: BASE, fields: { basis: "allowed", keySource: "helper", approvalId: undefined }, expect: SKIP });
  add({ name: "device-allowed", note: "keySource device is advisory (any process of the same OS user can sign with the device key): valid, but the hub queues.", signedArgs: BASE, fields: { basis: "allowed", keySource: "device", approvalId: undefined }, expect: { receiptValid: true, reason: null, hubAction: "queue", queueReason: "keySource device" } });
  add({ name: "non-integer-float", note: "hub queues: non-integer number. The receipt is valid, but a float's text form is not reproduced by every canonicalizer.", signedArgs: { ...BASE, timeout_secs: 2.5 }, expect: { receiptValid: true, reason: null, hubAction: "queue", queueReason: "non-integer number" } });
  add({ name: "integer-above-2-53", note: "hub queues: non-integer number. 9007199254740994 is above 2^53, outside the integers a JSON number in an IEEE double holds exactly.", signedArgs: { ...BASE, timeout_secs: 9007199254740994 }, expect: { receiptValid: true, reason: null, hubAction: "queue", queueReason: "non-integer number" } });
  add({ name: "bad-signature", note: "First signature byte flipped.", signedArgs: BASE, tamper: true, expect: rej("bad_signature") });
  add({ name: "expired", note: "exp is before the hub's now.", signedArgs: BASE, iat: IAT - 100, expect: rej("expired") });
  add({ name: "wrong-aud", note: "Minted for another hub.", signedArgs: BASE, payloadOver: { aud: "other-hub" }, expect: rej("wrong_aud") });
  add({ name: "wrong-tool", note: "Minted for dissolve_agent, attached to run_command.", tool: "dissolve_agent", hubTool: "run_command", signedArgs: BASE, expect: rej("wrong_tool") });
  add({ name: "args-mismatch", note: "Minted for one command, the hub received another.", signedArgs: BASE, receivedArgs: { device: "lab-01", command: "rm -rf /tmp/x" }, expect: rej("args_mismatch") });
  add({ name: "model-injected", note: "A _moorai receipt written by the model (signed by a key the hub does not pin). MoorAI strips a model-supplied _moorai and replaces it; a hub must still reject it.", signedArgs: BASE, signWith: modelKey, expect: rej("unknown_key") });
  add({ name: "device-approved", note: "keySource device claiming basis approved: refused (a device receipt is always basis allowed).", signedArgs: BASE, fields: { basis: "allowed", keySource: "device", approvalId: undefined }, payloadOver: { basis: "approved", approvalId: APR }, expect: rej("bad_basis") });
  add({ name: "ttl-too-long", note: "exp - iat is 121 s; the limit is 120.", signedArgs: BASE, ttl: 121, expect: rej("ttl_too_long") });
  add({ name: "device-key-claims-console", note: "Signed by the device key, payload claims keySource console with basis approved: refused. Trust follows the pinned key's keySource, never the payload's.", signedArgs: BASE, signWith: K.device.priv, expect: rej("bad_basis") });
  add({ name: "device-key-claims-helper", note: "Signed by the device key, payload claims keySource helper: refused.", signedArgs: BASE, signWith: K.device.priv, fields: { basis: "allowed", keySource: "helper", approvalId: undefined }, expect: rej("bad_basis") });
  add({ name: "console-key-basis-allowed", note: "Signed by the console key with basis allowed (no approval): valid, but the hub queues; only an approval skips the queue.", signedArgs: BASE, fields: { basis: "allowed", approvalId: undefined }, expect: { receiptValid: true, reason: null, hubAction: "queue", queueReason: "basis allowed" } });
  add({ name: "replay", note: "The hub has already seen this nonce (the same receipt presented again).", signedArgs: BASE, seen: [`nonce:${nonce(cases.length)}`, `approvalId:${APR}`], expect: rej("replay") });
  add({ name: "approval-id-reused", note: "A second console receipt for the same approval (same approvalId, a new nonce) after the hub accepted the first (the console-approved case): refused. The approvalId and the nonce are each single-use; one approval runs exactly one action.", signedArgs: BASE, seen: [`nonce:${cases[0].payload.nonce}`, `approvalId:${APR}`], expect: rej("replay") });

  return {
    v: 1,
    spec: "docs/approval-receipts.md",
    signPrefix: SIGN_PREFIX,
    canonicalJson: "keys sorted recursively (UTF-16 code unit order), no insignificant whitespace, UTF-8, strings and numbers as ECMAScript JSON.stringify writes them",
    keyEncoding: { publicKey: "raw 32-byte ed25519 public key, base64url, no padding", keyId: "first 32 lowercase hex characters of SHA-256 over the raw 32-byte public key", seed: "private key seed = SHA-256(UTF-8 seedLabel), the 32-byte ed25519 seed (RFC 8032)" },
    keys: Object.fromEntries(Object.entries(K).map(([src, k]) => [src, { seedLabel: k.seedLabel, seedHex: k.seedHex, publicKey: k.publicKey, keyId: k.keyId }])),
    modelKey: { seedLabel: MODEL_SEED_LABEL, keyId: receiptKeyId(createPublicKey(modelKey)), note: "not pinned by the hub" },
    actionHash: { installToken: TEST_INSTALL_TOKEN, formula: "contentHash(\"approval\" + U+0000 + canonicalJson({argsSha256, aud, tool: <bare tool>})); contentHash(s) = \"h2:\" + first 16 hex of HMAC-SHA256(key, s), key = HMAC-SHA256(installToken, \"moorai/content-hash/v2\")" },
    hub: { aud: AUD, nowSec: NOW, iatSkewSec: 30, keys: pinned, replayKey: "the nonce and the approvalId are each single-use: refuse when \"nonce:<nonce>\" was seen, or when the receipt has an approvalId and \"approvalId:<approvalId>\" was seen; record both" },
    cases
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify(buildVectors(), null, 2) + "\n");
  process.stdout.write(`wrote ${OUT}\n`);
}
