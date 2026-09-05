#!/usr/bin/env node
// MoorAI — signed, content-free per-verdict DECISION RECEIPTS.
//
// A decision receipt is the smallest independently-verifiable proof that a specific governance verdict
// was made on this device: for one governed action it captures the content-free verdict fields
// (tool, category, risk, decision, stage, tenant, the one-way content hash, and the chain link seq/prev/
// chash, plus the verdict timestamp), binds them all under a single SHA-256 digest, and signs that
// digest with the device's per-device ed25519 key. Anyone holding the device's pinned public key can
// later confirm — with NO network and NO console — that the verdict is authentic and that not one field
// was altered. It is the per-verdict complement to the whole-stream in-toto attestation (moorai-attest):
// the attestation proves a chain of verdicts; a receipt is a single verdict you can hand to an auditor.
//
// SACRED RULE — content-free: a record is NEVER spread. sanitizeReceiptPayload() is a strict allowlist,
// so a stray prompt / argument / path field on the audit row can never reach the receipt. Every field is
// governance metadata or a one-way hash.
//
// REUSE, DON'T ROLL CRYPTO: signing goes through data/agency-sign.mjs — the SAME per-device ed25519 key
// the MCP-approval tokens use (signApproval), over its canonical() bytes. No new key, no new signer.
// The receipt's digest is carried as agency.argsHash, so the existing signature machinery binds it.
//
// POST-HOC, FAIL-OPEN: this runs over the on-device action-audit log AFTER the fact. It is never on the
// enforcement hot path, and generation never throws — a signing failure yields an UNSIGNED receipt
// (signature: null), it does not block anything. Verification, by contrast, fails CLOSED — see
// verifyReceipt(): a bad signature, a mismatched digest, or a missing key is reported invalid.
//
//   node cli/moorai-receipt.mjs                 # emit signed receipts for this device's action-audit log
//   node cli/moorai-receipt.mjs --format json
//   node cli/moorai-receipt.mjs --help
//
// Also usable as a pure library: buildReceipt(record, { sign }) and verifyReceipt(receipt, { pubkey }).

import { createHash, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { chainOf } from "./record-chain.mjs";
import { parseTrustedKeys } from "./hook-core.mjs";
import { signApproval, canonical } from "../data/agency-sign.mjs";

export const RECEIPT_TYPE = "moorai.decision-receipt/v1";

const str = (v) => (v == null ? "" : String(v));

// The exact, ordered content-free field set a receipt commits to. A FIXED order (not a runtime sort of
// arbitrary keys) makes the digest deterministic and immune to any stray field on the input — nothing
// outside this list can ever enter the digest, so the digest itself is content-free by construction.
const RECEIPT_FIELDS = ["tool", "category", "risk", "decision", "stage", "tenant", "contentHash", "seq", "prev", "chash", "ts"];

// STRICT allowlist → a content-free receipt payload. Accepts BOTH a raw audit record (chain metadata
// under the namespaced `chain` key, via chainOf) AND an already-flattened payload (flat seq/prev/chash),
// so verifyReceipt can re-sanitize a payload and recompute the identical digest. Never spreads the row.
export function sanitizeReceiptPayload(r = {}) {
  const c = chainOf(r) || {};
  const seq = Number.isInteger(c.seq) ? c.seq : (Number.isInteger(r.seq) ? r.seq : null);
  return {
    tool: str(r.tool),
    category: str(r.category),
    risk: str(r.risk != null ? r.risk : r.riskLevel),
    decision: str(r.decision),
    stage: str(r.stage),
    tenant: str(r.tenant),
    contentHash: str(r.contentHash),
    seq,
    prev: c.prev != null ? str(c.prev) : str(r.prev),
    chash: c.chash != null ? str(c.chash) : str(r.chash),
    ts: str(r.ts)
  };
}

// Deterministic SHA-256 over the ordered content-free fields. Keyless — this is a binding digest, not a
// secrecy primitive (the underlying values are already one-way hashes or public metadata). Every payload
// field is folded in, so altering any one field changes the digest and breaks the signature.
export function receiptDigest(payload = {}) {
  const pairs = RECEIPT_FIELDS.map((k) => [k, payload[k] == null ? "" : payload[k]]);
  return createHash("sha256").update(JSON.stringify(pairs), "utf8").digest("hex");
}

// Default signer: the device's per-device ed25519 key via agency-sign. Returns { agency, sig, pub, alg }
// or null (fail-open). The receipt digest rides as agency.argsHash, so agency-sign's canonical() covers
// it and no new signing routine is introduced.
function defaultSign(tool, digest, decision) {
  return signApproval(tool, digest, decision);
}

// Build a content-free, signed decision receipt from one governed record. Pure and fail-open: a signing
// failure (or an injected signer returning null) yields a structurally valid but UNSIGNED receipt
// (signature: null) — it never throws and never blocks. `sign` is injectable for tests.
export function buildReceipt(record, { sign = defaultSign } = {}) {
  const payload = sanitizeReceiptPayload(record || {});
  const digest = receiptDigest(payload);
  let signature = null;
  try {
    const s = sign(payload.tool, digest, payload.decision);
    if (s && s.sig && s.pub) signature = { agency: s.agency, sig: s.sig, pub: s.pub, alg: s.alg || "ed25519" };
  } catch { signature = null; }
  return { type: RECEIPT_TYPE, payload, digest, signature };
}

function keyFrom(pubkey) {
  if (!pubkey) return null;
  if (typeof pubkey === "object" && pubkey.type === "public") return pubkey; // already a KeyObject
  const keys = parseTrustedKeys(String(pubkey)); // PEM block(s) and/or base64 SPKI DER line(s)
  return keys.length ? keys[0] : null;
}

// Export a public KeyObject back to the canonical base64 SPKI DER string agency-sign emits, so a
// provided key can be compared byte-for-byte against the receipt's embedded pub (pin check).
function keyToB64(k) {
  try { return k.export({ type: "spki", format: "der" }).toString("base64"); } catch { return null; }
}

// Verify a decision receipt OFFLINE — no network, no console. FAILS CLOSED: any of a malformed shape, a
// digest that does not recompute (a tampered payload), an unsigned receipt, an agency block not bound to
// the payload, a missing/unparseable key, a pin mismatch, or a bad ed25519 signature is reported invalid.
//
// Key selection: pass { pubkey } (a base64 SPKI DER / PEM string, or a KeyObject) to verify against a
// PINNED key — the trustworthy check; if the receipt also carries a pub that differs, that is a
// key_mismatch and is rejected. With no pubkey it falls back to the receipt's OWN embedded pub (pinned:
// false) — this confirms internal consistency but is NOT proof of origin, so callers wanting real
// assurance must pin. Returns { ok, reason, signed, pinned }.
export function verifyReceipt(receipt, { pubkey } = {}) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) return { ok: false, reason: "malformed", signed: false, pinned: false };
  const payload = receipt.payload;
  if (!payload || typeof payload !== "object") return { ok: false, reason: "malformed", signed: false, pinned: false };

  const recomputed = receiptDigest(sanitizeReceiptPayload(payload));
  if (recomputed !== str(receipt.digest)) return { ok: false, reason: "digest_mismatch", signed: !!receipt.signature, pinned: false };

  const sigblk = receipt.signature;
  if (!sigblk || typeof sigblk !== "object" || !sigblk.sig) return { ok: false, reason: "unsigned", signed: false, pinned: false };

  const ag = sigblk.agency || {};
  if (str(ag.argsHash) !== recomputed) return { ok: false, reason: "agency_digest_mismatch", signed: true, pinned: false };
  if (str(ag.tool) !== str(payload.tool) || str(ag.decision) !== str(payload.decision)) return { ok: false, reason: "agency_binding_mismatch", signed: true, pinned: false };

  const provided = keyFrom(pubkey);
  let keyObj = null, pinned = false;
  if (pubkey) {
    if (!provided) return { ok: false, reason: "bad_key", signed: true, pinned: false };
    // A pinned key that disagrees with the receipt's own pub is a substitution attempt — reject.
    if (sigblk.pub && keyToB64(provided) !== str(sigblk.pub)) return { ok: false, reason: "key_mismatch", signed: true, pinned: true };
    keyObj = provided; pinned = true;
  } else {
    keyObj = keyFrom(sigblk.pub); // unpinned fallback: the receipt's self-declared key
  }
  if (!keyObj) return { ok: false, reason: "no_key", signed: true, pinned };

  let ok = false;
  try { ok = cryptoVerify(null, Buffer.from(canonical(ag)), keyObj, Buffer.from(str(sigblk.sig), "base64")); } catch { ok = false; }
  return { ok, reason: ok ? null : "bad_signature", signed: true, pinned };
}

// ------------------------------------------------------------------------------------------------
// CLI — emit content-free receipts for THIS device's action-audit log. Best-effort: on any read/build
// error it degrades to an empty list rather than throwing.
// ------------------------------------------------------------------------------------------------
const HELP = `MoorAI decision-receipt — signed, content-free per-verdict receipts.

Usage:
  moorai-receipt [--format text|json]

Reads this device's action-audit log and emits one signed, content-free decision receipt per governed
record: { tool, category, risk, decision, stage, tenant, contentHash, seq/prev/chash, ts } bound under a
SHA-256 digest and signed with the device's ed25519 key. No prompt, argument, or path content is included.
Verify a receipt offline with:  moorai-verify-chain --offline <receipt.json> [--pubkey <key>]
`;

async function main() {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }
  let rows = [];
  try { const s = await import("./signals.mjs"); rows = s.readActions(); } catch { rows = []; }
  const receipts = (Array.isArray(rows) ? rows : []).map((r) => buildReceipt(r));
  process.stdout.write(JSON.stringify(receipts, null, 2) + "\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
