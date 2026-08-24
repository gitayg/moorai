// One-way content fingerprint for anything that leaves the device — alerts POSTed to /api/alerts,
// the SIEM records the console forwards, and the on-device JSONL logs (audit.jsonl,
// exposure-ledger.jsonl, action-audit.jsonl).
//
// ---------------------------------------------------------------------------------------------
// WHY THIS IS KEYED, AND NOT MERELY "A STRONGER HASH"
// ---------------------------------------------------------------------------------------------
// The value being fingerprinted is exactly the thing this product exists to protect: a phone
// number, an SSN, a payment card, an API key. The input space for those is TINY — every US phone
// number is 10^10 candidates, every SSN 10^9, every card 10^16 with a Luhn check that prunes 90%
// of it. An UNKEYED digest over a small space is not one-way in practice, it is an ENCODING:
// enumerate the space, digest each candidate, and read the plaintext back out of your own table.
//
// That was true of the 32-bit DJB2 this replaces (reversed in single-digit milliseconds on a
// laptop) and it is EQUALLY true of a plain SHA-256 — SHA-256 does not add entropy the input did
// not have. Only a SECRET mixed into the hash input breaks the enumeration. Hence HMAC-SHA-256.
//
// ---------------------------------------------------------------------------------------------
// KEY SCOPE: PER TENANT. The evidence behind that choice:
// ---------------------------------------------------------------------------------------------
//   * The field's PURPOSE is correlation/dedup — "the same secret was seen again", "this value
//     reached three different devices". A per-DEVICE key would permanently shrink that to
//     per-device correlation; a per-TENANT key keeps the fleet-wide answer available.
//   * The console does not correlate on it today: nothing in the server GROUPs BY, JOINs on, or
//     dedups by content_hash — it is an unindexed TEXT column that is stored and forwarded to
//     SIEM/CEF verbatim. So the scope choice breaks nothing either way right now, which is
//     precisely why it should be the WIDER one: per-device would foreclose the fleet-wide query
//     forever, per-tenant leaves it buildable in the SIEM with no device re-instrumentation.
//   * Cross-TENANT linkage is the property we actively want gone (two customers' consoles, or one
//     SIEM ingesting both, must not be able to tell they hold the same secret). Distinct tenant
//     tokens produce independent keys, so it is gone.
//   * The hook, the desktop host, the Claude Desktop MCP proxy and the browser extension all
//     fingerprint the same spans and are all provisioned with the SAME per-tenant installToken.
//     Deriving from it keeps their hashes byte-identical — a property this repo already relies on
//     and tests — with no new provisioning step, no new secret to distribute, and no console change.
//
// KEY SOURCE: the enrollment installToken in ~/.curaiq/config.json. `packaging/mdm/jamf/
// moorai-jamf-deploy.sh` documents it as the "per-tenant enroll token" and pushes one value to the
// whole fleet; the browser extension's options page takes the same token. It is passed through one
// HMAC with a domain-separation label so the hashing key is not the bearer token itself.
//
// ---------------------------------------------------------------------------------------------
// WHAT THIS DEFENDS, AND WHAT IT DOES NOT
// ---------------------------------------------------------------------------------------------
// It defends the places the plaintext is NOT and where a reader holds hashes but not the key: the
// console's alerts table, the SIEM/CEF stream, and any log copied off the box. That is the real
// threat — a server DB dump, SIEM access, or a stolen audit.jsonl must not yield plaintext SSNs.
//
// It does NOT defend against an attacker who already owns the device. That attacker reads
// ~/.curaiq/config.json for the token and — far more to the point — reads the plaintext directly
// off disk and out of memory. No on-device hash can change that, and claiming otherwise would be
// the same overclaim this commit exists to remove.
//
// NO-KEY BEHAVIOUR IS FAIL-SAFE: an unenrolled device emits the constant NO_KEY sentinel. It never
// falls back to a reversible hash. A constant is chosen over a random value on purpose — a random
// per-alert value is indistinguishable from a real fingerprint and would silently inflate any
// "distinct values seen" count, whereas `h2:nokey` is self-describing to anyone reading the column.
import { createHmac, createHash } from "node:crypto";
import { loadConfig } from "./config.mjs";

export const HASH_PREFIX = "h2:";       // version tag: old reversible values are bare "h<hex>"
export const NO_KEY = "h2:nokey";       // no enrollment key → explicitly non-correlatable
export const KEY_LABEL = "moorai/content-hash/v2";
const HEX_LEN = 16;                     // 64 bits — ample for correlation, far past any enumeration

// HMAC-SHA-256(installToken, label) → 32 raw key bytes. The tenant slug is deliberately NOT folded
// in: it is public, it adds no entropy, and the console mints each install token as a fresh
// randomUUID mapped 1:1 to a tenant, so the token alone already separates tenants. Leaving it out is
// what lets the browser extension — whose options page holds the token but not the tenant — produce
// hashes byte-identical to the agent's.
export function deriveKey(installToken) {
  if (!installToken) return null;
  return createHmac("sha256", String(installToken)).update(KEY_LABEL, "utf8").digest();
}

// Pure form — takes the key explicitly. Used by the tests and by any caller holding its own key.
export function hashWithKey(key, s) {
  if (!key) return NO_KEY;
  return HASH_PREFIX + createHmac("sha256", key).update(String(s == null ? "" : s), "utf8").digest("hex").slice(0, HEX_LEN);
}

let _key, _resolved = false;
function key() {
  if (!_resolved) {
    _resolved = true;
    try { _key = deriveKey(loadConfig().installToken); } catch { _key = null; }
  }
  return _key;
}

// The call every emit site uses: fingerprint a matched span / prompt / argument blob.
export function contentHash(s) { return hashWithKey(key(), s); }

// A drift FINGERPRINT is a different problem from a content hash, and needs a different primitive.
//
// It compares a whole file against its own previous value, so it must be stable on every device —
// including an unenrolled one. contentHash() cannot serve: with no enrollment token it returns the
// NO_KEY sentinel for every input, so every file hashes identically and drift silently stops
// firing. That is a detection outage disguised as a privacy feature.
//
// Unkeyed is acceptable HERE, where it was not for a matched span, because the threat differs. A
// span is drawn from a tiny space (~10^9 SSNs) and is therefore enumerable; a whole agent config
// file is not, so reversal is not the risk. The risk is FORGERY — a 32-bit djb2 lets an attacker
// who controls the file append a suffix that collides with the stored baseline and suppresses the
// drift alert. SHA-256 removes that, and needs no key to do it.
export const FP_PREFIX = "fp2:";
export function fileFingerprint(s) {
  return FP_PREFIX + createHash("sha256").update(String(s ?? ""), "utf8").digest("hex").slice(0, 16);
}
