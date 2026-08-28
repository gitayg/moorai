// #20 — cryptographically signed, tamper-evident approval tokens for MCP enforcement decisions.
// MoorAI is hook-based (no proxy), so "block unsigned at a gateway" isn't the model; instead every
// MCP allow/deny the hook makes is signed with a per-device ed25519 key over a CONTENT-FREE token
// (tool + args HASH + decision + nonce + ts). The private key never leaves the device; the console
// verifies the signature and pins the public key (trust-on-first-use), so the Agency-Enforcement trail
// cannot be forged or tampered with. All of this is metadata — no prompt or argument content leaves.
import { generateKeyPairSync, createPrivateKey, createPublicKey, sign as cryptoSign, randomBytes } from "node:crypto";
import { contentHash } from "../cli/content-hash.mjs";
import { writeFileSync, mkdirSync } from "node:fs";
import { STATE_DIR, statePath, readState } from "../cli/state-dirs.mjs";

// The per-device signing key is a STABLE identity: the console pins its public half on first use
// (TOFU), so it must NOT be regenerated across the CuraIQ→MoorAI rebrand or the pin breaks. New keys
// are written to ~/.moorai; an existing key in the pre-rebrand ~/.curaiq (or ~/.raiseme) is read in
// place via readState() so an upgraded device keeps signing with its already-pinned key.
const KEY = statePath("agency-ed25519.key"); // ~/.moorai — the WRITE path for a brand-new device

let _priv = null, _pubB64 = null;
function loadKeys() {
  if (_priv) return true;
  const existing = readState("agency-ed25519.key"); // ~/.moorai, then pre-rebrand ~/.curaiq / ~/.raiseme
  if (existing) { try { _priv = createPrivateKey(existing); } catch { _priv = null; } }
  if (!_priv) {
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      mkdirSync(STATE_DIR, { recursive: true });
      writeFileSync(KEY, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
      _priv = privateKey;
    } catch { return false; }
  }
  try { _pubB64 = createPublicKey(_priv).export({ type: "spki", format: "der" }).toString("base64"); } catch { return false; }
  return true;
}

// Keyed one-way hash of the serialized tool arguments (never the arguments themselves). MCP arguments
// carry file paths, prompts and secrets, so this is the same small-input-space problem as a matched
// span: a plain SHA-256 of `{"path":"/etc/shadow"}` is guessable, so it goes through the tenant-keyed
// HMAC in cli/content-hash.mjs. The console rebuilds the signed canonical string from the argsHash
// field it RECEIVES (server/db.js `_verifyEd`), so changing the derivation does not affect signature
// verification — only what a reader of the stored token can recover from it.
export function argsHash(s) { return contentHash(s); }

// The exact bytes signed + verified — keep agent and server in lockstep.
export function canonical(t) { return `${t.tool}|${t.argsHash}|${t.decision}|${t.nonce}|${t.ts}`; }

// Sign an MCP decision. Returns { agency, sig, pub, alg } to merge into a content-free alert, or null
// (fail-open: a signing error must never change the enforcement decision).
export function signApproval(tool, argsH, decision) {
  try {
    if (!loadKeys()) return null;
    const agency = { tool, argsHash: argsH, decision, nonce: randomBytes(8).toString("hex"), ts: new Date().toISOString() };
    const sig = cryptoSign(null, Buffer.from(canonical(agency)), _priv).toString("base64");
    return { agency, sig, pub: _pubB64, alg: "ed25519" };
  } catch { return null; }
}
