// #20 — cryptographically signed, tamper-evident approval tokens for MCP enforcement decisions.
// MoorAI is hook-based (no proxy), so "block unsigned at a gateway" isn't the model; instead every
// MCP allow/deny the hook makes is signed with a per-device ed25519 key over a CONTENT-FREE token
// (tool + args HASH + decision + nonce + ts). The private key never leaves the device; the console
// verifies the signature and pins the public key (trust-on-first-use), so the Agency-Enforcement trail
// cannot be forged or tampered with. All of this is metadata — no prompt or argument content leaves.
import { generateKeyPairSync, createPrivateKey, createPublicKey, sign as cryptoSign, randomBytes, createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const DIR = join(homedir(), ".curaiq");
const KEY = join(DIR, "agency-ed25519.key");

let _priv = null, _pubB64 = null;
function loadKeys() {
  if (_priv) return true;
  try { _priv = createPrivateKey(readFileSync(KEY, "utf8")); } catch {
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      mkdirSync(DIR, { recursive: true });
      writeFileSync(KEY, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
      _priv = privateKey;
    } catch { return false; }
  }
  try { _pubB64 = createPublicKey(_priv).export({ type: "spki", format: "der" }).toString("base64"); } catch { return false; }
  return true;
}

// Content-free hash of the serialized tool arguments (never the arguments themselves).
export function argsHash(s) { return createHash("sha256").update(String(s || "")).digest("base64").slice(0, 22); }

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
