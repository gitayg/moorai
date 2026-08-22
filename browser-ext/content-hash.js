// MoorAI Browser Guard — keyed, one-way content fingerprint.
//
// Twin of src/content-hash.js, which is in turn the browser twin of cli/content-hash.mjs. Read
// cli/content-hash.mjs for the full rationale: why the fingerprint is KEYED (HMAC-SHA-256) rather
// than merely "a stronger hash", why the key is per-TENANT, and what it does and does not defend.
//
// Why a THIRD copy rather than an import: an MV3 content script cannot use ESM, and the extension
// gates the send synchronously inside a capture-phase keydown/click handler — it must call
// preventDefault(), so it cannot await crypto.subtle. So SHA-256 and HMAC are implemented here
// synchronously. The output is ordinary HMAC-SHA-256 and is byte-identical to the agent's for the
// same key and input; test/content-hash.test.mjs asserts that parity against node:crypto AND
// against src/content-hash.js, so a divergence between the copies fails the suite.
//
// Key material: the per-tenant installToken the user pastes on the options page — the same token the
// desktop agent is enrolled with, which is why the two produce identical hashes for identical spans.
// No token configured → the NO_KEY sentinel, never a fallback to the old reversible hash.
//
// Loadable two ways from ONE file, like detectors.js:
//   * Chrome MV3 content script  → sets globalThis.MoorAIContentHash
//   * Node (unit test)           → module.exports = api

(function (root) {
  "use strict";

  const HASH_PREFIX = "h2:";
  const NO_KEY = "h2:nokey";
  const KEY_LABEL = "moorai/content-hash/v2";
  const HEX_LEN = 16;

  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

  function sha256(bytes) {
    const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const l = bytes.length;
    const buf = new Uint8Array((((l + 8) >> 6) + 1) << 6);
    buf.set(bytes);
    buf[l] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(buf.length - 8, Math.floor(l / 536870912)); // high 32 bits of l*8
    dv.setUint32(buf.length - 4, (l << 3) >>> 0);
    const w = new Uint32Array(64);
    for (let off = 0; off < buf.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i]);
    return out;
  }

  const enc = (s) => new TextEncoder().encode(String(s == null ? "" : s));

  function hmacSha256(keyBytes, msgBytes) {
    let k = keyBytes;
    if (k.length > 64) k = sha256(k);
    const inner = new Uint8Array(64 + msgBytes.length);
    const outer = new Uint8Array(64 + 32);
    for (let i = 0; i < 64; i++) {
      const kb = i < k.length ? k[i] : 0;
      inner[i] = kb ^ 0x36;
      outer[i] = kb ^ 0x5c;
    }
    inner.set(msgBytes, 64);
    outer.set(sha256(inner), 64);
    return sha256(outer);
  }

  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

  function deriveKey(installToken) {
    if (!installToken) return null;
    return hmacSha256(enc(installToken), enc(KEY_LABEL));
  }

  function hashWithKey(key, s) {
    if (!key) return NO_KEY;
    return HASH_PREFIX + hex(hmacSha256(key, enc(s))).slice(0, HEX_LEN);
  }

  // The content script's live key. content.js already reads chrome.storage.sync at startup and on
  // change; it hands the token here so scan() stays synchronous.
  let _key = null;
  function setKey(installToken) { _key = deriveKey(installToken); }
  function contentHash(s) { return hashWithKey(_key, s); }

  const api = { sha256, hmacSha256, deriveKey, hashWithKey, setKey, contentHash, HASH_PREFIX, NO_KEY, KEY_LABEL };

  if (typeof module !== "undefined" && module.exports) module.exports = api; // Node (unit test)
  root.MoorAIContentHash = api;                                             // content-script isolated world
})(typeof globalThis !== "undefined" ? globalThis : this);
