// HMAC-SHA-256 in plain JS, for the instruction-leak fingerprints (data/instruction-fingerprint.js).
// Browser-safe on purpose (no node: imports) because the detector that consumes it lives in data/, which
// the desktop app and the extension bundle; WebCrypto is async and cannot run inside a sync refine().
//
// Why a real PRF and not a seeded murmur/FNV: the stored fingerprints are hashes of 7-word shingles of
// the user's rules files. An attacker holding the cache file and GUESSING text (a template line, a line
// from a public repo's CLAUDE.md) must not be able to confirm the guess without the device key, and a
// seeded non-cryptographic hash lets the seed be brute-forced from one known shingle. HMAC-SHA-256
// keyed with 32 random bytes does not.
//
// makeKeyedHash(key) precomputes the ipad/opad states once, so each call costs two or three compression
// rounds; the result is the first 40 bits of the MAC as a Number (exact in a double, compact in JSON).

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
const IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const W = new Uint32Array(64);

function compress(st, buf, off) {
  for (let i = 0; i < 16; i++) {
    const j = off + i * 4;
    W[i] = (buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3];
  }
  for (let i = 16; i < 64; i++) {
    const a = W[i - 15], b = W[i - 2];
    const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
    const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
  }
  let a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  st[0] = (st[0] + a) | 0; st[1] = (st[1] + b) | 0; st[2] = (st[2] + c) | 0; st[3] = (st[3] + d) | 0;
  st[4] = (st[4] + e) | 0; st[5] = (st[5] + f) | 0; st[6] = (st[6] + g) | 0; st[7] = (st[7] + h) | 0;
}

// SHA-256 of `msg` continuing from `state` after `prefixLen` bytes were already absorbed.
function finish(state, msg, prefixLen) {
  const st = Int32Array.from(state);
  const full = msg.length - (msg.length % 64);
  for (let off = 0; off < full; off += 64) compress(st, msg, off);
  const rest = msg.length - full;
  const tail = new Uint8Array(rest < 56 ? 64 : 128);
  tail.set(msg.subarray(full));
  tail[rest] = 0x80;
  const bits = (prefixLen + msg.length) * 8;
  const n = tail.length;
  tail[n - 5] = Math.floor(bits / 0x100000000) & 0xff;
  tail[n - 4] = (bits >>> 24) & 0xff; tail[n - 3] = (bits >>> 16) & 0xff;
  tail[n - 2] = (bits >>> 8) & 0xff; tail[n - 1] = bits & 0xff;
  for (let off = 0; off < n; off += 64) compress(st, tail, off);
  return st;
}

function wordsToBytes(st) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) { out[i * 4] = st[i] >>> 24; out[i * 4 + 1] = (st[i] >>> 16) & 0xff; out[i * 4 + 2] = (st[i] >>> 8) & 0xff; out[i * 4 + 3] = st[i] & 0xff; }
  return out;
}

const ENC = new TextEncoder();

export function sha256Hex(input) {
  const bytes = typeof input === "string" ? ENC.encode(input) : input;
  return [...wordsToBytes(finish(IV, bytes, 0))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// key: Uint8Array (any length; hashed first if > 64 bytes, per RFC 2104).
export function makeKeyedHash(key) {
  let k = key instanceof Uint8Array ? key : ENC.encode(String(key));
  if (k.length > 64) k = wordsToBytes(finish(IV, k, 0));
  const ipad = new Uint8Array(64), opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) { const b = k[i] || 0; ipad[i] = b ^ 0x36; opad[i] = b ^ 0x5c; }
  const inner = Int32Array.from(IV); compress(inner, ipad, 0);
  const outer = Int32Array.from(IV); compress(outer, opad, 0);
  const mac = (msg) => finish(outer, wordsToBytes(finish(inner, typeof msg === "string" ? ENC.encode(msg) : msg, 64)), 64);
  // 40-bit Number: top 32 bits of word 0 * 256 + top byte of word 1.
  const h40 = (msg) => { const s = mac(msg); return (s[0] >>> 0) * 256 + (s[1] >>> 24); };
  h40.hex = (msg) => [...wordsToBytes(mac(msg))].map((b) => b.toString(16).padStart(2, "0")).join("");
  return h40;
}
