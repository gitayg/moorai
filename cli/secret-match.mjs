// #65 — find any tracked secret form in an outbound text, holding the forms only as keyed hashes.
//
// A tracked form is { len, fp, h }: its byte length, a 24-bit keyed fingerprint of its first K bytes, and
// a 96-bit HMAC-SHA-256 of the whole form. The scan slides one K-byte window over each view of the text
// once, with a polynomial rolling hash (secret odd base, mod 2^32) finished by a keyed 32-bit mixer; a
// window whose fingerprint is in the bitmap is confirmed by the HMAC of the `len` bytes starting there.
// One pass per view whatever the number of secrets or distinct lengths: O(bytes) plus one HMAC per
// fingerprint hit (true matches, plus about bytes * forms / 2^24 chance hits).
//
// WHY A KEYED PREFILTER: the forms of a session-read secret persist on disk between hook processes, and
// only as these three numbers. The HMAC is the match; the fingerprint is a 24-bit digest of K bytes under
// a key-derived base and mask, so a state file read without the key yields neither the value nor a
// cheap test of a guess.
//
// WORST CASE: the raw text is scanned up to MAX_RAW bytes and each decoded view up to MAX_SCAN bytes, and at
// most MAX_CONFIRM HMACs run per check. A truncated view (`truncated`) and an exhausted HMAC budget
// (`exhausted`) are both reported, and cli/secret-egress.mjs turns either into an unverified match (fail
// closed).
import { createHmac, randomBytes } from "node:crypto";
import { percentView, unwrapView, toBytes } from "./secret-forms.mjs";

export const K = 8;
export const MAX_SCAN = 4 << 20;
export const MAX_RAW = 16 << 20;
export const MAX_CONFIRM = 20000;
export const FP_BITS = 24;
const H_HEX = 24;

// A keyring from 32 key bytes: the HMAC key and the rolling-hash base and mask derived from it.
export function keyring(key) {
  const k = Buffer.isBuffer(key) && key.length >= 16 ? key : randomBytes(32);
  const d = (label) => createHmac("sha256", k).update(label).digest();
  const roll = d("moorai/secret-match/roll");
  return { hk: d("moorai/secret-match/hmac"), base: (roll.readUInt32BE(0) | 1) >>> 0, mask: roll.readUInt32BE(4) >>> 0 };
}

const fmix = (x) => {
  x ^= x >>> 16; x = Math.imul(x, 0x85ebca6b); x ^= x >>> 13; x = Math.imul(x, 0xc2b2ae35); x ^= x >>> 16;
  return x >>> 0;
};
function powK1(base) { let p = 1; for (let i = 0; i < K - 1; i++) p = Math.imul(p, base); return p >>> 0; }
const finish = (h, kr) => fmix((h ^ kr.mask) >>> 0) >>> (32 - FP_BITS);

export function fingerprintOf(kr, form) {
  let h = 0;
  for (let i = 0; i < K; i++) h = (Math.imul(h, kr.base) + form.charCodeAt(i)) >>> 0;
  return finish(h, kr);
}
export const hmacOf = (kr, bytes) => createHmac("sha256", kr.hk).update(Buffer.from(bytes, "latin1")).digest("hex").slice(0, H_HEX);

// One tracked form from its byte string.
export function trackForm(kr, form) {
  return form.length >= K ? { len: form.length, fp: fingerprintOf(kr, form), h: hmacOf(kr, form) } : null;
}

// The index over tracked entries: [{ len, fp, h, sid, enc }]. `sid` names the secret (any string), `enc` the form.
// The bitmap is sized to the entries (2^16 to 2^24 bits, ~1/32 full at most): fingerprints keep all 24
// bits and the bitmap reads their top `b` bits, so a large retained set does not raise the chance-hit rate.
export function buildIndex(kr, entries) {
  const b = Math.max(16, Math.min(FP_BITS, Math.ceil(Math.log2(Math.max(1, entries.length) * 32))));
  const bshift = FP_BITS - b;
  const bits = new Uint32Array(1 << (b - 5));
  const byFp = new Map();
  for (const e of entries) {
    if (!e || !(e.len >= K) || typeof e.h !== "string") continue;
    const fp = e.fp >>> 0, bi = fp >>> bshift;
    bits[bi >>> 5] |= 1 << (bi & 31);
    const l = byFp.get(fp);
    if (l) l.push(e); else byFp.set(fp, [e]);
  }
  return { kr, bits, bshift, byFp, size: entries.length, pk1: powK1(kr.base) };
}

// Scan one byte string; true when it was truncated. `found`: Map sid -> { enc, view }; `budget`: { left }
// shared across views.
function scanView(ix, s, view, found, budget, cap) {
  const n = Math.min(s.length, cap);
  if (n < K) return n < s.length;
  const { kr, bits, bshift, byFp, pk1 } = ix;
  let h = 0;
  for (let i = 0; i < K; i++) h = (Math.imul(h, kr.base) + s.charCodeAt(i)) >>> 0;
  for (let i = 0; ; i++) {
    const fp = finish(h, kr), bi = fp >>> bshift;
    if (bits[bi >>> 5] & (1 << (bi & 31))) {
      for (const e of byFp.get(fp) || []) {
        if (i + e.len > n) continue;
        if (found.has(e.sid)) continue;
        if (--budget.left < 0) return n < s.length;
        if (hmacOf(kr, s.slice(i, i + e.len)) === e.h) found.set(e.sid, { enc: e.enc, view });
      }
    }
    if (i + K >= n) break;
    h = (Math.imul((h - Math.imul(s.charCodeAt(i), pk1)) | 0, kr.base) + s.charCodeAt(i + K)) >>> 0;
  }
  return n < s.length;
}

// Every tracked secret present in `text`: { hits: [{ sid, enc, view }], truncated, exhausted }. `enc` is
// the form that matched; a raw-form match inside the percent-decoded view reports "url". `truncated`: the
// raw text was longer than MAX_RAW, or a decoded view longer than MAX_SCAN, and its tail was not scanned. `exhausted`: the HMAC budget ran out before
// the scan finished — the caller fails closed on it.
export function scanText(ix, text) {
  const out = { hits: [], truncated: false, exhausted: false };
  if (!ix || !ix.size || !text) return out;
  const raw = toBytes(text);
  const found = new Map();
  const budget = { left: MAX_CONFIRM };
  const views = [["raw", raw]];
  const pv = percentView(raw); if (pv) views.push(["url", pv]);
  const uv = unwrapView(raw); if (uv) views.push(["unwrapped", uv]);
  for (const [name, s] of views) {
    if (scanView(ix, s, name, found, budget, name === "raw" ? MAX_RAW : MAX_SCAN)) out.truncated = true;
    if (budget.left < 0) { out.exhausted = true; break; }
  }
  for (const [sid, m] of found) out.hits.push({ sid, enc: m.view === "url" && m.enc === "raw" ? "url" : m.enc, view: m.view });
  return out;
}
