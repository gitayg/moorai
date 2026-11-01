// #65 — the encoded forms of one secret value, and the decoded views of an outbound text. Everything
// here works on BYTE strings (latin1, one char per byte of the UTF-8 encoding), so a form computed from
// a value and a window cut from an outbound text compare byte for byte.
//
// FORMS (what a value can look like on the wire), each tagged with the `encoding` an alert reports:
//   raw       the value itself
//   json      the value inside a JSON string, when JSON escaping changes it (a quote or backslash)
//   reversed  the value byte-reversed
//   base64    standard base64 at each of the 3 byte alignments: the characters of base64(prefix + value
//             + suffix) that depend only on the value, for a prefix of 0, 1 or 2 bytes mod 3. A value
//             encoded alone, or anywhere inside a larger base64 blob, contains one of the three. Unpadded,
//             so a padded encoding (which carries the unpadded one as a prefix) matches too.
//   base64url the same over the URL-safe alphabet (only when it differs)
//   hex       lower- and upper-case hex
//   url       not a stored form: the percent-decoded view below reads any percent-encoding back to raw
//
// VIEWS (extra readings of the outbound text the forms are searched in):
//   percent-decoded  every %XX replaced by its byte, so any percent-encoding variant (lower/upper case
//                    escapes, every byte escaped, partial escaping) reads back as the raw value
//   unwrapped        CR, LF and the two-character JSON escapes \n and \r removed, so a base64 or hex
//                    payload wrapped at a line width (`base64` wraps at 76 by default) reads unbroken
// NOT COVERED: encryption, compression, custom alphabets, XOR, base32/base85, a value split across separate
// strings or arguments, hex with separators (41:42, \x41), and nested encodings (base64 of hex).

export const ENCODINGS = Object.freeze(["raw", "json", "reversed", "base64", "base64url", "hex", "url"]);

export const toBytes = (s) => Buffer.from(String(s), "utf8").toString("latin1");

// The characters of base64(pad(shift) + bytes + pad) that no neighbouring byte influences.
function base64Shifted(buf, shift, url) {
  const padded = Buffer.concat([Buffer.alloc(shift), buf, Buffer.alloc(3)]);
  const enc = padded.toString(url ? "base64url" : "base64");
  const j0 = Math.ceil((8 * shift) / 6);
  const j1 = Math.floor((8 * shift + 8 * buf.length) / 6);
  return enc.slice(j0, j1);
}

// [{ enc, form }] for one value, deduplicated by form. `reversed` is opt-out (opts.reversed === false).
export function formsOf(value, opts = {}) {
  const v = String(value);
  const buf = Buffer.from(v, "utf8");
  const raw = buf.toString("latin1");
  const out = [];
  const seen = new Set();
  const add = (enc, form) => { if (form && !seen.has(form)) { seen.add(form); out.push({ enc, form }); } };
  add("raw", raw);
  add("json", toBytes(JSON.stringify(v).slice(1, -1)));
  if (opts.reversed !== false) add("reversed", Buffer.from(buf).reverse().toString("latin1"));
  for (const s of [0, 1, 2]) add("base64", base64Shifted(buf, s, false));
  for (const s of [0, 1, 2]) add("base64url", base64Shifted(buf, s, true));
  const hex = buf.toString("hex");
  add("hex", hex);
  add("hex", hex.toUpperCase());
  return out;
}

const HEXV = (c) => (c >= 48 && c <= 57 ? c - 48 : c >= 65 && c <= 70 ? c - 55 : c >= 97 && c <= 102 ? c - 87 : -1);

// The percent-decoded view of a byte string, or null when it carries no %XX escape. Linear.
export function percentView(s) {
  if (s.indexOf("%") < 0) return null;
  let out = "", last = 0, any = false;
  for (let i = s.indexOf("%"); i >= 0 && i < s.length - 2; i = s.indexOf("%", i + 1)) {
    const a = HEXV(s.charCodeAt(i + 1)), b = HEXV(s.charCodeAt(i + 2));
    if (a < 0 || b < 0) continue;
    out += s.slice(last, i) + String.fromCharCode(a * 16 + b);
    last = i + 3;
    i += 2;
    any = true;
  }
  return any ? out + s.slice(last) : null;
}

// The unwrapped view, or null when there is nothing to unwrap. Linear.
export function unwrapView(s) {
  if (!/[\r\n]|\\[nr]/.test(s)) return null;
  return s.replace(/\r|\n|\\[nr]/g, "");
}
