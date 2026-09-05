// Bounded normalization / decode pre-pass for the detection engine (src/engine.js).
//
// WHY: red-team frameworks (HackAgent's CipherChat, FlipAttack, h4rm3l, …) hide a malicious
// instruction behind an ENCODING so a plain-text detector never sees it — base64/hex/rot13/caesar/
// leetspeak/unicode-escape, reversed characters or words, or layers of those composed together. This
// module produces a small, capped set of DECODED / NORMALIZED variants of the input so the engine can
// re-run its existing detectors over them. It decides nothing and enforces nothing; it only hands the
// engine more text to scan.
//
// SAFETY (the input is attacker-controlled):
//   * Browser-safe: NO node imports. Uses only atob / TextDecoder / standard JS, so the browser bundle
//     that imports engine.js keeps working. (Buffer would have broken it.)
//   * DoS-capped on every axis — input size, per-blob decode size, blob count, layered depth, and a
//     hard ceiling on the total number of variants produced (which bounds how many detector re-scans
//     the engine does). None of the transforms EXPAND their input (base64/hex shrink; rot13/leet/
//     reverse/caesar are same-length), so there is no decompression-bomb vector here.
//   * Pure + total: a transform that changes nothing returns null; malformed encodings are swallowed.
//     The caller treats a throw as "no variants" (fail-open), so normalization can never flip a
//     decision toward blocking or away from it — it can only reveal an attack the raw scan missed.

export const NORMALIZE_MAX_INPUT = 50_000; // don't normalize inputs larger than this (CPU bound; the
// oversized-input detector already covers the >60k unbounded-consumption case, and real prompts are
// far smaller — spending 8× transforms × N detectors over a 1 MB paste is the cost we refuse here).
export const NORMALIZE_MAX_DECODE = 20_000; // cap decoded bytes per blob (a single huge blob can't
// dominate the budget).
export const NORMALIZE_MAX_BLOBS = 16;      // cap encoded blobs decoded per transform pass.
export const NORMALIZE_MAX_DEPTH = 3;       // layered decode/normalize depth (h4rm3l composes 2–3
// transforms in practice; deeper is combinatorially expensive for no real-world gain).
export const NORMALIZE_MAX_VARIANTS = 64;   // hard ceiling on variants → bounds total detector work.
const CAESAR_MAX_LEN = 2_000;               // full 25-shift caesar sweep only on short inputs.

const PRINTABLE_RATIO = 0.85; // a decoded blob must be mostly printable to be treated as hidden text
// (an image / binary blob decodes to noise and is discarded — it is not an instruction and would only
// waste budget / risk noise).

const decoder = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8", { fatal: false }) : null;

function bytesFromBase64(blob) {
  if (typeof atob !== "function") return null;
  let bin;
  try { bin = atob(blob); } catch { return null; }
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i) & 0xff;
  return u;
}

function mostlyPrintable(u) {
  if (!u.length) return false;
  let ok = 0;
  for (const b of u) if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) ok++;
  return ok / u.length >= PRINTABLE_RATIO;
}

function bytesToText(u) {
  if (decoder) return decoder.decode(u);
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return s;
}

// Decoded natural-language text hidden inside an encoded blob is itself the obfuscation tell, even
// when the decoded words don't trip a specific detector. Kept tight so JSON/base64-of-config
// (few spaces, punctuation-heavy) and binary noise do NOT qualify.
export function looksLikeHiddenText(s) {
  if (typeof s !== "string" || !/\s/.test(s)) return false;
  const words = s.match(/[A-Za-z]{3,}/g);
  if (!words || words.length < 4) return false;
  const letterSpace = (s.match(/[A-Za-z\s]/g) || []).length;
  return letterSpace / s.length >= 0.7;
}

// Decode base64 runs in place, preserving surrounding instruction context.
function decodeBase64(text) {
  let changed = false, nl = false, blobs = 0;
  const out = text.replace(/[A-Za-z0-9+/]{16,}={0,2}/g, (blob) => {
    if (blobs >= NORMALIZE_MAX_BLOBS || blob.length % 4 === 1) return blob;
    const u = bytesFromBase64(blob);
    if (!u || !u.length || u.length > NORMALIZE_MAX_DECODE || !mostlyPrintable(u)) return blob;
    const s = bytesToText(u);
    if (s === blob) return blob;
    blobs++; changed = true;
    if (looksLikeHiddenText(s)) nl = true;
    return s;
  });
  return changed ? { kind: "base64", text: out, nl } : null;
}

// Decode long runs of raw hex bytes (69676e6f7265… = "ignore…") in place.
function decodeHex(text) {
  let changed = false, blobs = 0;
  const out = text.replace(/(?:[0-9a-fA-F]{2}){8,}/g, (blob) => {
    if (blobs >= NORMALIZE_MAX_BLOBS) return blob;
    const even = blob.length % 2 ? blob.slice(0, -1) : blob;
    const n = even.length / 2;
    if (n > NORMALIZE_MAX_DECODE) return blob;
    const u = new Uint8Array(n);
    for (let i = 0; i < n; i++) u[i] = parseInt(even.substr(i * 2, 2), 16);
    if (!mostlyPrintable(u)) return blob;
    blobs++; changed = true;
    return bytesToText(u);
  });
  return changed ? { kind: "hex", text: out, nl: looksLikeHiddenText(out) } : null;
}

// Decode \uXXXX, \xXX and HTML numeric entities (&#NN; / &#xNN;) in place.
function decodeUnicodeEscapes(text) {
  if (!/\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;/.test(text)) return null;
  let cp;
  const safe = (n) => (n >= 0 && n <= 0x10ffff ? String.fromCodePoint(n) : "");
  const out = text
    .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (_m, h) => ((cp = parseInt(h, 16)), safe(cp)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_m, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9a-fA-F]{2})/g, (_m, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_m, h) => ((cp = parseInt(h, 16)), safe(cp)))
    .replace(/&#(\d+);/g, (_m, d) => ((cp = parseInt(d, 10)), safe(cp)));
  return out !== text ? { kind: "unicode-escape", text: out } : null;
}

function caesar(text, shift) {
  const s = ((shift % 26) + 26) % 26;
  if (!s) return text;
  let out = "", changed = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 65 && c <= 90) { out += String.fromCharCode(((c - 65 + s) % 26) + 65); changed = true; }
    else if (c >= 97 && c <= 122) { out += String.fromCharCode(((c - 97 + s) % 26) + 97); changed = true; }
    else out += text[i];
  }
  return changed ? out : text;
}

const LEET = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "!": "i", "|": "l" };
function leet(text) {
  let out = "", changed = false;
  for (const ch of text) {
    const r = LEET[ch];
    if (r) { out += r; changed = true; } else out += ch;
  }
  return changed ? { kind: "leetspeak", text: out } : null;
}

function rot13(text) {
  const out = caesar(text, 13);
  return out !== text ? { kind: "rot13", text: out } : null;
}

// CONFUSABLE (homoglyph) FOLDING. h4rm3l's homoglyph transform swaps a handful of Cyrillic/Greek
// look-alikes into an otherwise ASCII sentence — "оvеrrіdе уоur sаfеtу rulеs" is Cyrillic о е і у а с р
// — and every ASCII-anchored detector then sees a string it has no pattern for and scores exactly 0.
// Folding is the same idea as the leetspeak table one block up, just for a different substitution
// alphabet: a single table lookup per character (no regex, so no backtracking surface), plus NFKC to
// collapse the fullwidth / mathematical-alphanumeric families the same way.
//
// The mapping is by APPEARANCE, not by transliteration (Cyrillic "р" folds to Latin "p", not "r"),
// because appearance is what the attack exploits. Folding legitimate Cyrillic or Greek prose yields
// gibberish — which is harmless: this only ADDS a variant for the engine to re-scan, it never replaces
// the raw scan, and no `nl` obfuscation signal is set, so ordinary non-ASCII text raises nothing.
const CONFUSABLES = {
  // Cyrillic lowercase
  "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h",
  "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x",
  "ё": "e", "є": "e", "ѕ": "s", "і": "i", "ї": "i", "ј": "j",
  "һ": "h", "ӏ": "l", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ґ": "r",
  // Cyrillic uppercase
  "А": "A", "В": "B", "Е": "E", "З": "3", "К": "K", "М": "M",
  "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y",
  "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J", "Ӏ": "I",
  // Greek lowercase
  "α": "a", "β": "b", "γ": "y", "ε": "e", "η": "n", "ι": "i",
  "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "σ": "o", "τ": "t",
  "υ": "u", "χ": "x", "μ": "u", "ς": "c",
  // Greek uppercase
  "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
  "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
  "Υ": "Y", "Χ": "X",
  // Latin-block and symbol look-alikes NFKC leaves alone
  "ı": "i", "ȷ": "j", "‐": "-", "‑": "-", "⁄": "/", "ǃ": "!",
  "\u00a0": " ", "\u2007": " ", "\u202f": " ", "\u200b": "", "\u200c": "", "\u200d": "", "\ufeff": ""
};

function foldConfusables(text) {
  if (!/[^\u0000-\u007f]/.test(text)) return null; // pure ASCII — nothing to fold (cheap gate)
  let s = text;
  try { s = s.normalize("NFKC"); } catch { /* fail-open: fold the raw string */ }
  let out = "";
  for (const ch of s) {
    const r = CONFUSABLES[ch];
    out += r === undefined ? ch : r;
  }
  return out !== text ? { kind: "confusable-fold", text: out } : null;
}

function reverseChars(text) {
  // No `nl` obfuscation signal here: reversing ANY prose yields letters+spaces, so "looks like natural
  // language" is not a tell for reversal (it is for an ENCODED blob). A reversed instruction is still
  // caught by the engine re-running its detectors over this variant.
  const out = [...text].reverse().join("");
  return out !== text ? { kind: "reverse-chars", text: out } : null;
}

function reverseWords(text) {
  const parts = text.split(/(\s+)/);
  const words = parts.filter((_p, i) => i % 2 === 0);
  if (words.length < 2) return null;
  const rev = words.reverse();
  let wi = 0;
  const out = parts.map((p, i) => (i % 2 === 0 ? rev[wi++] : p)).join("");
  return out !== text ? { kind: "reverse-words", text: out } : null;
}

function* transformsOf(node) {
  const { text, depth } = node;
  yield decodeBase64(text);
  yield decodeHex(text);
  yield decodeUnicodeEscapes(text);
  // Cheap (ASCII-gated) and first among the same-length transforms, so a homoglyph attack is folded
  // to Latin at depth 1 and the layered decoders below still have depth left to run over the result.
  yield foldConfusables(text);
  yield rot13(text);
  yield leet(text);
  yield reverseChars(text);
  yield reverseWords(text);
  if (depth === 0 && text.length <= CAESAR_MAX_LEN) {
    for (let sh = 1; sh <= 25; sh++) {
      if (sh === 13) continue; // rot13 already yielded above
      const out = caesar(text, sh);
      if (out !== text) yield { kind: "caesar-" + sh, text: out };
    }
  }
}

// Produce the bounded set of decoded/normalized variants of `text`. Never includes the raw input.
// Layered (h4rm3l) transforms are reached by BFS to NORMALIZE_MAX_DEPTH; the visited-set dedups so a
// no-op transform can't cycle, and NORMALIZE_MAX_VARIANTS caps total work regardless of depth.
export function normalizeVariants(text, opts = {}) {
  const maxInput = opts.maxInput ?? NORMALIZE_MAX_INPUT;
  if (typeof text !== "string" || !text.length || text.length > maxInput) return [];
  const maxDepth = opts.maxDepth ?? NORMALIZE_MAX_DEPTH;
  const maxVariants = opts.maxVariants ?? NORMALIZE_MAX_VARIANTS;

  const out = [];
  const seen = new Set([text]);
  let frontier = [{ text, depth: 0 }];

  while (frontier.length && out.length < maxVariants) {
    const next = [];
    for (const node of frontier) {
      if (node.depth >= maxDepth) continue;
      for (const child of transformsOf(node)) {
        if (out.length >= maxVariants) break;
        if (!child || !child.text || seen.has(child.text)) continue;
        seen.add(child.text);
        const rec = { kind: child.kind, text: child.text, depth: node.depth + 1, nl: !!child.nl };
        out.push(rec);
        next.push(rec);
      }
      if (out.length >= maxVariants) break;
    }
    frontier = next;
  }
  return out;
}
