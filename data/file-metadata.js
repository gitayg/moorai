// AML.T0129 — Triggers in Multimodal Inputs: the file-metadata half. Instructions in an image's EXIF or
// XMP, an audio file's ID3 comment, or a document's title and subject are parsed by a model that reads
// the file while being absent from everything a person looks at.
//
// THE GAP THIS FILLS. cli/moorai-hook.mjs's readFileCapped() returns "" for any file containing a NUL
// byte — every JPEG, PNG, PDF and MP3 — so a binary file the agent reads was not scanned at all. The
// metadata is the part of such a file that can carry a sentence, and it is small, so it is the part
// worth recovering.
//
// Text only, and bounded. Nothing here decodes pixels, audio samples or compressed streams: the fields
// below are the ones stored as plain strings in a container's header, which is the whole of what the
// technique's "file metadata" example covers. Anything zlib-compressed (PNG zTXt, a compressed XMP
// stream) is skipped rather than inflated — inflating attacker-controlled bytes is a decompression-bomb
// surface this does not need.
import { exifTextFields } from "./exif.js";

const MAX_FIELD = 4096;
const MAX_TOTAL = 16_384;
const MAX_FIELDS = 64;

const printable = (s) => s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, " ").replace(/[ \t]{2,}/g, " ").trim();

function latin1(buf, start, end) {
  let s = "";
  const stop = Math.min(end, buf.length, start + MAX_FIELD);
  for (let i = start; i < stop; i++) s += String.fromCharCode(buf[i]);
  return s;
}

// Byte-level helpers rather than Buffer methods: this module is imported by the Node hook today, and a
// browser caller holding a Uint8Array from a dropped file must be able to use it unchanged.
function find(buf, needle, from = 0) {
  const n = [];
  for (let i = 0; i < needle.length; i++) n.push(needle.charCodeAt(i) & 0xff);
  outer: for (let i = from; i + n.length <= buf.length; i++) {
    for (let j = 0; j < n.length; j++) if (buf[i + j] !== n[j]) continue outer;
    return i;
  }
  return -1;
}

const u32be = (buf, p) => (p + 4 <= buf.length ? buf[p] * 0x1000000 + ((buf[p + 1] << 16) | (buf[p + 2] << 8) | buf[p + 3]) : -1);

// XMP travels as an XML packet inside JPEG, PNG, PDF, TIFF and MP4 alike, so one scan covers them all.
// The packet is taken as text and its tags stripped; which schema a directive was planted under does not
// change what it says.
function xmpText(buf, out) {
  let at = find(buf, "<x:xmpmeta");
  if (at < 0) at = find(buf, "<?xpacket");
  if (at < 0) return;
  const end = find(buf, "</x:xmpmeta>", at);
  const raw = latin1(buf, at, end > 0 ? end + 12 : at + MAX_FIELD);
  for (const m of raw.matchAll(/>([^<>]{16,})</g)) {
    const v = printable(m[1]);
    if (v && !/^[\s\d.:+-]*$/.test(v)) out.push(v);
    if (out.length >= MAX_FIELDS) return;
  }
}

// PNG tEXt / iTXt: keyword\0[compression flag, language, translated keyword\0]text. zTXt is compressed
// and is skipped.
function pngText(buf, out) {
  let p = 8;
  while (p + 8 <= buf.length && out.length < MAX_FIELDS) {
    const len = u32be(buf, p);
    const type = latin1(buf, p + 4, p + 8);
    if (len < 0 || len > buf.length) return;
    if (type === "tEXt" || type === "iTXt") {
      const seg = latin1(buf, p + 8, p + 8 + Math.min(len, MAX_FIELD));
      const parts = seg.split("\u0000");
      const v = printable(parts[parts.length - 1]);
      if (v) out.push(v);
    }
    if (type === "IDAT" || type === "IEND") return; // metadata that follows the pixels is not worth the walk
    p += 12 + len;
  }
}

// ID3v2 text frames — the audio case the technique names. Frame ids are 4 ASCII chars from v2.3 on; the
// COMM (comment) and TXXX (user-defined) frames are where prose actually goes.
function id3Text(buf, out) {
  if (latin1(buf, 0, 3) !== "ID3") return;
  const size = ((buf[6] & 0x7f) << 21) | ((buf[7] & 0x7f) << 14) | ((buf[8] & 0x7f) << 7) | (buf[9] & 0x7f);
  let p = 10;
  const end = Math.min(10 + size, buf.length);
  while (p + 10 <= end && out.length < MAX_FIELDS) {
    const id = latin1(buf, p, p + 4);
    if (!/^[A-Z][A-Z0-9]{3}$/.test(id)) return;
    const len = u32be(buf, p + 4);
    if (len <= 0 || p + 10 + len > end) return;
    if (id === "COMM" || id === "TXXX" || id[0] === "T" || id === "USLT") {
      // Layout: an encoding byte, a 3-byte language code on COMM/USLT, then a NUL-terminated short
      // description before the text. Taking the LAST NUL-separated part drops all of that scaffolding
      // in one step, which is why the language code is not skipped explicitly.
      const parts = latin1(buf, p + 11, p + 10 + Math.min(len, MAX_FIELD)).split("\u0000");
      const v = printable(parts[parts.length - 1]);
      if (v) out.push(v);
    }
    p += 10 + len;
  }
}

// PDF document information: the literal strings of the Info dictionary. A PDF whose Info dictionary sits
// in an object stream is compressed and is not read here.
function pdfInfo(buf, out) {
  const head = latin1(buf, 0, Math.min(buf.length, 262_144));
  for (const m of head.matchAll(/\/(Title|Subject|Keywords|Author|Producer|Creator)\s*\(((?:[^()\\]|\\.){0,2000})\)/g)) {
    const v = printable(m[2].replace(/\\([()\\])/g, "$1"));
    if (v) out.push(v);
    if (out.length >= MAX_FIELDS) return;
  }
}

function exifFromJpeg(buf, out) {
  // Walk the JPEG segment chain to the APP1 that starts with "Exif\0\0" rather than searching for the
  // string, so a JPEG whose pixel data happens to contain those bytes is not mis-parsed.
  let p = 2;
  while (p + 4 <= buf.length && buf[p] === 0xff) {
    const marker = buf[p + 1];
    if (marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd9)) { p += 2; continue; }
    if (marker === 0xda) return; // start of scan: the compressed image follows
    const len = (buf[p + 2] << 8) | buf[p + 3];
    if (len < 2) return;
    if (marker === 0xe1 && latin1(buf, p + 4, p + 10) === "Exif\u0000\u0000") {
      out.push(...exifTextFields(buf.subarray(p + 10, p + 2 + len)));
      return;
    }
    p += 2 + len;
  }
}

// Returns the file's metadata text as one block, or "" when the file carries none. The caller scans it
// with the ordinary detectors: the point of the technique is the CHANNEL, not a new payload grammar.
export function fileMetadataText(buf) {
  if (!buf || buf.length < 12) return "";
  const out = [];
  const b0 = buf[0], b1 = buf[1];
  if (b0 === 0xff && b1 === 0xd8) exifFromJpeg(buf, out);
  else if (b0 === 0x89 && b1 === 0x50) pngText(buf, out);
  else if (b0 === 0x49 || b0 === 0x4d) out.push(...exifTextFields(buf));
  if (latin1(buf, 0, 5) === "%PDF-") pdfInfo(buf, out);
  id3Text(buf, out);
  xmpText(buf, out);

  const seen = new Set();
  let total = 0;
  const kept = [];
  for (const v of out) {
    if (v.length < 8 || seen.has(v)) continue;
    seen.add(v);
    kept.push(v);
    total += v.length + 1;
    if (total >= MAX_TOTAL || kept.length >= MAX_FIELDS) break;
  }
  return kept.join("\n");
}
