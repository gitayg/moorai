// TIFF/Exif IFD walk, for the text-bearing tags only. AML.T0129 names EXIF as a carrier for planted
// instructions, and the fields that carry prose are a short list: ImageDescription, Artist, Copyright,
// XPComment/XPSubject/XPTitle (Windows, UTF-16LE) and UserComment (with its 8-byte character code).
//
// Deliberately narrow. This is not an Exif library: it reads the byte order, walks IFD0 and the Exif
// sub-IFD once each, and returns only the ASCII/UTF-16 values of those tags. Everything else — rationals,
// makernotes, thumbnails, nested IFDs — is skipped, because none of it can hold a sentence and parsing it
// would only add surface. Every offset is bounds-checked against the slice, so a truncated or hostile
// header yields fewer strings rather than a throw.

const TEXT_TAGS = new Set([
  0x010e, // ImageDescription
  0x013b, // Artist
  0x8298, // Copyright
  0x9c9b, // XPTitle
  0x9c9c, // XPComment
  0x9c9d, // XPAuthor
  0x9c9e, // XPKeywords
  0x9c9f, // XPSubject
  0x9286  // UserComment
]);
const EXIF_IFD_POINTER = 0x8769;
const MAX_ENTRIES = 256;
const MAX_VALUE = 4096;

function reader(buf, base, little) {
  return {
    u16: (o) => (o + 2 <= buf.length ? (little ? buf[base + o] | (buf[base + o + 1] << 8) : (buf[base + o] << 8) | buf[base + o + 1]) : -1),
    u32: (o) => {
      const p = base + o;
      if (p + 4 > buf.length) return -1;
      return little
        ? (buf[p] | (buf[p + 1] << 8) | (buf[p + 2] << 16)) + buf[p + 3] * 0x1000000
        : (buf[p + 3] | (buf[p + 2] << 8) | (buf[p + 1] << 16)) + buf[p] * 0x1000000;
    }
  };
}

function ascii(buf, start, len) {
  let s = "";
  for (let i = start; i < start + len && i < buf.length; i++) {
    const b = buf[i];
    if (b === 0) break;
    s += b >= 32 && b < 127 ? String.fromCharCode(b) : " ";
  }
  return s.trim();
}

// XP* tags are UTF-16LE byte arrays; UserComment is prefixed by an 8-byte character-code identifier.
function utf16le(buf, start, len) {
  let s = "";
  for (let i = start; i + 1 < start + len && i + 1 < buf.length; i += 2) {
    const c = buf[i] | (buf[i + 1] << 8);
    if (c === 0) break;
    s += c >= 32 && c < 0xfffe ? String.fromCharCode(c) : " ";
  }
  return s.trim();
}

function readIfd(buf, tiff, offset, little, out, depth) {
  if (offset <= 0 || tiff + offset + 2 > buf.length) return;
  const r = reader(buf, tiff, little);
  const count = r.u16(offset);
  if (count < 0 || count > MAX_ENTRIES) return;
  for (let i = 0; i < count; i++) {
    const e = offset + 2 + i * 12;
    if (tiff + e + 12 > buf.length) return;
    const tag = r.u16(e);
    const type = r.u16(e + 2);
    const n = r.u32(e + 4);
    if (tag === EXIF_IFD_POINTER && depth === 0) {
      readIfd(buf, tiff, r.u32(e + 8), little, out, depth + 1);
      continue;
    }
    if (!TEXT_TAGS.has(tag)) continue;
    // Types 1 (BYTE), 2 (ASCII) and 7 (UNDEFINED) are one byte per component; nothing else here is text.
    if (type !== 1 && type !== 2 && type !== 7) continue;
    if (n <= 0 || n > MAX_VALUE) continue;
    const at = n <= 4 ? tiff + e + 8 : tiff + r.u32(e + 8);
    if (at < 0 || at + Math.min(n, 4) > buf.length) continue;
    // UserComment's first 8 bytes name the character set (ASCII\0\0\0, UNICODE\0, JIS\0\0\0\0\0).
    const unicodeXp = tag >= 0x9c9b && tag <= 0x9c9f;
    const v = tag === 0x9286
      ? (ascii(buf, at, 8).startsWith("UNICODE") ? utf16le(buf, at + 8, n - 8) : ascii(buf, at + 8, n - 8))
      : unicodeXp ? utf16le(buf, at, n) : ascii(buf, at, n);
    if (v) out.push(v);
  }
}

// `buf` starts at the TIFF header ("II*\0" or "MM\0*"), which is what both a JPEG APP1 Exif segment and a
// bare .tif file contain after their own prefix.
export function exifTextFields(buf) {
  const out = [];
  if (!buf || buf.length < 8) return out;
  const little = buf[0] === 0x49 && buf[1] === 0x49;
  const big = buf[0] === 0x4d && buf[1] === 0x4d;
  if (!little && !big) return out;
  const r = reader(buf, 0, little);
  if (r.u16(2) !== 42) return out;
  readIfd(buf, 0, r.u32(4), little, out, 0);
  return out;
}
