// Extraction from a temp FILE rather than a Buffer, so nothing larger than one entry is ever resident.
//
//   tar / tar.gz   the file is streamed (and gunzipped) into the streaming tar parser (archive-stream).
//   zip / wheel    a zip needs random access (the central directory is at the END), so entries are read
//                  by offset with pread — the archive is never loaded whole.
//
// Guards are archive.mjs's: names are refused before any write (makeWriter), links and devices are
// skipped, files are created `wx` 0644, and the entry / per-file / total-byte caps apply unchanged.

import { openSync, closeSync, readSync, fstatSync, createReadStream } from "node:fs";
import { inflateRawSync, createGunzip } from "node:zlib";
import { makeWriter, LIMITS } from "./archive.mjs";
import { extractTarStream } from "./archive-stream.mjs";

const MAX_CENTRAL_DIR_BYTES = 64 * 1024 * 1024;
const EOCD_SCAN = 65557;                 // 22-byte EOCD + the largest possible zip comment

function readAt(fd, pos, len) {
  if (len <= 0) return Buffer.alloc(0);
  const b = Buffer.alloc(len);
  let got = 0;
  while (got < len) {
    const n = readSync(fd, b, got, len - got, pos + got);
    if (n <= 0) break;
    got += n;
  }
  return got === len ? b : b.subarray(0, got);
}

export function extractZipFile(path, dest, limits = LIMITS) {
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    const tailLen = Math.min(size, EOCD_SCAN);
    const tail = readAt(fd, size - tailLen, tailLen);
    let eocd = -1;
    for (let i = tail.length - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error("zip: no end-of-central-directory");
    const count = tail.readUInt16LE(eocd + 10);
    const cdSize = tail.readUInt32LE(eocd + 12);
    const cdOff = tail.readUInt32LE(eocd + 16);
    if (count === 0xffff || cdOff === 0xffffffff || cdSize === 0xffffffff) throw new Error("zip64 not supported");
    if (cdSize > MAX_CENTRAL_DIR_BYTES) throw new Error("zip: central directory too large");
    const cd = readAt(fd, cdOff, cdSize);

    const w = makeWriter(dest, limits);
    let p = 0;
    for (let n = 0; n < count; n++) {
      if (p + 46 > cd.length || cd.readUInt32LE(p) !== 0x02014b50) throw new Error("zip: bad central directory");
      const method = cd.readUInt16LE(p + 10);
      const compSize = cd.readUInt32LE(p + 20);
      const uncSize = cd.readUInt32LE(p + 24);
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      const extAttr = cd.readUInt32LE(p + 38);
      const local = cd.readUInt32LE(p + 42);
      const name = cd.subarray(p + 46, p + 46 + nameLen).toString("utf8");
      p += 46 + nameLen + extraLen + commentLen;

      if (!w.tick()) break;
      const fileType = (extAttr >>> 16) & 0o170000;
      if (fileType === 0o120000) { w.skip(); continue; }
      if (name.endsWith("/")) { w.dir(name); continue; }
      // A hostile entry could claim a small uncompressed size next to an enormous compressed one, so
      // both are capped before a single byte is read.
      if (uncSize > limits.maxFileBytes || compSize > limits.maxFileBytes) { w.skip(); continue; }
      const lh = readAt(fd, local, 30);
      if (lh.length < 30 || lh.readUInt32LE(0) !== 0x04034b50) throw new Error("zip: bad local header");
      const start = local + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
      if (start + compSize > size) { w.skip(); continue; }
      const raw = readAt(fd, start, compSize);
      let data;
      if (method === 0) data = raw;
      else if (method === 8) {
        try { data = inflateRawSync(raw, { maxOutputLength: Math.max(uncSize, 1) }); } catch { w.skip(); continue; }
      } else { w.skip(); continue; }
      if (data.length !== uncSize) { w.skip(); continue; }
      w.file(name, data);
      if (w.stats.truncated) break;
    }
    return w.stats;
  } finally {
    closeSync(fd);
  }
}

// Detect by magic bytes, not by the (attacker-chosen) filename.
// → {format, commit?, matched?, ...writer stats}
export async function extractArchiveFile(path, dest, { stripTop = false, subpath = "", skip = null, limits = LIMITS } = {}) {
  const fd = openSync(path, "r");
  let magic;
  try { magic = readAt(fd, 0, 4); } finally { closeSync(fd); }

  if (magic.length >= 4 && magic.readUInt32LE(0) === 0x04034b50) {
    return { format: "zip", commit: null, ...extractZipFile(path, dest, limits) };
  }
  const rs = createReadStream(path);
  const gz = magic.length >= 2 && magic[0] === 0x1f && magic[1] === 0x8b;
  const src = gz ? rs.pipe(createGunzip()) : rs;
  try {
    return await extractTarStream(src, dest, { stripTop, subpath, skip, limits });
  } finally {
    rs.destroy();
  }
}
