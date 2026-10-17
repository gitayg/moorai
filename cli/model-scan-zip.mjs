// Minimal ZIP reader for the model scanner: the central directory (ZIP64 included, which PyTorch
// writes for large checkpoints) and one entry's bytes, stored or deflated, with an output cap. Enough
// for a PyTorch archive (<name>/data.pkl, stored) and a .keras archive (config.json, deflated).
// Nothing is extracted to disk. Layout: PKWARE APPNOTE.TXT sections 4.3.6-4.3.16 and 4.5.3.
import { inflateRawSync } from "node:zlib";
import { Cursor, ScanMalformed, ScanTruncated } from "./model-scan-bytes.mjs";

const EOCD = 0x06054b50, EOCD64 = 0x06064b50, EOCD64_LOC = 0x07064b50, CDH = 0x02014b50, LFH = 0x04034b50;
export const ZIP_LIMITS = Object.freeze({ maxEntries: 100_000, maxCommentScan: 65_557 });

export function looksLikeZip(head) {
  return !!head && head.length >= 4 && head.readUInt32LE(0) === LFH;
}

// → [{ name, method, csize, usize, localOffset }]. Throws ScanMalformed / ScanTruncated.
export function zipEntries(src, limits = ZIP_LIMITS) {
  const tailLen = Math.min(src.size, limits.maxCommentScan);
  const tail = src.read(src.size - tailLen, tailLen);
  let at = -1;
  for (let i = tail.length - 22; i >= 0; i--) if (tail.readUInt32LE(i) === EOCD) { at = i; break; }
  if (at < 0) throw new ScanMalformed("no end-of-central-directory record");
  const eocdPos = src.size - tailLen + at;
  const e = new Cursor(src, eocdPos + 4);
  e.skip(4); // disk numbers
  e.u16();
  let count = e.u16(), cdSize = e.u32(), cdOff = e.u32();
  if (count === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) {
    if (eocdPos < 20) throw new ScanMalformed("ZIP64 locator missing");
    const loc = new Cursor(src, eocdPos - 20);
    if (loc.u32() !== EOCD64_LOC) throw new ScanMalformed("ZIP64 locator missing");
    loc.u32();
    const e64Pos = loc.u64();
    const e64 = new Cursor(src, e64Pos);
    if (e64.u32() !== EOCD64) throw new ScanMalformed("ZIP64 end record missing");
    e64.skip(8 + 2 + 2 + 4 + 4 + 8);
    count = e64.u64(); cdSize = e64.u64(); cdOff = e64.u64();
  }
  if (count > limits.maxEntries) throw new ScanMalformed("too many zip entries");
  if (cdOff + cdSize > src.size) throw new ScanTruncated();
  const c = new Cursor(src, cdOff, cdOff + cdSize);
  const out = [];
  for (let i = 0; i < count; i++) {
    if (c.u32() !== CDH) throw new ScanMalformed("bad central directory header");
    c.skip(2 + 2 + 2);
    const method = c.u16();
    c.skip(2 + 2 + 4);
    let csize = c.u32(), usize = c.u32();
    const nlen = c.u16(), xlen = c.u16(), clen = c.u16();
    c.skip(2 + 2 + 4);
    let localOffset = c.u32();
    const name = c.bytes(nlen).toString("utf8");
    const xend = c.pos + xlen;
    while (c.pos + 4 <= xend) {
      const id = c.u16(), sz = c.u16();
      const next = c.pos + sz;
      if (id === 0x0001) {
        if (usize === 0xffffffff && c.pos + 8 <= next) usize = c.u64();
        if (csize === 0xffffffff && c.pos + 8 <= next) csize = c.u64();
        if (localOffset === 0xffffffff && c.pos + 8 <= next) localOffset = c.u64();
      }
      c.pos = next;
    }
    c.pos = xend;
    c.skip(clen);
    out.push({ name, method, csize, usize, localOffset });
  }
  return out;
}

// Where an entry's data starts (after its local header).
export function entryDataOffset(src, entry) {
  const l = new Cursor(src, entry.localOffset);
  if (l.u32() !== LFH) throw new ScanMalformed("bad local header");
  l.skip(22);
  const nlen = l.u16(), xlen = l.u16();
  const start = entry.localOffset + 30 + nlen + xlen;
  if (start + entry.csize > src.size) throw new ScanTruncated();
  return start;
}

// An entry's bytes as a Buffer, at most `max` uncompressed bytes. → Buffer | null (over the cap).
export function readEntry(src, entry, max) {
  if (entry.usize > max) return null;
  const start = entryDataOffset(src, entry);
  const raw = src.read(start, entry.csize);
  if (entry.method === 0) return Buffer.from(raw);
  if (entry.method === 8) {
    try { return inflateRawSync(raw, { maxOutputLength: Math.max(1, max) }); } catch { throw new ScanMalformed("deflate stream unreadable or over the cap"); }
  }
  throw new ScanMalformed(`unsupported compression method ${entry.method}`);
}
