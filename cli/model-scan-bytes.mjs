// Bounded random-access reads for the model-file scanner (cli/model-scan.mjs). A source is either a
// Buffer or an open file read in small windows, so a multi-gigabyte model is walked without being
// loaded. Every read past the end throws ScanTruncated, which the format readers turn into a
// "malformed" finding instead of a crash.
import { openSync, readSync, closeSync, fstatSync } from "node:fs";

export class ScanTruncated extends Error {
  constructor(what = "truncated") { super(what); this.name = "ScanTruncated"; }
}
export class ScanMalformed extends Error {
  constructor(what = "malformed") { super(what); this.name = "ScanMalformed"; }
}

const WINDOW = 64 * 1024;

export class BufferSource {
  constructor(buf) { this.buf = buf; this.size = buf.length; }
  read(pos, len) {
    if (pos < 0 || len < 0 || pos + len > this.size) throw new ScanTruncated();
    return this.buf.subarray(pos, pos + len);
  }
  close() {}
}

export class FileSource {
  constructor(path) {
    this.fd = openSync(path, "r");
    this.size = fstatSync(this.fd).size;
    this.wpos = -1;
    this.wbuf = null;
  }
  read(pos, len) {
    if (pos < 0 || len < 0 || pos + len > this.size) throw new ScanTruncated();
    if (this.wbuf && pos >= this.wpos && pos + len <= this.wpos + this.wbuf.length) return this.wbuf.subarray(pos - this.wpos, pos - this.wpos + len);
    if (len > WINDOW) {
      const b = Buffer.alloc(len);
      const n = readSync(this.fd, b, 0, len, pos);
      if (n < len) throw new ScanTruncated();
      return b;
    }
    const want = Math.min(WINDOW, this.size - pos);
    const b = Buffer.alloc(want);
    const n = readSync(this.fd, b, 0, want, pos);
    if (n < len) throw new ScanTruncated();
    this.wpos = pos;
    this.wbuf = b.subarray(0, n);
    return this.wbuf.subarray(0, len);
  }
  close() { try { closeSync(this.fd); } catch { /* already closed */ } }
}

// A read position over a source, bounded by `end`.
export class Cursor {
  constructor(src, pos = 0, end = src.size) { this.src = src; this.pos = pos; this.end = Math.min(end, src.size); }
  get left() { return this.end - this.pos; }
  need(n) { if (n < 0 || this.pos + n > this.end) throw new ScanTruncated(); }
  bytes(n) { this.need(n); const b = this.src.read(this.pos, n); this.pos += n; return b; }
  skip(n) { this.need(n); this.pos += n; }
  u8() { return this.bytes(1)[0]; }
  u16() { return this.bytes(2).readUInt16LE(0); }
  u32() { return this.bytes(4).readUInt32LE(0); }
  i32() { return this.bytes(4).readInt32LE(0); }
  // A 64-bit length or count. Values past Number.MAX_SAFE_INTEGER cannot be a real offset.
  u64() {
    const v = this.bytes(8).readBigUInt64LE(0);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new ScanMalformed("64-bit value out of range");
    return Number(v);
  }
  // Protobuf base-128 varint, at most 10 bytes. Values past 2^53 are returned as Infinity (a length
  // that large is caught by the caller's bounds check).
  varint() {
    let v = 0, mul = 1;
    for (let i = 0; i < 10; i++) {
      const b = this.u8();
      v += (b & 0x7f) * mul;
      if (!(b & 0x80)) return v > Number.MAX_SAFE_INTEGER ? Infinity : v;
      mul *= 128;
    }
    throw new ScanMalformed("varint too long");
  }
  // Up to the next "\n" (pickle text opcodes), at most `max` bytes.
  line(max = 4096) {
    const start = this.pos;
    for (let i = 0; i < max && this.pos < this.end; i++) {
      const b = this.src.read(this.pos, 1)[0];
      this.pos++;
      if (b === 0x0a) return this.src.read(start, this.pos - start - 1).toString("latin1");
    }
    if (this.pos >= this.end) throw new ScanTruncated();
    throw new ScanMalformed("line too long");
  }
}

// A short, printable description for local output only (CLI / doctor). Never sent off the device.
export function safeDetail(s, max = 120) {
  const t = String(s ?? "").replace(/[^\x20-\x7e]/g, "?");
  return t.length > max ? `${t.slice(0, max)}…` : t;
}
