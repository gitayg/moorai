// SafeTensors header validation. The format holds no code: an 8-byte little-endian header length N,
// N bytes of JSON ({ name: { dtype, shape, data_offsets: [begin, end] }, "__metadata__"?: {str: str} }),
// then the raw tensor bytes (github.com/huggingface/safetensors, README "Format"). A file whose header
// is valid is clean by design; everything checked here is a reason a loader might misread it:
//   malformed           medium  N past the file or past 100 MB (the reference loader's
//                               MAX_HEADER_SIZE), header not a JSON object, a tensor entry without
//                               a known dtype, a non-integer shape, offsets out of order or out of
//                               bounds, a byte size that does not match dtype × shape, or two tensors
//                               whose byte ranges overlap
//   offset-gap          low     bytes between tensors that no tensor indexes (the spec says the buffer
//                               "cannot contain holes")
//   metadata-not-string low     a __metadata__ value that is not a string
import { Cursor, ScanMalformed, ScanTruncated, safeDetail } from "./model-scan-bytes.mjs";

export const SAFETENSORS_MAX_HEADER = 100_000_000;
// Bits per element. Sub-byte types (F4, F6_*) are packed.
const DTYPE_BITS = {
  BOOL: 8, U8: 8, I8: 8, F8_E5M2: 8, F8_E4M3: 8, F8_E8M0: 8, I16: 16, U16: 16, F16: 16, BF16: 16,
  I32: 32, U32: 32, F32: 32, C64: 64, F64: 64, I64: 64, U64: 64, F4: 4, F6_E2M3: 6, F6_E3M2: 6
};

// A header length that fits the file and the cap, followed by "{".
export function looksLikeSafetensors(head, size) {
  if (!head || head.length < 9) return false;
  const n = Number(head.readBigUInt64LE(0));
  return n > 1 && n <= SAFETENSORS_MAX_HEADER && n + 8 <= size && head[8] === 0x7b;
}

export function scanSafetensors(src) {
  const findings = [];
  const add = (cls, severity, detail) => {
    const f = findings.find((x) => x.class === cls);
    if (f) { f.count++; if (detail && f.details.length < 20) f.details.push(safeDetail(detail)); }
    else findings.push({ class: cls, severity, count: 1, details: detail ? [safeDetail(detail)] : [] });
  };
  let tensors = 0;
  try {
    const c = new Cursor(src);
    const n = c.u64();
    if (n > SAFETENSORS_MAX_HEADER) throw new ScanMalformed("header length over 100 MB");
    if (n + 8 > src.size) throw new ScanMalformed("header length past the end of the file");
    let header;
    try { header = JSON.parse(c.bytes(n).toString("utf8")); } catch { throw new ScanMalformed("header is not JSON"); }
    if (!header || typeof header !== "object" || Array.isArray(header)) throw new ScanMalformed("header is not a JSON object");
    const bufLen = src.size - 8 - n;
    const ranges = [];
    for (const [name, t] of Object.entries(header)) {
      if (name === "__metadata__") {
        if (!t || typeof t !== "object" || Array.isArray(t)) { add("malformed", "medium", "__metadata__ is not an object"); continue; }
        for (const v of Object.values(t)) if (typeof v !== "string") { add("metadata-not-string", "low", "non-string metadata value"); break; }
        continue;
      }
      tensors++;
      if (!t || typeof t !== "object") { add("malformed", "medium", "tensor entry is not an object"); continue; }
      const bits = DTYPE_BITS[t.dtype];
      if (!bits) { add("malformed", "medium", `unknown dtype ${String(t.dtype).slice(0, 20)}`); continue; }
      if (!Array.isArray(t.shape) || !t.shape.every((d) => Number.isSafeInteger(d) && d >= 0)) { add("malformed", "medium", "shape is not a list of non-negative integers"); continue; }
      const off = t.data_offsets;
      if (!Array.isArray(off) || off.length !== 2 || !off.every((d) => Number.isSafeInteger(d) && d >= 0)) { add("malformed", "medium", "data_offsets is not two non-negative integers"); continue; }
      const [b, e] = off;
      if (b > e) { add("malformed", "medium", "data_offsets out of order"); continue; }
      if (e > bufLen) { add("malformed", "medium", "data_offsets past the end of the file"); continue; }
      let numel = 1n;
      for (const d of t.shape) numel *= BigInt(d);
      const want = (numel * BigInt(bits) + 7n) / 8n;
      if (want !== BigInt(e - b)) { add("malformed", "medium", "byte size does not match dtype and shape"); continue; }
      ranges.push([b, e]);
    }
    ranges.sort((x, y) => x[0] - y[0] || x[1] - y[1]);
    let at = 0;
    for (const [b, e] of ranges) {
      if (b < at) add("malformed", "medium", "tensor byte ranges overlap");
      else if (b > at) add("offset-gap", "low", "unindexed bytes between tensors");
      at = Math.max(at, e);
    }
  } catch (e) {
    if (e instanceof ScanTruncated) add("malformed", "medium", "truncated header");
    else if (e instanceof ScanMalformed) add("malformed", "medium", e.message);
    else throw e;
  }
  return { findings, tensors };
}
