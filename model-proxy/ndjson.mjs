// Newline-delimited JSON (application/x-ndjson, Ollama's streaming format), split without re-encoding: each
// line keeps the exact bytes the upstream sent, its "\n" included, so a forwarded line is byte-identical.
// The same interface as sse.mjs createSplitter: events { raw, data }, where data is the line without its
// line ending ("\r\n" or "\n").
//
// BOUNDED. One pending line is held at a time, capped at `maxEvent` bytes, its "\n" included; past it the
// splitter stops and reports `overflow` (the caller decides: refuse in enforce mode, stop observing in report
// mode). A line that arrives whole inside one chunk is held to the same cap. LINEAR. Only each new chunk is
// searched for "\n", and the pending part is appended to a buffer that grows by doubling, so a line
// delivered a byte at a time costs O(length), not O(length²) (concat-and-rescan took 25 s of CPU for a
// 1 MiB line in 1-byte chunks, measured).
const NL = 0x0a;
const ev = (raw) => {
  let s = raw.toString("utf8");
  if (s.endsWith("\n")) s = s.slice(0, -1);
  if (s.endsWith("\r")) s = s.slice(0, -1);
  return { raw, data: s };
};

export function createLineSplitter(maxEvent) {
  // The pending partial line, copied into one buffer that grows by doubling up to maxEvent: memory is at
  // most maxEvent bytes whatever the chunk sizes (a list of 1-byte chunks would cost ~100 bytes each).
  let buf = null, len = 0, overflow = false;
  const stop = () => { overflow = true; buf = null; len = 0; };
  const append = (b) => {
    if (!buf || len + b.length > buf.length) {
      const nb = Buffer.allocUnsafe(Math.min(maxEvent, Math.max(4096, 2 * (len + b.length))));
      if (len) buf.copy(nb, 0, 0, len);
      buf = nb;
    }
    b.copy(buf, len);
    len += b.length;
  };
  const take = (tail) => {
    const raw = len ? Buffer.concat([buf.subarray(0, len), tail]) : tail;
    len = 0;
    if (buf && buf.length > 65536) buf = null;
    return raw;
  };
  function push(chunk) {
    if (overflow) return [];
    const out = [];
    let from = 0, i;
    while ((i = chunk.indexOf(NL, from)) !== -1) {
      if (len + i + 1 - from > maxEvent) { stop(); return out; }
      out.push(ev(take(chunk.subarray(from, i + 1))));
      from = i + 1;
    }
    if (from < chunk.length) {
      if (len + chunk.length - from > maxEvent) { stop(); return out; }
      append(chunk.subarray(from));
    }
    return out;
  }
  // A stream that ends without a final newline still delivers its last line.
  function end() {
    if (overflow || !len) return [];
    return [ev(take(Buffer.alloc(0)))];
  }
  return { push, end, get overflow() { return overflow; } };
}
