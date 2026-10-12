// Newline-delimited JSON (application/x-ndjson, Ollama's streaming format), split without re-encoding: each
// line keeps the exact bytes the upstream sent, its "\n" included, so a forwarded line is byte-identical.
// The same interface as sse.mjs createSplitter: events { raw, data }, where data is the line without its
// line ending ("\r\n" or "\n").
//
// BOUNDED. One pending line is held at a time, capped at `maxEvent` bytes; past it the splitter stops and
// reports `overflow` (the caller decides: refuse in enforce mode, stop observing in report mode).
const NL = 0x0a;
const ev = (raw) => {
  let s = raw.toString("utf8");
  if (s.endsWith("\n")) s = s.slice(0, -1);
  if (s.endsWith("\r")) s = s.slice(0, -1);
  return { raw, data: s };
};

export function createLineSplitter(maxEvent) {
  let buf = Buffer.alloc(0), overflow = false;
  function push(chunk) {
    if (overflow) return [];
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    const out = [];
    let i;
    while ((i = buf.indexOf(NL)) !== -1) {
      out.push(ev(buf.subarray(0, i + 1)));
      buf = buf.subarray(i + 1);
    }
    if (buf.length > maxEvent) { overflow = true; buf = Buffer.alloc(0); }
    return out;
  }
  // A stream that ends without a final newline still delivers its last line.
  function end() {
    if (overflow || !buf.length) return [];
    const raw = buf;
    buf = Buffer.alloc(0);
    return [ev(raw)];
  }
  return { push, end, get overflow() { return overflow; } };
}
