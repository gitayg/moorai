// Server-sent events, split without re-encoding: each event keeps the exact bytes the provider sent, so a
// forwarded event is byte-identical to the upstream one. An event ends at a blank line (WHATWG SSE: "\n\n",
// "\r\n\r\n" or "\r\r"); the field parse follows the same spec (a leading space after the colon is dropped,
// several data lines join with "\n").
//
// BOUNDED. One pending event is held at a time, capped at `maxEvent` bytes; past it the splitter stops and
// reports `overflow` (the caller decides: refuse in enforce mode, stop observing in report mode).
const BOUNDARY = /\r\n\r\n|\n\n|\r\r/g;

export function parseEvent(raw) {
  let event = null;
  const data = [];
  for (const line of raw.toString("utf8").split(/\r\n|\n|\r/)) {
    if (!line || line.startsWith(":")) continue;
    const i = line.indexOf(":");
    const field = i < 0 ? line : line.slice(0, i);
    let value = i < 0 ? "" : line.slice(i + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "event") event = value;
    else if (field === "data") data.push(value);
  }
  return { event, data: data.join("\n") };
}

export function createSplitter(maxEvent) {
  let buf = Buffer.alloc(0), scanFrom = 0, overflow = false;
  function push(chunk) {
    if (overflow) return [];
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    const out = [];
    for (;;) {
      // latin1 maps byte n to char n, so string offsets are byte offsets.
      const s = buf.toString("latin1", scanFrom);
      BOUNDARY.lastIndex = 0;
      const m = BOUNDARY.exec(s);
      if (!m) {
        // A boundary can straddle chunks: rescan the last 3 bytes next time.
        scanFrom = Math.max(0, buf.length - 3);
        if (buf.length > maxEvent) { overflow = true; buf = Buffer.alloc(0); }
        return out;
      }
      const end = scanFrom + m.index + m[0].length;
      const raw = buf.subarray(0, end);
      out.push({ raw, ...parseEvent(raw) });
      buf = buf.subarray(end);
      scanFrom = 0;
    }
  }
  // A stream that ends without a final blank line still delivers its last event.
  function end() {
    if (overflow || !buf.length) return [];
    const raw = buf;
    buf = Buffer.alloc(0);
    return [{ raw, ...parseEvent(raw) }];
  }
  return { push, end, get overflow() { return overflow; } };
}
