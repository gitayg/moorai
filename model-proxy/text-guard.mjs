// Response text scanning applied to a body or a stream (response-scan.mjs decides, text-codecs.mjs finds the
// text). Stream: each forwarded event (SSE event or NDJSON line, exactly as the tool-call state machine
// releases it) goes through event(raw) → the buffers to write in its place:
//   report   the event itself, unchanged; its text is fed to the scanner.
//   mask /   an event whose text changed (held back, or masked) is re-serialized with the new text — `event:`
//   block    line kept, JSON with the same keys in the same order, one `data:` line (SSE) or one line
//            (NDJSON), every number written as its source text (json-lossless.mjs: an integer past 2^53 in a
//            function call's arguments in the same event is not rounded; string escapes and whitespace may
//            differ from the provider's bytes, the values do not); an event with no text, or whose text did
//            not change, goes out byte-identical. A channel that ends at an event with no text of its own gets
//            one flush event first, carrying its held text. Every event that carries token log-probabilities
//            (codec.logprobs: `logprobs`, `top_logprobs`, Gemini `logprobsResult`) has them removed and is
//            re-serialized: they repeat the reply text token by token, held or masked text included.
// end() → the flush events of the channels the stream never ended (written before the stream closes).
// An event that is not JSON is passed on as it is (the tool-call machine has already judged it).
// Past the scanner's MAX_CHANNELS text channels, mask / block throw before any of the event is taken
// (response-scan.mjs admit): the caller reports it unevaluated and, under a closed fail mode, stops the stream.
import { parseEvent } from "./sse.mjs";
import { parseLossless } from "./json-lossless.mjs";

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const parse = parseLossless;
const MAX_TEMPLATE = 16384;

export function frameEvent(ev, d, lines) {
  return Buffer.from(lines ? `${JSON.stringify(d)}\n` : `${ev.event ? `event: ${ev.event}\n` : ""}data: ${JSON.stringify(d)}\n\n`);
}
const lineEvent = (raw) => { let s = raw.toString("utf8"); if (s.endsWith("\n")) s = s.slice(0, -1); if (s.endsWith("\r")) s = s.slice(0, -1); return { raw, event: null, data: s }; };

export function createTextGuard({ codec, scanner, lines = false, hold = false }) {
  const open = new Set();
  const templates = new Map();
  const tmplOf = (ch) => (templates.has(ch) ? parse(templates.get(ch)) : null);
  const flush = (ch, text) => (text ? [codec.flush(ch, text, tmplOf(ch))] : []);

  function event(raw) {
    const ev = lines ? lineEvent(raw) : { raw, ...parseEvent(raw) };
    const d = parse(ev.data);
    const obj = isObj(d) ? d : null;
    const out = [];
    const pieces = obj ? codec.pieces(obj) : [];
    if (hold) scanner.admit(pieces.map((p) => p.ch));
    const ending = new Set(codec.ends(obj, ev, [...open]));
    for (const ch of ending) {
      if (!open.has(ch) || pieces.some((p) => p.ch === ch)) continue;
      open.delete(ch);
      const t = scanner.push(ch, "", true);
      if (hold) out.push(...flush(ch, t));
    }
    let changed = false;
    if (obj) {
      // The channel's latest text event (its data as received, at most MAX_TEMPLATE characters): the metadata a
      // flush event copies.
      if (hold) for (const p of pieces) if (ev.data.length <= MAX_TEMPLATE) templates.set(p.ch, ev.data);
      pieces.forEach((p, i) => {
        const fin = ending.has(p.ch) && !pieces.slice(i + 1).some((q) => q.ch === p.ch);
        const t = scanner.push(p.ch, p.text, fin);
        if (fin) open.delete(p.ch); else open.add(p.ch);
        if (hold && t !== p.text) { p.set(t); changed = true; }
      });
      for (const w of codec.wholes(obj)) {
        const t = scanner.whole(w.text);
        if (hold && t !== w.text) { w.set(t); changed = true; }
      }
      if (hold && codec.logprobs(obj)) changed = true;
    }
    out.push(changed ? frameEvent(ev, obj, lines) : raw);
    return out;
  }
  function end() {
    const out = [];
    for (const [ch, t] of scanner.finish()) if (hold) out.push(...flush(ch, t));
    open.clear();
    return out;
  }
  return { event, end };
}

// A non-streaming body: every text scanned whole; with hold (mask / block) a changed text is set back and the
// token log-probabilities are removed. Returns whether the body changed (parse it with json-lossless.mjs when
// it will be re-serialized).
export function guardBody(codec, scanner, body, hold) {
  let changed = false;
  for (const p of codec.body(body)) {
    const t = scanner.whole(p.text);
    if (hold && t !== p.text) { p.set(t); changed = true; }
  }
  if (hold && codec.logprobs(body)) changed = true;
  return changed;
}
