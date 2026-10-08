// Incremental Server-Sent Events framing that keeps each event's ORIGINAL text, so an event the gateway
// does not replace is forwarded exactly as the upstream wrote it.
//
// Per the SSE spec a line ends in CRLF, LF or CR, and a blank line ends an event; `data:` lines are
// joined with "\n"; a line starting with ":" is a comment. Bounded: an event whose text grows past
// `maxEventBytes` is declared unscannable — what was buffered is released as raw text and the rest of
// that event streams straight through until its blank line. Less scanning, never a stuck stream.
//
// With `onOverflow` (the gateway's response size cap, C5 RESPONSE_TOO_LARGE) an oversized event is
// DROPPED instead: nothing of it is released, the rest of it is discarded up to its blank line, and
// onOverflow({ id }) is called once. Without it, onUnscanned() (when given) is called once per event
// that overflows into raw text. Size is counted in UTF-8 bytes for complete lines; an unterminated
// line is checked by its length in characters (a lower bound), so memory stays within ~3x the cap.
import { StringDecoder } from "node:string_decoder";

export function createSseFramer({ maxEventBytes, onEvent, onRaw, onOverflow = null, onUnscanned = null }) {
  const decoder = new StringDecoder("utf8");
  let pending = "";      // undecided text: an incomplete line
  let evRaw = "";        // the current event's text so far
  let evData = [];       // its data lines
  let evId = null;       // its last `id:` value
  let evType = null;     // its `event:` value
  let evBytes = 0;       // its size so far in UTF-8 bytes
  let rawMode = false;   // the current event overflowed: stream it through
  let dropMode = false;  // the current event overflowed with onOverflow set: discard it
  let first = true;      // the stream's first line, whose one leading BOM a client's decoder drops
  const reset = () => { evRaw = ""; evData = []; evId = null; evType = null; evBytes = 0; };
  function overflow(extra) {
    if (onOverflow) { const id = evId; reset(); dropMode = true; onOverflow({ id }); }
    else { if (onUnscanned) onUnscanned(); onRaw(evRaw + extra); reset(); rawMode = true; }
  }

  // Fields are matched with the `s` flag: a line ends only at CR / LF (above), so a U+2028 / U+2029 inside a
  // data line is part of it, as it is to the client's parser.
  function line(text, term) {
    const whole = text + term;
    if (first) { first = false; if (text.charCodeAt(0) === 0xfeff) text = text.slice(1); }
    if (dropMode) { if (text === "") dropMode = false; return; }
    if (rawMode) {
      onRaw(whole);
      if (text === "") rawMode = false;
      return;
    }
    if (text === "") {
      evRaw += whole;
      const ev = { raw: evRaw, data: evData.length ? evData.join("\n") : null, id: evId, type: evType, bytes: evBytes + term.length };
      reset();
      onEvent(ev);
      return;
    }
    evRaw += whole;
    evBytes += Buffer.byteLength(text) + term.length;
    if (text.startsWith("data")) {
      const m = /^data(?::\s?(.*))?$/s.exec(text);
      if (m) evData.push(m[1] || "");
    } else if (text.startsWith("id")) {
      const m = /^id(?::\s?(.*))?$/s.exec(text);
      if (m) evId = m[1] || "";
    } else if (text.startsWith("event")) {
      const m = /^event(?::\s?(.*))?$/s.exec(text);
      if (m) evType = m[1] || "";
    }
    if (evBytes > maxEventBytes) overflow("");
  }

  function drain(final) {
    let i = 0;
    while (i < pending.length) {
      const lf = pending.indexOf("\n", i);
      const cr = pending.indexOf("\r", i);
      let end, termLen;
      if (cr >= 0 && (lf < 0 || cr < lf)) {
        if (cr === pending.length - 1 && !final) break; // a CR at the end may be half of a CRLF
        end = cr; termLen = pending[cr + 1] === "\n" ? 2 : 1;
      } else if (lf >= 0) { end = lf; termLen = 1; }
      else break;
      line(pending.slice(i, end), pending.slice(end, end + termLen));
      i = end + termLen;
    }
    pending = pending.slice(i);
    if (!rawMode && !dropMode && evBytes + pending.length > maxEventBytes && pending.length) {
      // one enormous line with no terminator yet
      const p = pending; pending = "";
      overflow(p);
    } else if (rawMode && pending.length > 65536) {
      onRaw(pending); pending = "";
    } else if (dropMode && pending.length > 65536) {
      pending = "";
    }
  }

  return {
    push(buf) { pending += decoder.write(buf); drain(false); },
    end() {
      pending += decoder.end();
      drain(true);
      // A stream that ends mid-event: what is left is not a complete event; forward it as it was.
      const rest = dropMode ? "" : evRaw + pending;
      reset(); pending = "";
      if (rest) onRaw(rest);
    }
  };
}

// A replacement event: the original's id (so a resuming client's Last-Event-ID still lines up) and one
// data line. JSON.stringify never emits a raw newline, so one data line is always enough.
export function sseEvent(obj, id) {
  return `${id != null ? `id: ${id}\n` : ""}event: message\ndata: ${JSON.stringify(obj)}\n\n`;
}
