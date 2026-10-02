// Incremental Server-Sent Events framing that keeps each event's ORIGINAL text, so an event the gateway
// does not replace is forwarded exactly as the upstream wrote it.
//
// Per the SSE spec a line ends in CRLF, LF or CR, and a blank line ends an event; `data:` lines are
// joined with "\n"; a line starting with ":" is a comment. Bounded: an event whose text grows past
// `maxEventBytes` is declared unscannable — what was buffered is released as raw text and the rest of
// that event streams straight through until its blank line. Less scanning, never a stuck stream.
import { StringDecoder } from "node:string_decoder";

export function createSseFramer({ maxEventBytes, onEvent, onRaw }) {
  const decoder = new StringDecoder("utf8");
  let pending = "";      // undecided text: an incomplete line
  let evRaw = "";        // the current event's text so far
  let evData = [];       // its data lines
  let evId = null;       // its last `id:` value
  let rawMode = false;   // the current event overflowed: stream it through

  function line(text, term) {
    const whole = text + term;
    if (rawMode) {
      onRaw(whole);
      if (text === "") rawMode = false;
      return;
    }
    if (text === "") {
      evRaw += whole;
      const ev = { raw: evRaw, data: evData.length ? evData.join("\n") : null, id: evId };
      evRaw = ""; evData = []; evId = null;
      onEvent(ev);
      return;
    }
    evRaw += whole;
    if (text.startsWith("data")) {
      const m = /^data(?::\s?(.*))?$/.exec(text);
      if (m) evData.push(m[1] || "");
    } else if (text.startsWith("id")) {
      const m = /^id(?::\s?(.*))?$/.exec(text);
      if (m) evId = m[1] || "";
    }
    if (evRaw.length > maxEventBytes) {
      onRaw(evRaw);
      evRaw = ""; evData = []; evId = null; rawMode = true;
    }
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
    if (!rawMode && evRaw.length + pending.length > maxEventBytes && pending.length) {
      // one enormous line with no terminator yet
      onRaw(evRaw + pending);
      evRaw = ""; evData = []; evId = null; pending = ""; rawMode = true;
    } else if (rawMode && pending.length > 65536) {
      onRaw(pending); pending = "";
    }
  }

  return {
    push(buf) { pending += decoder.write(buf); drain(false); },
    end() {
      pending += decoder.end();
      drain(true);
      // A stream that ends mid-event: what is left is not a complete event; forward it as it was.
      const rest = evRaw + pending;
      evRaw = ""; pending = ""; evData = [];
      if (rest) onRaw(rest);
    }
  };
}

// A replacement event: the original's id (so a resuming client's Last-Event-ID still lines up) and one
// data line. JSON.stringify never emits a raw newline, so one data line is always enough.
export function sseEvent(obj, id) {
  return `${id != null ? `id: ${id}\n` : ""}event: message\ndata: ${JSON.stringify(obj)}\n\n`;
}
