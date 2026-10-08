// The response side of placeholder credentials: a bound secret that an upstream echoes back (in a header,
// the status line or the body) is replaced by '*' of the same length before the component reads the
// response, so no client-visible byte carries it and a Content-Length stays right.
//
// Only a verbatim echo is masked. A secret the upstream encodes (base64, JSON \u escapes, reversed) or
// echoes in part (an "sk-…abcd" hint) passes: the bound upstream is trusted with the secret by definition,
// and this is a guard against an accidental echo, not against an upstream that wants the agent to have it.
import { Transform, pipeline } from "node:stream";
import { createGunzip, createInflate, createBrotliDecompress } from "node:zlib";

const STAR = 0x2a;
const DECODERS = { gzip: createGunzip, "x-gzip": createGunzip, deflate: createInflate, br: createBrotliDecompress };

export function maskString(s, secrets) {
  let out = String(s);
  for (const x of secrets) if (out.includes(x)) out = out.split(x).join("*".repeat(x.length));
  return out;
}

// A Transform that masks every secret, also across chunk boundaries. At the end of a chunk it holds back only
// the longest tail that is a proper prefix of a secret, so an SSE event ending in "\n\n" is never delayed.
export function createMasker(secrets) {
  const bufs = secrets.map((s) => Buffer.from(s, "utf8")).sort((a, b) => b.length - a.length);
  let pending = null;
  const maskAll = (buf) => {
    let copy = null;
    for (const s of bufs) {
      let i = (copy || buf).indexOf(s);
      while (i >= 0) { copy ||= Buffer.from(buf); copy.fill(STAR, i, i + s.length); i = copy.indexOf(s, i + s.length); }
    }
    return copy || buf;
  };
  const holdOf = (buf) => {
    let hold = 0;
    for (const s of bufs) {
      const from = Math.max(0, buf.length - (s.length - 1));
      for (let i = buf.indexOf(s[0], from); i >= 0 && i < buf.length; i = buf.indexOf(s[0], i + 1)) {
        const k = buf.length - i;
        if (k <= hold) break;
        if (buf.subarray(i).equals(s.subarray(0, k))) { hold = k; break; }
      }
    }
    return hold;
  };
  return new Transform({
    transform(chunk, _enc, cb) {
      const buf = maskAll(pending ? Buffer.concat([pending, chunk]) : chunk);
      const hold = holdOf(buf);
      pending = hold ? Buffer.from(buf.subarray(buf.length - hold)) : null;
      const out = hold ? buf.subarray(0, buf.length - hold) : buf;
      cb(null, out.length ? out : undefined);
    },
    flush(cb) { const p = pending; pending = null; cb(null, p ? maskAll(p) : undefined); }
  });
}

// The upstream response as the component goes on to read it: same status, headers masked, body masked
// (decoded first when it is gzip / deflate / br, since a compressed echo cannot be found; Content-Encoding and
// Content-Length are then dropped). An unknown Content-Encoding → { refuse: true }: the body cannot be
// checked for an echo. pipeline() ties the two ends together: an upstream that fails mid-body destroys the
// masker with the error (a consumer reading it sees it; one piping it sees the stream stop), and a consumer
// that destroys the masker destroys the upstream response.
export function maskResponse(ur, secrets) {
  const enc = String(ur.headers["content-encoding"] || "identity").trim().toLowerCase();
  if (enc !== "identity" && !Object.hasOwn(DECODERS, enc)) { ur.resume(); return { refuse: true }; }
  const headers = {};
  for (const [k, v] of Object.entries(ur.headers)) headers[k] = Array.isArray(v) ? v.map((x) => maskString(x, secrets)) : maskString(v, secrets);
  const masker = createMasker(secrets);
  masker.on("error", () => {}); // an aborted upstream is not a crash: the IncomingMessage it replaces swallows it too
  if (enc === "identity") pipeline(ur, masker, () => {});
  else { delete headers["content-encoding"]; delete headers["content-length"]; pipeline(ur, DECODERS[enc](), masker, () => {}); }
  return Object.assign(masker, { statusCode: ur.statusCode, statusMessage: maskString(ur.statusMessage || "", secrets), headers });
}
