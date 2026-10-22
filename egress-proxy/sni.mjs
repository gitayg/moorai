// The server name a TLS client asks for (SNI), read from the first bytes a CONNECT tunnel carries, so the
// proxy judges the host the TLS session is for and not only the host the CONNECT line names. The proxy
// does not decrypt anything: the ClientHello is sent in the clear before any key exchange.
//
// Sources, quoted:
//   RFC 8446 5.1  "TLSPlaintext.type ... handshake(22)"; "length: The length (in bytes) of the following
//                 TLSPlaintext.fragment. The length MUST NOT exceed 2^14 bytes"; "Handshake messages MAY be
//                 coalesced into a single TLSPlaintext record or fragmented across several records".
//   RFC 8446 4    HandshakeType client_hello(1), a 24-bit length; 4.1.2 ClientHello: legacy_version,
//                 random[32], legacy_session_id<0..32>, cipher_suites<2..2^16-2>,
//                 legacy_compression_methods<1..2^8-1>, extensions<8..2^16-1>.
//   RFC 8446 4.2  "There MUST NOT be more than one extension of the same type in a given extension block."
//   RFC 6066 3    server_name(0): ServerNameList; NameType host_name(0); "The ServerNameList MUST NOT
//                 contain more than one name of the same name_type"; "Literal IPv4 and IPv6 addresses are
//                 not permitted in "HostName""; "The hostname is represented as a byte string using ASCII
//                 encoding without a trailing dot."
//
// sniffClientHello(buf) →
//   { need: true }              more bytes are needed to decide
//   { tls: false }              the first byte is not a TLS handshake record: not TLS, nothing to read
//   { tls: true, sni }          a complete ClientHello; sni is the lower-cased host_name, or null when the
//                               client sent no server_name extension
//   { error }                   a handshake record that is not a well-formed ClientHello, one spread over more
//                               than MAX_HELLO_RECORDS records, or more than MAX_HELLO_BYTES (the caller refuses)
// Pure. Never throws. createHelloSniffer() reads the same incrementally, one chunk at a time.

export const MAX_HELLO_BYTES = 65536 + 5 * 8;
export const MAX_HELLO_RECORDS = 16;
const HOST_RE = /^[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*$/;

function parseHello(b) {
  let o = 0;
  const need = (n) => o + n <= b.length;
  if (!need(2 + 32 + 1)) return { error: "short ClientHello" };
  o += 2 + 32;
  const sid = b[o]; o += 1;
  if (sid > 32 || !need(sid + 2)) return { error: "bad session id" };
  o += sid;
  const cs = b.readUInt16BE(o); o += 2;
  if (cs < 2 || cs % 2 || !need(cs + 1)) return { error: "bad cipher suites" };
  o += cs;
  const cm = b[o]; o += 1;
  if (cm < 1 || !need(cm)) return { error: "bad compression methods" };
  o += cm;
  if (o === b.length) return { tls: true, sni: null }; // no extensions block (pre-TLS 1.2 clients)
  if (!need(2)) return { error: "bad extensions" };
  const el = b.readUInt16BE(o); o += 2;
  if (o + el !== b.length) return { error: "extensions length does not match the ClientHello" };
  const seen = new Set();
  let sni = null;
  while (o < b.length) {
    if (!need(4)) return { error: "truncated extension" };
    const type = b.readUInt16BE(o), len = b.readUInt16BE(o + 2);
    o += 4;
    if (!need(len)) return { error: "truncated extension" };
    if (seen.has(type)) return { error: "repeated extension" };
    seen.add(type);
    if (type === 0) {
      const e = b.subarray(o, o + len);
      if (e.length < 2 || e.readUInt16BE(0) !== e.length - 2) return { error: "bad server_name list" };
      let p = 2;
      while (p < e.length) {
        if (p + 3 > e.length) return { error: "bad server_name entry" };
        const nt = e[p], nl = e.readUInt16BE(p + 1);
        p += 3;
        if (p + nl > e.length) return { error: "bad server_name entry" };
        if (nt === 0) {
          if (sni !== null) return { error: "more than one host_name" };
          const name = e.subarray(p, p + nl).toString("latin1").toLowerCase();
          if (!HOST_RE.test(name) || name.length > 253) return { error: "host_name is not a host name" };
          sni = name;
        }
        p += nl;
      }
    }
    o += len;
  }
  return { tls: true, sni };
}

// An incremental reader: push(chunk) → the same results as sniffClientHello, decided once (every later push
// returns the same object). Each byte is copied a bounded number of times however the client cuts its first
// flight: unread bytes wait as the chunks they arrived in, a record is taken off them once, and the
// handshake message is joined once, when it is complete. At most MAX_HELLO_RECORDS records may carry the
// ClientHello and at most MAX_HELLO_BYTES bytes may arrive before it completes.
export function createHelloSniffer() {
  const q = []; // unread chunks, q[head] first
  let head = 0, qlen = 0, total = 0, records = 0, hsLen = 0, hl = -1, done = null;
  const frags = [];
  const byteAt = (i) => { for (let k = head; k < q.length; k++) { if (i < q[k].length) return q[k][i]; i -= q[k].length; } return -1; };
  function take(n) {
    if (q[head].length >= n) {
      const b = q[head].subarray(0, n);
      q[head] = q[head].subarray(n);
      if (!q[head].length) head++;
      qlen -= n;
      return b;
    }
    const parts = [];
    let left = n;
    while (left > 0) {
      const c = q[head];
      if (c.length <= left) { parts.push(c); left -= c.length; head++; }
      else { parts.push(c.subarray(0, left)); q[head] = c.subarray(left); left = 0; }
    }
    qlen -= n;
    return Buffer.concat(parts, n);
  }
  const finish = (v) => { done = v; q.length = 0; frags.length = 0; return v; };
  function step() {
    while (qlen >= 5) {
      if (byteAt(0) !== 0x16) return finish({ error: "a non-handshake record before the ClientHello ended" });
      if (byteAt(1) !== 3) return finish({ error: "not a TLS record version" });
      const len = (byteAt(3) << 8) | byteAt(4);
      if (len === 0 || len > 16384) return finish({ error: "bad record length" });
      if (qlen < 5 + len) break;
      take(5);
      const frag = take(len);
      records++;
      if (hsLen === 0 && frag[0] !== 1) return finish({ error: "the first handshake message is not a ClientHello" });
      frags.push(frag);
      hsLen += len;
      if (hl < 0 && hsLen >= 4) {
        const h4 = frags.length === 1 ? frag : Buffer.concat(frags, hsLen);
        hl = h4.readUIntBE(1, 3);
        if (hl > 65536) return finish({ error: "ClientHello too large" });
      }
      if (hl >= 0 && hsLen >= 4 + hl) {
        const hs = frags.length === 1 ? frags[0] : Buffer.concat(frags, hsLen);
        return finish(parseHello(hs.subarray(4, 4 + hl)));
      }
      if (records >= MAX_HELLO_RECORDS) return finish({ error: `the ClientHello spans more than ${MAX_HELLO_RECORDS} records` });
    }
    if (head > 1024) { q.splice(0, head); head = 0; }
    return total > MAX_HELLO_BYTES ? finish({ error: "ClientHello too large" }) : NEED;
  }
  return {
    push(chunk) {
      if (done) return done;
      try {
        if (!chunk || !chunk.length) return NEED;
        if (total === 0 && chunk[0] !== 0x16) return finish({ tls: false });
        total += chunk.length;
        q.push(chunk);
        qlen += chunk.length;
        return step();
      } catch {
        return finish({ error: "unparsed ClientHello" });
      }
    }
  };
}
const NEED = Object.freeze({ need: true });

export function sniffClientHello(buf) {
  return createHelloSniffer().push(buf);
}
