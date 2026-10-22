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
//   { error }                   a handshake record that is not a well-formed ClientHello (the caller refuses)
// Pure. Never throws.

export const MAX_HELLO_BYTES = 65536 + 5 * 8;
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

export function sniffClientHello(buf) {
  try {
    if (!buf || !buf.length) return { need: true };
    if (buf[0] !== 0x16) return { tls: false };
    const frags = [];
    let off = 0, total = 0;
    while (true) {
      if (buf.length < off + 5) return buf.length > MAX_HELLO_BYTES ? { error: "ClientHello too large" } : { need: true };
      if (buf[off] !== 0x16) return { error: "a non-handshake record before the ClientHello ended" };
      if (buf[off + 1] !== 3) return { error: "not a TLS record version" };
      const len = buf.readUInt16BE(off + 3);
      if (len === 0 || len > 16384) return { error: "bad record length" };
      if (buf.length < off + 5 + len) return buf.length > MAX_HELLO_BYTES ? { error: "ClientHello too large" } : { need: true };
      frags.push(buf.subarray(off + 5, off + 5 + len));
      total += len;
      off += 5 + len;
      const hs = Buffer.concat(frags, total);
      if (hs.length >= 1 && hs[0] !== 1) return { error: "the first handshake message is not a ClientHello" };
      if (hs.length >= 4) {
        const hl = hs.readUIntBE(1, 3);
        if (hl > 65536) return { error: "ClientHello too large" };
        if (hs.length >= 4 + hl) return parseHello(hs.subarray(4, 4 + hl));
      }
      if (off > MAX_HELLO_BYTES) return { error: "ClientHello too large" };
    }
  } catch {
    return { error: "unparsed ClientHello" };
  }
}
