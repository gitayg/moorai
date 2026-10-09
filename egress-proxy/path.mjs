// The request path of a plain-HTTP request, canonicalised once: that string is what the egress rules judge
// AND what is sent upstream, so the proxy and the server cannot read two different paths.
//
//   * Percent-escapes of unreserved characters (A-Z a-z 0-9 - . _ ~) are decoded: `/%61dmin` is `/admin`.
//   * Every other escape is kept, with upper-case hex: `%3b` is `%3B`.
//   * Refused (400): an encoded separator (`%2F`, `%5C`), an encoded NUL (`%00`), any `%25` (an encoded
//     percent sign, which is how double encoding starts: `%252F`), a malformed escape (`%zz`, `%4`), a raw
//     backslash, and a dot segment carrying a parameter (`..;/`, `.;/`, which Tomcat-style servers resolve
//     as `..` and `.`).
//   * Characters a URL path may not carry raw are escaped the way the WHATWG URL parser escapes them
//     (space, `"`, `<`, `>`, `` ` ``, `{`, `}`, controls, non-ASCII as UTF-8), so a rule path, which
//     cli/egress-rules.mjs normalises with that parser, compares like for like.
//   * Then, after decoding: empty segments collapse (`//admin` is `/admin`, as nginx's merge_slashes reads
//     it) and dot segments are resolved (RFC 3986 5.2.4; `..` stops at the root). A trailing slash stays.
//
// Path rules compare this string case-sensitively. A server that matches paths case-blind (IIS, a static
// server on a case-insensitive filesystem) reads `/Admin` as `/admin`; a block rule written `/admin*` does
// not match `/Admin`. Against such a server, allow-list instead (allow rules plus egressDefault block): a
// changed case misses the allow rule and falls to the block.
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;
const ESCAPE_ALWAYS = new Set([0x20, 0x22, 0x3c, 0x3e, 0x60, 0x7b, 0x7d, 0x7f]);
const REFUSED_BYTES = new Set([0x2f, 0x5c, 0x00, 0x25]);
const hex2 = (b) => `%${b.toString(16).toUpperCase().padStart(2, "0")}`;

// A raw request path (from `/` up to, not including, `?` or `#`) → its canonical form, or null when it is
// refused.
export function canonicalPath(raw) {
  const s = String(raw ?? "");
  if (!s.startsWith("/") || s.includes("\\")) return null;
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "%") {
      const h = s.slice(i + 1, i + 3);
      if (!/^[0-9A-Fa-f]{2}$/.test(h)) return null;
      const b = parseInt(h, 16);
      if (REFUSED_BYTES.has(b)) return null;
      const c = String.fromCharCode(b);
      out += b < 0x80 && UNRESERVED.test(c) ? c : hex2(b);
      i += 2;
      continue;
    }
    const code = ch.charCodeAt(0);
    if (code < 0x20 || ESCAPE_ALWAYS.has(code) || code > 0x7e) {
      const cp = s.codePointAt(i);
      if (cp > 0xffff) i++;
      for (const b of Buffer.from(String.fromCodePoint(cp), "utf8")) out += hex2(b);
      continue;
    }
    out += ch;
  }
  const segs = out.split("/").slice(1);
  const kept = [];
  let trailing = false;
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];
    const last = i === segs.length - 1;
    if (/^\.\.?;/.test(seg)) return null;
    if (seg === "" || seg === ".") { if (last) trailing = true; continue; }
    if (seg === "..") { kept.pop(); if (last) trailing = true; continue; }
    kept.push(seg);
  }
  return `/${kept.join("/")}${trailing && kept.length ? "/" : ""}`;
}

// The raw path of an absolute http:// request target → its canonical form, or null when refused. A
// backslash anywhere in the target is refused: WHATWG reads it as `/`, other parsers do not.
export function requestPath(rawUrl) {
  const s = String(rawUrl || "");
  if (!/^http:\/\//i.test(s) || s.includes("\\")) return null;
  const rest = s.slice(7);
  const end = rest.search(/[/?#]/);
  if (end === -1 || rest[end] !== "/") return "/";
  const p = rest.slice(end);
  const q = p.search(/[?#]/);
  return canonicalPath(q === -1 ? p : p.slice(0, q));
}
