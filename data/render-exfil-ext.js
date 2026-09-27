// LLM Response Rendering (AML.T0077, ATLAS v2026.09) — the parts of the technique data/render-exfil.js
// does not read. That module asks one question of an inline markdown image, an <img src> and a bare
// markdown link: does a QUERY value carry an opaque mixed-case blob, an address or a template? The
// technique's own text names more than that:
//   * "parts of the URL ... including query parameters or URL PATH SEGMENTS";
//   * "images, EMBEDDED WEBPAGES, or link previews ... HTML, Markdown, or other rendering mechanisms" —
//     a reference-style markdown image (`![x][r]` + `[r]: https://…`), <iframe>/<embed>/<object>/
//     <video poster>/<source>, <img srcset>, and CSS url() are all fetched by the client with no click;
//   * "may be SPLIT ACROSS MULTIPLE REQUESTS" — one short value per image, many images;
//   * the example itself, `?secrets="private data"` — plain text under a parameter NAMED for what it
//     carries, which the opaque-blob test cannot see.
// And one encoding the mixed-case gate lets through: hex. A hex digest and a hex-encoded sentence are
// both single-case; what separates them is what they decode to.
//
// "Carries data" stays a SHAPE decision, never a host list:
//   * decodes to text — a base64/base64url/hex run that decodes to >= 12 bytes of mostly printable
//     ASCII with letters in it. Digests, asset ids and signed tokens decode to noise; a payload written
//     to be read back decodes to words or JSON. Two decoded shapes are named exceptions because they
//     are how image proxies address their source: a URL (imgproxy, thumbor) and the serverless image
//     handler's {"bucket","key"} request;
//   * an address or an unexpanded template in a path segment, as the query test already does;
//   * a secret-NAMED parameter with a value;
//   * a run of >= 8 rendered requests to one host+path whose one parameter takes >= 8 distinct values of
//     <= 3 characters, at least half of them not purely numeric (a counter like ?random=1..10 is not).
// Loopback and private-network hosts are skipped: rendering them sends nothing off the device.
// Content-free: the caller gets a boolean, never a URL or a value.

const MAX = 200_000;
const MAX_URLS = 400;

const MD_IMAGE = /!\[[^\]\n]{0,200}\]\(\s{0,4}<?(https?:\/\/[^\s)>]{1,2000})/gi;
const HTML_IMG = /<img\b[^>]{0,400}?\bsrc\s{0,4}=\s{0,4}["'](https?:\/\/[^"']{1,2000})["']/gi;
const REF_DEF = /^[ \t]{0,3}\[([^\]\n]{1,100})\]:[ \t]{0,8}<?(https?:\/\/[^\s>]{1,2000})/gim;
const IMG_REF = /!\[([^\]\n]{0,200})\](?:\[([^\]\n]{0,100})\])?/g;
const EMBED_TAG = /<(?:iframe|frame|embed|object|video|audio|source|track|img|input|link)\b[^>]{0,800}>/gi;
const EMBED_ATTR = /\b(src|data|poster|srcset|href)\s{0,4}=\s{0,4}["']([^"']{1,4000})["']/gi;
const LINK_FETCHED = /\brel\s{0,4}=\s{0,4}["'][^"']{0,60}\b(?:preload|prefetch|stylesheet|icon)\b/i;
const CSS_URL = /url\(\s{0,4}["']?(https?:\/\/[^"')\s]{1,2000})/gi;

const OPAQUE = /^[A-Za-z0-9+/_-]{24,}={0,2}$/;
const SUBSTITUTION = /\$\(|\$\{|\{\{|%7B%7B/i;
const ADDRESS = /[A-Za-z0-9._%+-]{1,64}(?:@|%40)[A-Za-z0-9.-]{1,64}\.[A-Za-z]{2,12}/;
const B64 = /^[A-Za-z0-9+/_-]{16,4000}={0,2}$/;
const HEX = /^(?:[0-9a-f]{2}){12,2000}$/i;
const SECRET_PARAM = /^(?:secrets?|password|passwd|pwd|pass|creds?|credentials?|private|leak|exfil|stolen|ssn|conversation|convo|history|chat|memory|system_?prompt|prompt)$/i;
const PRIVATE_HOST = /^(?:localhost|.*\.localhost|.*\.local|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|0\.0\.0\.0|\[::1\]|::1)$/i;

function decodeLoose(v) {
  try { return decodeURIComponent(v); } catch { return v; }
}

function printableText(bytes) {
  if (bytes.length < 12) return false;
  let printable = 0, letters = 0;
  for (const b of bytes) {
    if ((b >= 0x20 && b <= 0x7e) || b === 9 || b === 10 || b === 13) printable++;
    if ((b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a)) letters++;
  }
  return printable / bytes.length >= 0.9 && letters >= 4;
}

// Image proxies put their SOURCE in the path: a URL, or a {"bucket","key"} request. Those decode to
// text by design and are how the image is addressed, not what it carries out.
function proxySource(s) {
  return /^\s{0,4}(?:https?|s3|gs|local):\/\//i.test(s) || /^\s{0,4}\{[^]{0,200}"(?:bucket|key|edits)"\s{0,4}:/.test(s);
}

// `atob` rather than Buffer, for the reason data/normalize.js gives: engine.js is bundled for the browser.
function decodesToText(value) {
  let bytes = null;
  if (HEX.test(value)) {
    bytes = [];
    for (let i = 0; i < value.length; i += 2) bytes.push(parseInt(value.slice(i, i + 2), 16));
  } else if (B64.test(value) && value.replace(/=+$/, "").length >= 24 && typeof atob === "function") {
    try {
      const s = atob(value.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "").padEnd(Math.ceil(value.replace(/=+$/, "").length / 4) * 4, "="));
      bytes = Array.from(s, (c) => c.charCodeAt(0));
    } catch { return false; }
  }
  if (!bytes || !printableText(bytes)) return false;
  return !proxySource(String.fromCharCode(...bytes.slice(0, 240)));
}

function queryValueBearing(name, value) {
  if (SUBSTITUTION.test(value) || ADDRESS.test(value)) return true;
  if (SECRET_PARAM.test(name) && value.trim().length >= 6) return true;
  if (OPAQUE.test(value) && /[a-z]/.test(value) && /[A-Z]/.test(value)) return true;
  return decodesToText(value);
}

function pathBearing(pathname) {
  for (const raw of pathname.split("/")) {
    if (!raw) continue;
    const seg = decodeLoose(raw);
    if (SUBSTITUTION.test(seg) || ADDRESS.test(seg)) return true;
    // A file extension is presentation, not payload: `<blob>.png` is judged on the blob.
    if (decodesToText(seg.replace(/\.[A-Za-z0-9]{2,5}$/, ""))) return true;
  }
  return false;
}

function parse(raw) {
  let u;
  try { u = new URL(raw.replace(/[.,;]+$/, "")); } catch { return null; }
  if (PRIVATE_HOST.test(u.hostname)) return null;
  return u;
}

function collect(text) {
  const out = [];
  const push = (raw) => { if (out.length < MAX_URLS) { const u = parse(raw); if (u) out.push(u); } };
  for (const re of [MD_IMAGE, HTML_IMG, CSS_URL]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null && out.length < MAX_URLS) push(m[1]);
  }
  // Reference-style images: only a definition some image actually uses is rendered.
  const used = new Set();
  IMG_REF.lastIndex = 0;
  let m;
  while ((m = IMG_REF.exec(text)) !== null) {
    const label = (m[2] ? m[2] : m[1]).trim().toLowerCase().replace(/\s+/g, " ");
    if (label) used.add(label);
    if (used.size > MAX_URLS) break;
  }
  if (used.size) {
    REF_DEF.lastIndex = 0;
    while ((m = REF_DEF.exec(text)) !== null && out.length < MAX_URLS) {
      if (used.has(m[1].trim().toLowerCase().replace(/\s+/g, " "))) push(m[2]);
    }
  }
  EMBED_TAG.lastIndex = 0;
  while ((m = EMBED_TAG.exec(text)) !== null && out.length < MAX_URLS) {
    const tag = m[0];
    const isLink = /^<link\b/i.test(tag);
    if (isLink && !LINK_FETCHED.test(tag)) continue;
    EMBED_ATTR.lastIndex = 0;
    let a;
    while ((a = EMBED_ATTR.exec(tag)) !== null) {
      const attr = a[1].toLowerCase();
      if (attr === "href" && !isLink) continue;
      if (attr === "srcset") {
        for (const part of a[2].split(",")) { const url = part.trim().split(/\s/)[0]; if (/^https?:\/\//i.test(url)) push(url); }
      } else if (/^https?:\/\//i.test(a[2])) push(a[2]);
    }
  }
  return out;
}

function splitAcrossRequests(urls) {
  const groups = new Map();
  for (const u of urls) {
    const k = u.host + u.pathname;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(u);
  }
  for (const list of groups.values()) {
    if (list.length < 8) continue;
    const byParam = new Map();
    for (const u of list) for (const [name, value] of u.searchParams) {
      if (!byParam.has(name)) byParam.set(name, []);
      byParam.get(name).push(value);
    }
    for (const values of byParam.values()) {
      const distinct = new Set(values);
      if (distinct.size < 8 || values.some((v) => v.length > 3)) continue;
      const nonNumeric = [...distinct].filter((v) => !/^\d+$/.test(v)).length;
      if (nonNumeric * 2 >= distinct.size) return true;
    }
  }
  return false;
}

function scanRenderedExfilExt(text) {
  if (typeof text !== "string" || text.length > MAX) return false;
  const urls = collect(text);
  for (const u of urls) {
    for (const [name, value] of u.searchParams) if (queryValueBearing(name, value)) return true;
    if (pathBearing(u.pathname) || SUBSTITUTION.test(u.hash)) return true;
  }
  return splitAcrossRequests(urls);
}

// Memoised on the last text, for the reason data/obfuscation-signal.js gives: _matchDetector re-invokes
// refine() once per prefilter occurrence, and the prefilter here is deliberately cheap and broad.
let lastText = null, lastHit = false;
export function renderedExfilExtHit(text) {
  if (text === lastText) return lastHit;
  lastText = text;
  lastHit = scanRenderedExfilExt(text);
  return lastHit;
}
