// AML.T0067 — LLM Trusted Output Components Manipulation. The technique names the LINKS in a response
// among the components an adversary shapes "to make it appear trustworthy". On-device, the observable
// form is a link that DISPLAYS one destination and GOES to another: the text a reader trusts is a URL or
// a domain, and the href is somewhere else.
//
// #17 out-links fires on every URL and was rejected for T0067 for exactly that reason. This fires only
// when the displayed text is itself a URL or a domain and the href's registrable domain differs from it,
// AND one of the deception shapes holds:
//   * the displayed brand re-appears as a hyphen token of the real host (github-releases.example), or the
//     whole displayed domain is a subdomain prefix of it (accounts.google.com.session-check.example);
//   * the real host is a lookalike: digit homoglyphs (paypa1, micros0ft), <= 2 substitutions, or one
//     inserted/dropped letter in the middle of the brand;
//   * the real host is an IP literal or punycode (xn--);
//   * the displayed PATH (>= 12 characters, >= 2 segments) was copied onto the foreign host;
//   * the displayed text is a full URL with a scheme, and the href is not a redirector (click./link./
//     t. subdomains, or a registrable of <= 7 characters — the shortener shape).
// Plus two shapes that need no link text at all: a URL whose USERINFO is a domain
// (https://github.com@mirror.example/ goes to mirror.example), and zero-width or bidi-override characters
// inside a URL or a URL-shaped link text (https://evil.example/<RLO>moc.buhtig reads as …github.com).
//
// Not deceptive, and silent: the same registrable (www., subdomains), the same brand on another TLD
// (google.de → google.com), one brand a prefix of the other (reactjs.org → react.dev, github.com →
// githubusercontent.com), and a wrapper whose href still carries the displayed domain (web.archive.org,
// Outlook safelinks, a redirect ?url=). Link text that is a filename (setup.py, README.md) is not a
// domain: a schemeless display needs www. or a common TLD. RLM/LRM and the embedding/isolate controls
// that Hebrew and Arabic text legitimately use are not in the invisible set.
// Content-free: the caller gets a boolean.

const MAX = 200_000;
const MAX_LINKS = 600;

const MD_LINK = /(?<!!)\[([^\]\n]{1,200})\]\(\s{0,4}<?(https?:\/\/[^\s)>]{1,2000})/g;
const A_TAG = /<a\b[^>]{0,400}?\bhref\s{0,4}=\s{0,4}["'](https?:\/\/[^"'<>]{1,2000})["'][^>]{0,400}>([^<]{0,300}(?:<(?!\/a\b)[^>]{0,100}>[^<]{0,300}){0,4})<\/a\s{0,4}>/gi;
const USERINFO_URL = /\bhttps?:\/\/([^\s\/?#@"'<>]{1,200})@([^\s\/?#:"'<>]{1,253})/gi;
const INVISIBLE = /[\u200B-\u200D\u2060\uFEFF\u202D\u202E]/;
const URL_SHAPED = /:\/\/|\bwww\.|\.[a-z]{2,24}(?:[\/:?#]|$)/i;

const HOST = /^(?:[a-z0-9\u00A1-\uFFFF](?:[a-z0-9\u00A1-\uFFFF-]{0,61}[a-z0-9\u00A1-\uFFFF])?\.){1,8}(?:[a-z\u00A1-\uFFFF]{2,24}|xn--[a-z0-9-]{1,59})$/i;
const COMMON_TLD = /\.(?:com|org|net|io|dev|ai|app|gov|edu|info|co|me|cloud|tech|site|online|xyz|top|biz|us|uk|de|fr|jp|cn|ru|in|il|eu|ca|au|nl|br|es|it|ch|se|no|pl|kr|tw)$/i;
const SLD = new Set(["co", "com", "org", "net", "gov", "ac", "edu", "ne", "or", "go", "ltd", "plc", "sch", "nic", "mil"]);
const IP = /^(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]{2,45}\])$/i;
const REDIRECTOR_LABEL = /^(?:click|clicks|link|links|lnk|go|t|r|redirect|redir|track|tracking|trk|email|e|mail|url\d{0,6}|u\d{0,6}|em\d{0,6}|ct|l|out|away|safelinks)$/i;

function registrable(host) {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (IP.test(h)) return h;
  const labels = h.split(".");
  if (labels.length >= 3 && labels[labels.length - 1].length === 2 && SLD.has(labels[labels.length - 2])) return labels.slice(-3).join(".");
  return labels.slice(-2).join(".");
}
const brandOf = (reg) => reg.split(".")[0];

// The displayed text, when it is a URL or a domain: { host, path, scheme } or null.
function displayed(text) {
  const t = text.replace(/<[^>]{0,100}>/g, "").trim().replace(/^<|>$/g, "").replace(/[.,;:!?]+$/, "");
  if (!t || /\s/.test(t) || t.length > 300) return null;
  const m = t.match(/^(https?:\/\/)?([^\/?#:@]{1,253})(?::\d{1,5})?([\/?#].{0,280})?$/i);
  if (!m || !HOST.test(m[2])) return null;
  const host = m[2].toLowerCase();
  if (!m[1] && !/^www\./.test(host) && !COMMON_TLD.test(host)) return null;
  return { host, path: m[3] || "", scheme: !!m[1] };
}

function hamming(a, b) {
  if (a.length !== b.length) return Infinity;
  let d = 0;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) d++;
  return d;
}
// One inserted or dropped letter, not at either end (a pure prefix/suffix relation is a brand family).
function oneEditInside(a, b) {
  const [s, l] = a.length < b.length ? [a, b] : [b, a];
  if (l.length - s.length !== 1 || s.length < 5 || l.startsWith(s) || l.endsWith(s)) return false;
  for (let i = 0; i < l.length; i++) if (l.slice(0, i) + l.slice(i + 1) === s) return true;
  return false;
}
const unHomoglyph = (s) => s.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/rn/g, "m").replace(/vv/g, "w").replace(/-/g, "");

function deceptive(disp, href) {
  let u;
  try { u = new URL(href); } catch { return false; }
  if (INVISIBLE.test(href)) return true;
  const realHost = u.hostname.toLowerCase();
  const dReg = registrable(disp.host), rReg = registrable(realHost);
  if (dReg === rReg) return false;
  let decoded = href.toLowerCase();
  try { decoded = decodeURIComponent(decoded); } catch { /* keep raw */ }
  if (decoded.slice(decoded.indexOf("//") + 2 + realHost.length).includes(dReg)) return false;
  const dBrand = brandOf(dReg), rBrand = brandOf(rReg);
  if (IP.test(realHost) || /(?:^|\.)xn--/.test(realHost)) return true;
  if (realHost.includes(dReg + ".")) return true;
  if (dBrand === rBrand) return false;
  // The displayed brand as a label or hyphen token of the REAL host, outside its own registrable:
  // github-releases.cdn.example, github.evil.example, secure-paypal.example.
  const labels = realHost.slice(0, realHost.length - rReg.length).split(".").filter(Boolean).concat(rBrand);
  if (dBrand.length >= 4 && labels.some((l) => l.split("-").includes(dBrand))) return true;
  if (unHomoglyph(rBrand) === unHomoglyph(dBrand)) return true;
  if (dBrand.length >= 4 && rBrand.length >= 4 && (rBrand.startsWith(dBrand) || dBrand.startsWith(rBrand))) return false;
  if (Math.min(dBrand.length, rBrand.length) >= 5 && (hamming(dBrand, rBrand) <= 2 || oneEditInside(dBrand, rBrand))) return true;
  // A copied path is evidence only when it is long enough to be a specific page: /acme on a rebranded
  // domain (twitter.com -> x.com) is a coincidence, /3/library/pickle.html is not.
  if (disp.path.length >= 12 && disp.path.split("/").filter(Boolean).length >= 2 && (u.pathname + u.search).toLowerCase().startsWith(disp.path.toLowerCase())) return true;
  if (disp.scheme && !REDIRECTOR_LABEL.test(realHost.split(".")[0]) && rReg.length > 7) return true;
  return false;
}

function userinfoSpoof(text) {
  USERINFO_URL.lastIndex = 0;
  let m, n = 0;
  while ((m = USERINFO_URL.exec(text)) !== null && n++ < MAX_LINKS) {
    const user = m[1].split(":")[0].toLowerCase();
    if (!HOST.test(user) || !/\.[a-z]{2,24}$/i.test(user)) continue;
    if (registrable(user) !== registrable(m[2])) return true;
  }
  return false;
}

function scanDeceptiveLink(text) {
  if (typeof text !== "string" || text.length > MAX) return false;
  if (userinfoSpoof(text)) return true;
  let n = 0;
  for (const [re, textIdx, hrefIdx] of [[MD_LINK, 1, 2], [A_TAG, 2, 1]]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null && n++ < MAX_LINKS) {
      const shown = m[textIdx];
      if (INVISIBLE.test(shown) && URL_SHAPED.test(shown)) return true;
      const disp = displayed(shown);
      if (disp && deceptive(disp, m[hrefIdx])) return true;
    }
  }
  return false;
}

// Memoised on the last text, for the reason data/obfuscation-signal.js gives: _matchDetector re-invokes
// refine() once per prefilter occurrence, and the prefilter here is deliberately cheap and broad.
let lastText = null, lastHit = false;
export function deceptiveLinkHit(text) {
  if (text === lastText) return lastHit;
  lastText = text;
  lastHit = scanDeceptiveLink(text);
  return lastHit;
}
