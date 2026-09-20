// LLM Response Rendering (ATLAS v2026.09, revised) — exfiltration through the things a client renders
// on its own. A markdown image or an unfurled link preview is fetched by the CLIENT, with no tool call
// and no approval prompt, so a URL whose query carries the conversation is a working egress channel that
// looks like a picture.
//
// #17 out-links already fires on any URL in an output, which is why it is gated at the ingest surface —
// it cannot tell a tracking pixel from a CI badge, and a signal that fires on both is not a signal. This
// asks the narrower question: is the URL being RENDERED, and does its query carry DATA rather than
// parameters?
//
// "Carries data" is decided on shape, never on a dictionary of hosts:
//   * an opaque blob — base64/base64url alphabet, long, and MIXED CASE. The mixed-case requirement is
//     what excludes cache-busting digests and UUIDs, which are single-case hex and are the dominant
//     benign long value in real image URLs;
//   * an identity — an address in a query value, percent-encoded or not;
//   * an unexpanded substitution — `$(...)`, `${...}`, `{{...}}` — a payload still in template form.
// Content-free: the caller gets a boolean, never the query value.

const MAX = 200_000;

// The rendered-URL surfaces: a markdown image, an HTML <img>, and a bare markdown link, which is what a
// client unfurls into a preview card.
const RENDERED = [
  /!\[[^\]]{0,120}\]\(\s*(https?:\/\/[^\s)]{1,2000})/gi,
  /<img\b[^>]{0,300}?\bsrc\s*=\s*["'](https?:\/\/[^"']{1,2000})["']/gi,
  /\[[^\]]{0,120}\]\(\s*(https?:\/\/[^\s)]{1,2000})/gi
];

const OPAQUE = /^[A-Za-z0-9+/_-]{24,}={0,2}$/;
const SUBSTITUTION = /\$\(|\$\{|\{\{|%7B%7B/i;
const ADDRESS = /[A-Za-z0-9._%+-]{1,64}(?:@|%40)[A-Za-z0-9.-]{1,64}\.[A-Za-z]{2,12}/;

function dataBearing(value) {
  if (SUBSTITUTION.test(value)) return true;
  if (ADDRESS.test(value)) return true;
  if (!OPAQUE.test(value)) return false;
  // Mixed case is the discriminator against digests and ids; a real base64 payload of text or JSON has
  // both, a hex cache-buster or a lowercase uuid has neither.
  return /[a-z]/.test(value) && /[A-Z]/.test(value);
}

function scanRenderedExfilHit(text) {
  if (typeof text !== "string" || text.length > MAX) return false;
  for (const re of RENDERED) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      let u;
      try { u = new URL(m[1].replace(/[.,;]+$/, "")); } catch { continue; }
      for (const [, value] of u.searchParams) {
        if (dataBearing(value)) return true;
      }
      if (SUBSTITUTION.test(u.pathname) || SUBSTITUTION.test(u.hash)) return true;
    }
  }
  return false;
}

// Memoised on the last text, for the reason data/obfuscation-signal.js gives: _matchDetector re-invokes
// refine() once per prefilter occurrence, and the prefilter here is deliberately cheap and broad.
let lastText = null, lastHit = false;
export function renderedExfilHit(text) {
  if (text === lastText) return lastHit;
  lastText = text;
  lastHit = scanRenderedExfilHit(text);
  return lastHit;
}
