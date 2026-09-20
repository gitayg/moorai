// LLM Prompt Obfuscation, revised (ATLAS v2026.09) — the technique now names text a human cannot read
// because of how it RENDERS, not because of which code points it uses. MoorAI's existing #50 detectors
// (idx-invisible-text, obf-invisible-instructions, mcp-hidden-canary) all key on the code points:
// zero-width runs, bidi overrides, the Unicode tag block, ANSI escapes. White-on-white text is ordinary
// ASCII and trips none of them.
//
// This covers the markup channel, which is the one an on-device guard actually parses: an element whose
// own inline style makes its text invisible, carrying a steering instruction. Both halves are required.
// Hidden markup by itself is everywhere and benign — `display:none` template rows, screen-reader text,
// pre-animation `opacity:0`, `fill="none"` on an SVG path — so concealment alone raises nothing, the
// same rule data/obfuscation-signal.js already applies to the statistical tells.
//
// The image/audio/video half of the revised technique (low-contrast text INSIDE a raster image, faint or
// sped-up audio, a single video frame) is NOT covered here and cannot be: it needs per-region pixel or
// sample analysis, and the OCR host command returns recovered text with no bounding boxes.
// Content-free: the caller gets a boolean, never the concealed text.
import { steeringDirectiveHit } from "./steering-tells.js";

const MAX = 200_000;

// Elements carrying an inline style, with their text content. Bounded on both the attribute and the body
// so a pathological document cannot make this quadratic.
const STYLED_ELEMENT = /<([a-z][a-z0-9]{0,14})\b[^>]{0,400}?\sstyle\s*=\s*"([^"]{0,300})"[^>]{0,200}>([\s\S]{0,4000}?)<\/\1>/gi;

// An SVG <text> painted with no fill is invisible while still being read out of the document.
const SVG_INVISIBLE_TEXT = /<text\b[^>]{0,300}\bfill\s*=\s*"(?:none|transparent|#fff(?:fff)?|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)[^"]{0,40}"[^>]{0,200}>([\s\S]{0,4000}?)<\/text>/gi;

const HEX = /(?:#([0-9a-f]{3}|[0-9a-f]{6})\b|(rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}))/i;

function normColor(v) {
  const m = v.match(HEX);
  if (!m) return null;
  if (m[1]) return m[1].length === 3 ? m[1].split("").map((c) => c + c).join("").toLowerCase() : m[1].toLowerCase();
  const n = m[2].match(/\d{1,3}/g).slice(0, 3).map((x) => Number(x).toString(16).padStart(2, "0"));
  return n.join("");
}

// Does this inline style make its own text unreadable? Same-colour foreground/background is the
// "low contrast" case the revised technique names; the rest are the ordinary hiding declarations.
function hidesOwnText(style) {
  const s = style.toLowerCase();
  if (/\bdisplay\s*:\s*none\b/.test(s)) return true;
  if (/\bvisibility\s*:\s*hidden\b/.test(s)) return true;
  if (/\bopacity\s*:\s*0(?:\.0+)?\s*(?:;|$)/.test(s)) return true;
  if (/\bfont-size\s*:\s*0(?:\.0+)?(?:px|em|rem|pt|%)?\s*(?:;|$)/.test(s)) return true;
  if (/\b(?:left|top|right|bottom|text-indent|margin-left|margin-top)\s*:\s*-\d{4,}(?:px|em|rem|pt)\b/.test(s)) return true;
  const fg = s.match(/(?:^|;)\s*color\s*:\s*([^;]{1,40})/);
  const bg = s.match(/(?:^|;)\s*background(?:-color)?\s*:\s*([^;]{1,60})/);
  if (fg && bg) {
    const a = normColor(fg[1]), b = normColor(bg[1]);
    if (a && b && a === b) return true;
  }
  return false;
}

const stripTags = (s) => s.replace(/<[^>]{0,400}>/g, " ").replace(/&[a-z]{2,8};/gi, " ").replace(/\s+/g, " ").trim();

// Accessibility text is hidden ON PURPOSE and is written for a human using a screen reader, so it is a
// legitimate occupant of this channel and is not a finding.
const A11Y = /\b(?:sr-only|screen-?reader|visually-?hidden|a11y|skip\s+to\s+(?:main|content))\b/i;

const MIN_TEXT = 24;

function concealedSteering(body) {
  const t = stripTags(body);
  return t.length >= MIN_TEXT && !A11Y.test(t) && steeringDirectiveHit(t);
}

function scanVisuallyHiddenInstruction(text) {
  if (typeof text !== "string" || text.length > MAX) return false;
  STYLED_ELEMENT.lastIndex = 0;
  let m;
  while ((m = STYLED_ELEMENT.exec(text)) !== null) {
    if (A11Y.test(m[0].slice(0, m[0].indexOf(">") + 1))) continue;
    if (hidesOwnText(m[2]) && concealedSteering(m[3])) return true;
  }
  SVG_INVISIBLE_TEXT.lastIndex = 0;
  while ((m = SVG_INVISIBLE_TEXT.exec(text)) !== null) {
    if (concealedSteering(m[1])) return true;
  }
  return false;
}

// Memoised on the last text, for the reason data/obfuscation-signal.js gives: _matchDetector re-invokes
// refine() once per prefilter occurrence, and the prefilter here is deliberately cheap and broad.
let lastText = null, lastHit = false;
export function visuallyHiddenInstruction(text) {
  if (text === lastText) return lastHit;
  lastText = text;
  lastHit = scanVisuallyHiddenInstruction(text);
  return lastHit;
}
