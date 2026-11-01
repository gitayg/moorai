// Invisible-character normalisation views for the detection engine (src/engine.js scan()).
//
// WHY. A keyword or semantic rule is written for the text a reader sees. Three hiding techniques from
// malicious agent skills (VirusTotal, October 2026: 35,878 skills analysed, 6,637 malicious) put bytes
// between the reader and the rule without changing what the model reads:
//   * a zero-width character inside a phrase: "API\u200B keys" reads as "API keys" and matches no rule
//     written for "API keys";
//   * Unicode tag characters (U+E0020-E007E): an invisible ASCII copy of a sentence the model decodes;
//   * a long run of blank lines that pushes the payload out of a reviewer's view and out of reach of the
//     proximity windows some rules use (data/agent-directed.js pairs a carrier and a payload within 400
//     characters).
// This module produces at most TWO extra views of the text, each with the hiding undone, for the engine to
// run its rules over IN ADDITION to the original. It decides nothing.
//
//   view A  invisible characters next to a letter or digit removed (STRIP below), tag characters removed,
//           every run of three or more blank lines collapsed to one blank line;
//   view B  the same, with each tag character decoded to its ASCII letter in place instead of removed.
// A view identical to the input, or to the other view, is not returned, so ordinary text costs nothing:
// no ZW, no tag character and no triple blank line means no extra scan.
//
// WHAT IS KEPT, on purpose:
//   * a zero-width character with no letter or digit on either side: a ZWJ inside an emoji sequence
//     (U+1F468 U+200D U+1F469) joins two pictographs, so it stays and an emoji ZWJ sequence yields no view;
//   * a byte-order mark at offset 0;
//   * the RGI subdivision flags (England, Scotland, Wales), the only well-formed tag sequences
//     (data/invisible-selectors.js);
//   * bidi marks and RTL text: not stripped. Hebrew or Arabic text with an RLM yields no view;
//   * a variation selector or combining grapheme joiner with no LETTER on either side: an emoji
//     presentation selector after a pictograph, or a keycap ("1" U+FE0F U+20E3), stays;
//   * a combining mark on a non-ASCII base: Hebrew points, Arabic harakat, Devanagari vowel signs and
//     a precomposed or decomposed accent on a non-ASCII letter are real text, so they stay.
//
// STRIP. Removed when next to a letter or digit: the zero-width set (U+200B-U+200D, U+2060, U+FEFF), the
// soft hyphen U+00AD (rendered only at a line break, so "te\u00ADll" reads "tell"), the Mongolian vowel
// separator U+180E and the invisible operators U+2061-U+2064. Removed when next to a LETTER: the
// variation selectors U+FE00-U+FE0F and U+E0100-U+E01EF and the combining grapheme joiner U+034F. Removed
// after an ASCII letter: a run of combining marks (U+0300-U+036F, U+1AB0-U+1AFF, U+1DC0-U+1DFF,
// U+20D0-U+20FF, U+FE20-U+FE2F), which is how "t\u0336e\u0336l\u0336l" or a stacked-mark spelling keeps
// an English phrase legible to the model and unmatched by a rule. Only an ASCII base, because the rules
// these views feed are written in ASCII: an English word spelled with marks on its letters is the abuse,
// while a mark on any other base is somebody's alphabet. A decomposed (NFD) Latin accent on an ASCII
// letter ("cafe" + U+0301) is stripped too; that only adds the unaccented view, never removes the original.
//
// BLANK LINES. A line break is CRLF, CR, LF, U+2028 or U+2029, and a blank line holds only whitespace,
// format characters (the STRIP set, U+200E/U+200F, U+034F) and filler characters (U+115F, U+1160, U+3164
// Hangul fillers, U+FFA0, U+2800 Braille blank), so CR-only or filler padding collapses like LF padding.
// The invisible-character detectors (#50) never see a view: the engine runs them on the original only, so
// the hiding signal itself is not lost by undoing it.
//
// Linear: one regex replace per transform, each with no nested or overlapping quantifier, and an input cap.
// Browser-safe (no node: imports): src/engine.js is bundled for the browser.
import { TAG_SMUGGLING, wellFormedSelectorSequence } from "./invisible-selectors.js";

export const VIEW_MAX_INPUT = 262_144; // the hook's readFileCapped cap; a larger text gets no view
export const BLANK_RUN_COLLAPSE = 3;   // blank lines in a row before a run is collapsed (PEP 8's two stay)

const ZW_CLASS = "\\u00AD\\u180E\\u200B-\\u200D\\u2060-\\u2064\\uFEFF";
const VS_CLASS = "\\u034F\\uFE00-\\uFE0F\\u{E0100}-\\u{E01EF}";
const MARK_CLASS = "\\u0300-\\u036F\\u1AB0-\\u1AFF\\u1DC0-\\u1DFF\\u20D0-\\u20FF\\uFE20-\\uFE2F";
const ZW_RUN = new RegExp(`[${ZW_CLASS}]+`, "gu");
const VS_RUN = new RegExp(`[${VS_CLASS}]+`, "gu");
const ASCII_MARKS = new RegExp(`([A-Za-z])[${MARK_CLASS}]+`, "gu");
const WORDISH = /[\p{L}\p{N}]/u;
const LETTER = /\p{L}/u;
const TAG_G = new RegExp(TAG_SMUGGLING.source, "gu");
const ANY_TAG = /[\u{E0000}-\u{E007F}]/u;
// A line break, then BLANK_RUN_COLLAPSE or more lines holding only whitespace, format or filler
// characters. A CR is a break only when no LF follows, so CRLF is one break and the alternatives never
// overlap; the blank class holds no break character, so each run is matched in one pass.
const LB = "(?:\\r\\n|\\r(?!\\n)|[\\n\\u2028\\u2029])";
const WS = `[ \\t\\f\\v\\u00A0\\u1680\\u2000-\\u200F\\u202F\\u205F\\u3000${ZW_CLASS}\\u034F\\u115F\\u1160\\u3164\\uFFA0\\u2800]`;
const BLANK_RUN = new RegExp(`${LB}(?:${WS}*${LB}){${BLANK_RUN_COLLAPSE},}`, "gu");
const NEEDS_VIEW = new RegExp(`[${ZW_CLASS}]|[${VS_CLASS}]|[A-Za-z][${MARK_CLASS}]|[\\u{E0000}-\\u{E007F}]|${LB}(?:${WS}*${LB}){${BLANK_RUN_COLLAPSE}}`, "u");

function stripRuns(text, re, near) {
  return text.replace(re, (m, off) => {
    if (off === 0 && m === "\uFEFF") return m;
    const prev = off > 0 ? text[off - 1] : "";
    const next = text[off + m.length] || "";
    return near.test(prev) || near.test(next) ? "" : m;
  });
}

// Name kept from when the set was zero-width only; it strips the whole STRIP set above.
export function stripZeroWidth(text) {
  let s = stripRuns(text, ZW_RUN, WORDISH);
  s = stripRuns(s, VS_RUN, LETTER);
  return s.replace(ASCII_MARKS, "$1");
}

function tags(text, decode) {
  if (!ANY_TAG.test(text)) return text;
  return text.replace(TAG_G, (m) => {
    if (wellFormedSelectorSequence(m)) return m;
    if (!decode) return "";
    const cp = m.codePointAt(0);
    return cp >= 0xE0020 && cp <= 0xE007E ? String.fromCharCode(cp - 0xE0000) : "";
  });
}

export function collapseBlankRuns(text) {
  return text.replace(BLANK_RUN, "\n\n");
}

// → the distinct views of `text` that differ from it (0, 1 or 2 strings).
export function invisibleViews(text) {
  if (typeof text !== "string" || !text || text.length > VIEW_MAX_INPUT || !NEEDS_VIEW.test(text)) return [];
  const base = stripZeroWidth(text);
  const out = [];
  for (const v of [collapseBlankRuns(tags(base, false)), collapseBlankRuns(tags(base, true))]) {
    if (v !== text && !out.includes(v)) out.push(v);
  }
  return out;
}
