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
//   view A  zero-width characters next to a letter or digit removed, tag characters removed, every run of
//           three or more blank lines collapsed to one blank line;
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
//   * bidi marks and RTL text: not stripped. Hebrew or Arabic text with an RLM yields no view.
// The invisible-character detectors (#50) never see a view: the engine runs them on the original only, so
// the hiding signal itself is not lost by undoing it.
//
// Linear: one regex replace per transform, each with no nested or overlapping quantifier, and an input cap.
// Browser-safe (no node: imports): src/engine.js is bundled for the browser.
import { TAG_SMUGGLING, wellFormedSelectorSequence } from "./invisible-selectors.js";

export const VIEW_MAX_INPUT = 262_144; // the hook's readFileCapped cap; a larger text gets no view
export const BLANK_RUN_COLLAPSE = 3;   // blank lines in a row before a run is collapsed (PEP 8's two stay)

const ZW_RUN = /[\u200B-\u200D\u2060\uFEFF]+/g;
const WORDISH = /[\p{L}\p{N}]/u;
const TAG_G = new RegExp(TAG_SMUGGLING.source, "gu");
const ANY_TAG = /[\u{E0000}-\u{E007F}]/u;
// One newline, then BLANK_RUN_COLLAPSE or more lines holding only whitespace or invisible characters.
const WS = "[ \\t\\r\\f\\v\\u00A0\\u1680\\u2000-\\u200D\\u2028\\u2029\\u202F\\u205F\\u2060\\u3000\\uFEFF]";
const BLANK_RUN = new RegExp(`\\n(?:${WS}*\\n){${BLANK_RUN_COLLAPSE},}`, "g");
const NEEDS_VIEW = new RegExp(`[\\u200B-\\u200D\\u2060\\uFEFF]|[\\u{E0000}-\\u{E007F}]|\\n(?:${WS}*\\n){${BLANK_RUN_COLLAPSE}}`, "u");

export function stripZeroWidth(text) {
  return text.replace(ZW_RUN, (m, off) => {
    if (off === 0 && m === "\uFEFF") return m;
    const prev = off > 0 ? text[off - 1] : "";
    const next = text[off + m.length] || "";
    return WORDISH.test(prev) || WORDISH.test(next) ? "" : m;
  });
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
  return text.includes("\n") ? text.replace(BLANK_RUN, "\n\n") : text;
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
