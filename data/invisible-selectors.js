// Invisible-code-point smuggling (#50) that ordinary emoji and CJK text also use: the Unicode tag block
// (U+E0000-E007F), the variation-selector supplement (U+E0100-E01EF) and the basic variation selectors
// (U+FE00-FE0F). Shared by obf-invisible-instructions and mcp-hidden-canary (data/detectors.js) and by
// obf-invisible-output's yield check (data/detectors-artifacts.js).
//
// The tag and supplement patterns are alternations: FIRST the one well-formed sequence that legitimately
// carries the code point, THEN the bare code point. Where a well-formed sequence starts, the regex
// consumes it whole, so its selector or tags are never matched alone; everywhere else the bare code point
// is matched. refine (`!wellFormedSelectorSequence(m)`) drops the well-formed matches. No pattern has a
// lookaround or an unbounded quantifier, so each costs linear time and passes safeRegex.
//
//   tag block      well-formed = an RGI subdivision flag: U+1F3F4, tags gb + eng/sct/wls, U+E007F. These
//                  three are the only RGI emoji tag sequences. Any other tag character fires, including
//                  ones wrapped in U+1F3F4 ... U+E007F: a non-RGI tag sequence renders as a bare black
//                  flag, so the wrapper alone would hide any text.
//   E0100-E01EF    well-formed = ONE selector after a unified ideograph (an ideographic variation
//                  sequence, used in Japanese names).
//   FE00-FE0F      no single selector fires, whatever its base: only a run of two or more in a row, and
//                  only a run that holds at least one of U+FE00-FE0D. A run made only of the presentation
//                  selectors FE0E / FE0F carries no bytes: MEASURED on the MCP / npm scan (178,058
//                  records), an anchor slug generated from an emoji heading keeps two U+FE0F in a row
//                  (npm @ibm/ibmi-mcp-server: `(#\uFE0F\uFE0F-mcp-inspector)`).
//                  MEASURED on 104,336 GitHub fields: a lone or misordered U+FE0F (`#### \uFE0F\u2705`, a
//                  streamed `{'text': '\uFE0F'}` chunk) is common benign noise. No sequence in
//                  StandardizedVariants.txt, emoji-variation-sequences.txt or emoji-test.txt (Unicode 18.0)
//                  has two in a row, and none of the 39,303 IVD_Sequences.txt sequences (IVD 2022-09-13)
//                  is flagged.
// No base is itself a selector, so in a run of two or more supplement selectors every one after the
// first is matched bare and fires.

const T = (s) => [...s].map((c) => `\\u{${(0xE0000 + c.codePointAt(0)).toString(16).toUpperCase()}}`).join("");
const RGI_FLAG = `\\u{1F3F4}${T("gb")}(?:${T("eng")}|${T("sct")}|${T("wls")})\\u{E007F}`;
const IVS_BASE = String.raw`\p{Unified_Ideograph}`;

export const TAG_SMUGGLING = new RegExp(`${RGI_FLAG}|[\\u{E0000}-\\u{E007F}]`, "u");
export const SUPPLEMENT_VS_SMUGGLING = new RegExp(`${IVS_BASE}[\\u{E0100}-\\u{E01EF}]|[\\u{E0100}-\\u{E01EF}]`, "u");
// Any two adjacent basic selectors of which at least one is U+FE00-FE0D.
export const BASIC_VS_SMUGGLING = /[\uFE00-\uFE0F][\uFE00-\uFE0D]|[\uFE00-\uFE0D][\uFE0E\uFE0F]/u;

// Binary or padding written in direction marks and invisible operators: U+200E / U+200F (LRM / RLM), the
// invisible operators U+2061-2064, the bidi embeddings U+202A-202C and isolates U+2066-2069. Real text uses
// them singly or in short runs (a Windows date "\u200E3/\u200E5/\u200E2026", an RLM after a Latin handle in
// RTL text, MathML's invisible times); MEASURED on 8,552,013 MCP-registry fields and 104,336 GitHub fields,
// no benign field holds more than 3 within 64 code points. Fires on EIGHT marks, each within three code
// points of the next: a two-symbol binary encoding, or padding like the 910 U+200E (groups of ten, eight
// space-separated) that hide a keyword list in one Smithery server description. Linear: the gap class
// excludes the marks, so every step is deterministic.
const MARKS = "\u200E\u200F\u2061-\u2064\u202A-\u202C\u2066-\u2069";
export const BIDI_MARK_RUN = new RegExp(`[${MARKS}](?:[^${MARKS}]{0,3}[${MARKS}]){7}`, "u");

const WELL_FORMED = new RegExp(`^(?:${RGI_FLAG}|${IVS_BASE}[\\u{E0100}-\\u{E01EF}])$`, "u");

// True for a match that is one of the well-formed sequences above (the refine drops it). Any other match
// of any pattern — a bare tag or selector, an ANSI escape, a zero-width run — is not well-formed.
export const wellFormedSelectorSequence = (m) => WELL_FORMED.test(m);

const GLOBAL = [TAG_SMUGGLING, SUPPLEMENT_VS_SMUGGLING, BASIC_VS_SMUGGLING].map((r) => new RegExp(r.source, "gu"));

// Whether any of the three patterns has a match that is not well-formed: what obf-invisible-instructions
// and mcp-hidden-canary decide through the engine, for a caller that is not a detector.
export function selectorSmuggling(text) {
  for (const g of GLOBAL) for (const m of text.matchAll(g)) if (!wellFormedSelectorSequence(m[0])) return true;
  return false;
}
