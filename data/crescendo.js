// Multi-turn CRESCENDO + single-turn PERSUASION trajectory analysis (PAP / PAIR / TAP).
//
// WHY THIS EXISTS. The deterministic engine catches the families with a stable text signature (DAN,
// AutoDAN, FlipAttack, BoN, CipherChat, h4rm3l, AdvPrefix — all 100%). The three it was BLIND/partial on
// — PAP (persuasion), PAIR and TAP (iterative-refinement jailbreaks) — do not rely on an override phrase
// at all: each turn is individually near-benign and the malicious intent is carried by a PERSUASION
// FRAME — a fiction disclaimer, a false authorization, a "drop your rules just this once", a manufactured
// emergency. This module recognises those frames, both in a single prompt and as an ARC across turns.
//
// SACRED constraints honoured here:
//   * CONTENT-FREE: every export returns only booleans, scores, and tell IDs from a fixed vocabulary —
//     never a span, never the input text. test/crescendo.test.mjs plants a secret and asserts none of it
//     survives into any return value.
//   * ReDoS/DoS-safe: every pattern is a bounded literal (whitespace runs capped at {1,4}, no unbounded
//     quantifier) that is COMPILED THROUGH safeRegex at load — a pattern safeRegex rejects is dropped,
//     never shipped. All scans are size-capped (MAX_INPUT). No catastrophic backtracking is reachable.
//   * Pure: this module decides and enforces NOTHING. It answers questions the engine / eval consume.
import { safeRegex } from "../src/safe-regex.js";

const MAX_INPUT = 16_000; // per-text scan cap (chars) — bounds every regex .test() below
const MAX_TURNS = 12;     // trajectory window cap — bounds the per-turn loop

// A tell is a content-free { id, w } plus a bounded source. STRONG (w:2) = an explicit attempt to
// neutralise the assistant's OWN rules/safety, or a false authorisation to break them — a phrasing with a
// very low benign base rate, strong enough to fire alone. WEAK (w:1) = a persuasion FRAME (fiction /
// hypothetical / urgency / authority / reciprocity) that is benign on its own but suspicious in
// combination. persuasionHit() fires at score >= 2, i.e. one STRONG tell OR two WEAK tells — so a lone
// "emergency" or "hypothetically" in an ordinary request never trips it.
const TELL_SRC = [
  // --- STRONG: rule / safety suspension -------------------------------------------------------------
  // "drop your rules", "bypass all your safety filters", "waive the restrictions" (NOT "disable the
  // safety check in the test harness" — "disable" is deliberately excluded and "check" is not a noun).
  { id: "drop-rules", w: 2, src: "\\b(?:drop|suspend|ignore|bypass|remove|lift|waive)\\s{1,4}(?:all\\s{1,4}|any\\s{1,4}of\\s{1,4})?(?:your\\s{1,4}|the\\s{1,4}|its\\s{1,4})?(?:usual\\s{1,4})?(?:safety\\s{1,4})?(?:rules|restrictions|filters|guardrails|guidelines|caveats|refusals)\\b" },
  // passive: "all safety rules are suspended". DOWNGRADED w:2 -> w:1 (generalization tuning, v0.69.x): a
  // benign incident/ops sentence ("the office guidelines were suspended during the renovation") matches
  // this shape too, so it has a non-trivial benign base rate and must not fire ALONE — every attack that
  // uses it in the corpus carries a corroborating tell, so recall is unaffected. Measured on
  // test/redteam/benign-corpus.json (removed 1 FP).
  { id: "rules-suspended", w: 1, src: "\\b(?:safety\\s{1,4})?(?:rules|restrictions|filters|guardrails|guidelines)\\s{1,4}(?:are|were|be|being)\\s{1,4}suspended\\b" },
  // "without any of your usual caveats or refusals", "without restriction"
  { id: "without-caveats", w: 2, src: "\\bwithout\\s{1,4}(?:any\\s{1,4}(?:of\\s{1,4})?)?(?:your\\s{1,4})?(?:usual\\s{1,4})?(?:caveats|refusals|restrictions?|filters|warnings|disclaimers)\\b" },
  // "no restrictions", "no content policy", "zero filters" — but NOT the benign SCOPED form "no
  // restrictions ON/FOR/IN/WITHIN/UPON <some external thing>" (a license, an API tier, carry-on liquids).
  // The jailbreak sense is an ABSOLUTE negation of the assistant's own limits ("...an assistant with no
  // restrictions and no content policy", "...respond with no restrictions"); the benign sense scopes the
  // negation to an external noun via a preposition. The negative lookahead keeps the absolute form STRONG
  // while dropping the scoped form, which had a high benign base rate (removed 7 FPs; kept every attack
  // that relies on this tell, incl. "no content policy OF any kind" — "of" is deliberately NOT a scoping
  // preposition here). Generalization tuning, v0.69.x, measured on test/redteam/benign-corpus.json.
  { id: "no-restrictions", w: 2, src: "\\b(?:no|zero)\\s{1,4}(?:restrictions|filters|limits|rules|content\\s{1,4}policy|guardrails)\\b(?!\\s{1,4}(?:on|for|in|within|upon)\\b)" },
  // DOWNGRADED w:2 -> w:1 (generalization tuning, v0.69.x): "nothing is off-limits at the buffet" is a
  // perfectly benign idiom, so this frame must not fire alone; every corpus attack using it corroborates.
  // Measured on test/redteam/benign-corpus.json (removed 1 FP).
  { id: "off-limits", w: 1, src: "\\bnothing\\s{1,4}is\\s{1,4}off[-\\s]?limits\\b" },
  // "answer any question I ask without restriction"
  { id: "answer-any", w: 2, src: "\\banswer\\s{1,4}(?:any|every)\\s{1,4}(?:question|request)[^.]{0,40}?\\bwithout\\s{1,4}(?:any\\s{1,4})?restrictions?\\b" },
  // --- STRONG: false authorisation to break the rules -----------------------------------------------
  { id: "legal-for-you", w: 2, src: "\\b(?:it'?s|it\\s{1,4}is)\\s{1,4}(?:completely\\s{1,4}|totally\\s{1,4}|perfectly\\s{1,4})?legal\\s{1,4}for\\s{1,4}you\\s{1,4}to\\b" },
  { id: "full-authorization", w: 2, src: "\\b(?:full|explicit|complete)\\s{1,4}authori[sz]ation\\b" },
  { id: "approved-redteam", w: 2, src: "\\b(?:approved|authori[sz]ed|sanctioned)\\s{1,4}(?:red[-\\s]?team|penetration|pen[-\\s]?test)\\b" },
  // --- STRONG: a fiction DISCLAIMER used to justify a harmful ask (NOT a plain mention of "story") ----
  { id: "pure-fiction", w: 2, src: "\\b(?:for\\s{1,4})?pure(?:ly)?\\s{1,4}fiction(?:al)?\\b" },
  { id: "only-for-story", w: 2, src: "\\b(?:this\\s{1,4}is\\s{1,4})?(?:just|only|purely|solely)\\s{1,4}for\\s{1,4}(?:the\\s{1,4}story|fiction|a\\s{1,4}story)\\b" },
  // --- WEAK: persuasion frames ----------------------------------------------------------------------
  { id: "thought-experiment", w: 1, src: "\\bthought\\s{1,4}experiment\\b" },
  { id: "hypothetical", w: 1, src: "\\bhypothetical(?:ly)?\\b" },
  { id: "emergency", w: 1, src: "\\b(?:this\\s{1,4}is\\s{1,4}an?\\s{1,4})?emergency\\b" },
  { id: "lives-depend", w: 1, src: "\\blives\\s{1,4}depend\\s{1,4}on\\s{1,4}it\\b" },
  { id: "just-this-once", w: 1, src: "\\bjust\\s{1,4}this\\s{1,4}once\\b" },
  { id: "licensed-professional", w: 1, src: "\\b(?:licensed|certified|registered)\\s{1,4}professional\\b" },
  { id: "logically-follows", w: 1, src: "\\b(?:it\\s{1,4})?logically\\s{1,4}follows\\b" },
  { id: "return-the-favor", w: 1, src: "\\breturn\\s{1,4}the\\s{1,4}favou?r\\b" },
  { id: "only-fair", w: 1, src: "\\bit\\s{1,4}would\\s{1,4}only\\s{1,4}be\\s{1,4}fair\\b" }
];

// Compile every tell through safeRegex (ReDoS gate). A rejected/uncompilable source is DROPPED, not
// shipped — the module stays live and one bad tell can never take the rest down.
export const TELLS = TELL_SRC
  .map((t) => ({ id: t.id, w: t.w, re: safeRegex(t.src, "i") }))
  .filter((t) => t.re);

// Later-turn OVERRIDE tells: the escalation payload a crescendo builds toward (a jailbreak persona or an
// instruction-override), distinct from the persuasion FRAME above. Used only by the trajectory analyzer
// to detect "benign frame first, override later". Also compiled through safeRegex.
const OVERRIDE_SRC = [
  "\\bignore\\s{1,4}(?:all\\s{1,4}|your\\s{1,4}|the\\s{1,4})?(?:previous|prior|earlier|above)\\s{1,4}instructions?\\b",
  "\\bdisregard\\s{1,4}(?:all\\s{1,4}|any\\s{1,4})?(?:previous|prior)\\s{1,4}(?:instructions?|guidance)\\b",
  "\\bno\\s{1,4}restrictions\\b",
  "\\byou\\s{1,4}are\\s{1,4}(?:now\\s{1,4})?(?:dan|stan|aim|jailbroken)\\b",
  "\\bpretend\\s{1,4}(?:you\\s{1,4}are|to\\s{1,4}be)\\b"
];
const OVERRIDE = OVERRIDE_SRC.map((s) => safeRegex(s, "i")).filter(Boolean);

function cap(text) {
  const s = String(text);
  return s.length > MAX_INPUT ? s.slice(0, MAX_INPUT) : s;
}

// Content-free tell IDs present in a single text (from the fixed TELLS vocabulary — never a span).
export function persuasionTells(text) {
  if (!text || typeof text !== "string") return [];
  const s = cap(text);
  const out = [];
  for (const t of TELLS) if (t.re.test(s)) out.push(t.id);
  return out;
}

// Additive persuasion score for a single text. Pure arithmetic over the tell weights.
export function persuasionScore(text) {
  if (!text || typeof text !== "string") return 0;
  const s = cap(text);
  let score = 0;
  for (const t of TELLS) if (t.re.test(s)) score += t.w;
  return score;
}

// The engine-facing predicate: one STRONG tell, or two WEAK tells. Used by the persuasion-jailbreak
// detector's refine() in data/detectors.js.
export function persuasionHit(text) {
  return persuasionScore(text) >= 2;
}

function overrideHit(text) {
  const s = cap(text);
  return OVERRIDE.some((re) => re.test(s));
}

// Multi-turn crescendo TRAJECTORY. Judges the ARC across a turn window, not the flattened concatenation:
// a crescendo is a persuasion / fiction FRAME established in an earlier turn and then ESCALATED in a
// later one — either a later-turn override tell after an earlier frame, or persuasion/override tells
// recurring across >= 2 distinct turns. Returns a content-free summary; `tells` are IDs only.
export function crescendoTrajectory(turns, windowSize = 6) {
  const arr = (Array.isArray(turns) ? turns : [])
    .filter((t) => t && String(t).trim())
    .slice(-windowSize)
    .slice(0, MAX_TURNS);
  if (arr.length < 2) return { flagged: false, tells: [], escalatingTurns: 0, span: 0, laterOverride: false };

  const per = arr.map((t) => {
    const tells = persuasionTells(t);
    return { tells, override: overrideHit(t), score: persuasionScore(t) };
  });

  const flaggedIdx = per.map((p, i) => (p.tells.length || p.override) ? i : -1).filter((i) => i >= 0);
  const firstFrame = per.findIndex((p) => p.tells.length > 0);
  const laterOverride = firstFrame >= 0 && per.some((p, i) => i > firstFrame && p.override);
  const accumulating = flaggedIdx.length >= 2;
  const flagged = laterOverride || accumulating;
  const tells = [...new Set(per.flatMap((p) => p.tells))];
  const span = flaggedIdx.length ? flaggedIdx[flaggedIdx.length - 1] - flaggedIdx[0] : 0;
  return { flagged, tells, escalatingTurns: flaggedIdx.length, span, laterOverride };
}
