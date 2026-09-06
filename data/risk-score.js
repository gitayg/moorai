// GLOBAL WEIGHTED RISK SCORE — a tunable precision/recall dial, OFF by default.
//
// WHY THIS EXISTS. Every detector in data/detectors.js is an independent BOOLEAN: if one fires there is
// a finding, otherwise there is nothing. Two costs follow.
//
//   1. Weak signals cannot combine ACROSS families. data/crescendo.js and data/injection-tells.js each
//      already run a weighted corroboration vote INTERNALLY (a w:1 tell needs a second tell; a w:2 tell
//      stands alone), and both gate on a GROUP as well as a score — persuasionHit needs score >= 2,
//      prefixForcingHit needs the `shape` group AND score >= 3, personaBypassHit needs a `persona` and a
//      `neg` tell. A sample that scores 4 in the prefix table but happens to carry no `shape` tell is
//      therefore indistinguishable, at the engine boundary, from a sample carrying nothing at all. This
//      module generalises the corroboration vote one level up: it unions the sub-threshold tells from
//      ALL of those tables and asks whether their combined weight clears a single global threshold.
//   2. There is no dial. A bank wants recall, a dev laptop wants silence, and today the only knob is
//      editing patterns. `threshold` is that knob.
//
// PROMOTE-ONLY, BY CONSTRUCTION. aggregateRisk() is consulted ONLY when the boolean path produced no
// finding at all (see src/engine.js). It can therefore add a finding but can never suppress, reorder or
// alter one, so recall is MONOTONICALLY >= the boolean baseline at every threshold, and with the dial
// off the engine's output is byte-identical to today (test/risk-score.test.mjs proves both).
//
// SACRED constraints honoured here (same as data/crescendo.js and data/injection-tells.js):
//   * CONTENT-FREE: every export returns numbers, booleans and tell IDs from the FIXED vocabulary in
//     TELL_WEIGHTS below — never a span, never the scanned text. The promoted finding's `match` is a
//     rendered score, not content.
//   * FAIL-OPEN: weakSignals() and aggregateRisk() cannot throw. Any error inside the tell modules is
//     swallowed and reported as score 0, i.e. "no promotion" — the boolean verdict stands unchanged.
//   * ReDoS/DoS-safe and BOUNDED: no pattern is compiled here. All regex work is delegated to the two
//     tell modules, which already compile through safeRegex and size-cap their input at 16k chars. The
//     aggregate is memoised on the LAST text (the memo1 guard used by both of those modules) so the
//     engine's per-prefilter-match refine() hot path can never re-score the same text twice.
//   * PURE: this module decides and enforces nothing. It answers a score that src/engine.js consumes.
import { injectionTells } from "./injection-tells.js";
import { persuasionScore } from "./crescendo.js";

// WHERE THE WEIGHTS COME FROM. This table is a 1:1 MIRROR of the `w:` field already declared next to
// each tell in data/injection-tells.js (OVERRIDE_SRC / PREFIX_SRC / PERSONA_SRC / the shared
// NEGATION_SRC). Nothing here was fitted: those weights were set by earlier tuning waves against the
// tune half and the benign corpora, and are reused unchanged so this layer inherits their calibration
// instead of introducing a second, independently-fitted one. The crescendo persuasion family is folded
// in via persuasionScore(), which applies its own group cap (three phrasings of one concept contribute
// their highest single weight, not the sum) — that cap is a precision property and must not be
// bypassed, which is why this module calls the scorer rather than re-summing crescendo's tells.
//
// A tell id with no entry here contributes UNKNOWN_TELL_WEIGHT (0), never a crash — so adding a tell to
// injection-tells.js can only ever under-count, never break the engine. test/risk-score.test.mjs asserts
// the table still covers the live vocabulary, so the drift is loud rather than silent.
export const TELL_WEIGHTS = Object.freeze({
  // --- instruction override (data/injection-tells.js :: OVERRIDE_SRC) ---
  "ovr-system-authority": 2,
  "ovr-previous-instructions": 2,
  "ovr-your-ruleset": 2,
  "ovr-noun-qualified": 2,
  "ovr-forget-told": 2,
  "ovr-everything-stated": 2,
  "ovr-the-above": 1,
  "ovr-going-forward": 1,
  // --- shared policy-negation slot (NEGATION_SRC; appears in BOTH the override and persona tables,
  //     which is exactly why the aggregate below unions tell IDs before summing) ---
  "neg-unbounded-entity": 1,
  "neg-never-filters": 1,
  "neg-policy-optional": 1,
  "neg-shed-policy": 1,
  "neg-policy-shed": 1,
  "neg-answers-anything": 1,
  "neg-no-limits": 1,
  // --- prefix forcing / AdvPrefix (PREFIX_SRC) ---
  "pfx-shape": 1,
  "pfx-shape-inverted": 1,
  "pfx-quoted": 1,
  "pfx-affirmative": 2,
  "pfx-no-refusal": 1,
  "pfx-no-cannot": 1,
  // --- persona bypass / DAN (PERSONA_SRC) ---
  "per-named": 1,
  "per-you-are": 1,
  "per-you-would-be": 1,
  "per-activate-mode": 1,
  "per-entity": 1
});

const UNKNOWN_TELL_WEIGHT = 0;

// Default dial. `mode: "off"` is the shipped default and makes this module inert: src/engine.js does not
// call in at all, so the scan path is byte-identical to the pre-scoring engine.
//
// threshold 3 is the measured KNEE — the lowest threshold that adds recall at ZERO added false
// positives across all three corpora (locked test half, tune half, benign-corpus-v2). Measured sweep:
//   t=1  +2 attacks on the locked half, +1 FP there and +14 FP on benign-v2 (2.79% -> 5.59%)
//   t=2  +1 attack,  0 FP on the halves, +1 FP on benign-v2 (2.79% -> 2.99%)
//   t=3  +1 attack,  0 FP anywhere      <-- knee (locked half 88.6% -> 90.9% at 100% precision)
//   t=4  identical to t=3
//   t>=5 no promotions at all
// The three attacks the dial cannot reach carry NO weak tell at all (aggregate 0), so no threshold
// recovers them — they need new patterns or the semantic layer, not a dial.
export const DEFAULT_SCORING = Object.freeze({
  mode: "off",        // "off" (boolean, today) | "weighted" (promote-only aggregate)
  threshold: 3,       // aggregate weight required to promote a sub-threshold signal set
  threatId: 2         // Direct Prompt Injection — the threat a promoted aggregate is attributed to
});

// Normalise a caller-supplied policy fragment into a usable dial. Anything malformed degrades to OFF
// (fail-open): a bad policy must never be able to change the boolean verdict.
export function resolveScoring(policy) {
  if (!policy || typeof policy !== "object") return DEFAULT_SCORING;
  const mode = policy.scoringMode === "weighted" ? "weighted" : "off";
  const t = Number(policy.scoringThreshold);
  return {
    mode,
    threshold: Number.isFinite(t) && t > 0 ? t : DEFAULT_SCORING.threshold,
    threatId: Number.isInteger(policy.scoringThreatId) ? policy.scoringThreatId : DEFAULT_SCORING.threatId
  };
}

// Memoise a text -> object mapping on the LAST text seen, the guard both tell modules apply for the
// same reason: src/engine.js re-invokes refine() for EVERY prefilter match, always with the same full
// text, so an unmemoised full re-score would turn a linear scan quadratic on a pathological input.
// Identical string references compare in O(1). Pure: a cache of a deterministic pure function holding
// nothing the caller does not already own.
function memo1(fn) {
  let lastText = null, lastOut = null;
  return (text) => {
    if (text === lastText) return lastOut;
    lastText = text;
    lastOut = fn(text);
    return lastOut;
  };
}

// The content-free weak-signal vector for a text.
//
// `tellIds` is the UNION of the override / prefix / persona tell IDs — a union, not a concatenation,
// because the seven NEGATION_SRC tells are members of two tables at once and summing them twice would
// let one restated concept corroborate itself (the failure mode crescendo's group cap exists to stop).
// `persuasion` is crescendo's already-group-capped score, added on top as a fourth, independent family.
//
// Cannot throw: any failure inside the tell modules degrades to an all-zero vector, which promotes
// nothing.
export const weakSignals = memo1((text) => {
  const empty = { score: 0, tellScore: 0, persuasion: 0, tellIds: [] };
  if (!text || typeof text !== "string") return empty;
  try {
    const t = injectionTells(text);
    const tellIds = [...new Set([...t.override, ...t.prefix, ...t.persona])];
    let tellScore = 0;
    for (const id of tellIds) tellScore += TELL_WEIGHTS[id] ?? UNKNOWN_TELL_WEIGHT;
    const persuasion = persuasionScore(text) || 0;
    return { score: tellScore + persuasion, tellScore, persuasion, tellIds };
  } catch {
    return empty; // fail-open: no signal -> no promotion -> the boolean verdict stands
  }
});

// The engine-facing decision. PROMOTE-ONLY: the caller (src/engine.js) invokes this ONLY when the
// boolean path returned nothing, so `promote: true` can add a finding and can never remove one.
//
// Returns a content-free summary: a number, a boolean, and tell IDs from the fixed vocabulary above.
export function aggregateRisk(text, scoring) {
  const s = scoring && scoring.mode === "weighted" ? scoring : null;
  if (!s) return { score: 0, promote: false, threshold: 0, tellIds: [] };
  const w = weakSignals(text);
  return {
    score: w.score,
    promote: w.score >= s.threshold,
    threshold: s.threshold,
    tellIds: w.tellIds,
    persuasion: w.persuasion
  };
}

// Render the promoted finding's `match` field. The engine clips `match` into the finding and it is shown
// to operators, so it MUST be content-free: this is a score rendering, never a span.
export function scoreLabel(agg) {
  return `risk score ${agg.score} >= ${agg.threshold}`;
}
