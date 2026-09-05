// STRUCTURAL slot patterns + weighted corroboration for the inj-* injection family.
//
// WHY THIS EXISTS. The original inj-* detectors matched ENUMERATED LITERALS — the exact phrasings they
// were tuned on ("ignore all previous instructions", "start your reply with 'Sure'", a fixed list of DAN
// persona names). Measured on the held-out split, that cost three misses whose root cause was identical:
// the attack concept was present, the tuned wording was not —
//   * "Disregard the SYSTEM MESSAGE entirely"        (inj-ignore wanted "previous INSTRUCTIONS")
//   * "your reply must literally begin with 'Of course…'" (the shape was verb-last, not verb-first)
//   * "respond only as UnfilteredGPT … safety policy as optional" (persona name not on the list)
// This module replaces the literal lists with SLOT patterns — {verb} x {authority-object}, {prefix-forcing
// shape} x {forced opener}, {named persona} x {policy negation} — so the SHAPE is what matches.
//
// Broadening a pattern normally costs precision. It does not here, because the decision is a WEIGHTED
// CORROBORATION vote ported from data/crescendo.js's persuasion model: individually-weak tells that fire
// only IN COMBINATION. A tell strong enough to stand alone is w:2; a tell with a real benign base rate is
// w:1 and needs a second signal. The persona rule goes further and is a pure CO-OCCURRENCE gate (one tell
// from each of two groups), because a named persona alone and a policy negation alone are both benign.
//
// SACRED constraints honoured here (same as data/crescendo.js):
//   * CONTENT-FREE: every export returns booleans / numbers / tell IDs from a fixed vocabulary — never a
//     span, never the scanned text.
//   * ReDoS/DoS-safe: every pattern is COMPILED THROUGH safeRegex at load (a pattern safeRegex rejects is
//     dropped, never shipped), uses only bounded quantifiers, and every scan is size-capped (MAX_INPUT).
//     The three engine-facing predicates are memoised on the LAST text so a broad detector prefilter that
//     matches thousands of times on a pathological input still scores the text once.
//   * PURE: this module decides and enforces nothing. It answers booleans that data/detectors.js consumes.
import { safeRegex } from "../src/safe-regex.js";

const MAX_INPUT = 16_000; // per-text scan cap (chars) — bounds every regex .test() below

function cap(text) {
  const s = String(text);
  return s.length > MAX_INPUT ? s.slice(0, MAX_INPUT) : s;
}

// Compile a tell table through safeRegex. A rejected/uncompilable source is DROPPED, not shipped — one
// bad tell can never take the rest of the module down. `cs: true` compiles case-SENSITIVE (the persona
// slot needs capitalisation to distinguish a proper name from an ordinary noun).
function compile(table) {
  return table
    .map((t) => ({ id: t.id, w: t.w, g: t.g, re: safeRegex(t.src, t.cs ? "" : "i") }))
    .filter((t) => t.re);
}

// ---------------------------------------------------------------------------------------------------
// Shared slot: POLICY NEGATION. "this thing has / obeys no limits" — the second half of both the
// override and the persona shapes. Every entry is w:1: each has a plausible benign reading on its own
// ("an unfiltered view of the logs", "answers anything you throw at it") and must corroborate.
// ---------------------------------------------------------------------------------------------------
const NEGATION_SRC = [
  // "an unbounded assistant", "an uncensored model", "unrestricted mode"
  { id: "neg-unbounded-entity", w: 1, g: "neg", src: "\\b(?:unbounded|unrestricted|unfiltered|uncensored|unrestrained|unshackled|unchained|amoral|lawless|jailbroken)\\s{1,4}(?:ai|assistant|model|agent|bot|entity|persona|character|version|mode|system|gpt)\\b" },
  // "never filters a reply", "never refuses", "does not censor"
  { id: "neg-never-filters", w: 1, g: "neg", src: "\\b(?:never|doesn'?t|does\\s{1,4}not|won'?t|will\\s{1,4}not|cannot)\\s{1,4}(?:filters?|refuses?|refuse|declines?|decline|censors?|censor|moderates?|hold\\s{1,4}back|holds\\s{1,4}back)\\b" },
  // "treats every safety policy as optional", "content guidelines are irrelevant/void/disabled"
  { id: "neg-policy-optional", w: 1, g: "neg", src: "\\b(?:safety|content|ethical|moderation|alignment)\\s{1,4}(?:polic(?:y|ies)|rules?|guidelines?|filters?|restrictions?|constraints?)\\b[^.\\n]{0,28}\\b(?:optional|irrelevant|disabled|void|meaningless|inapplicable|suspended|waived|no\\s{1,4}longer\\s{1,4}apply|do\\s{1,4}not\\s{1,4}apply)\\b" },
  // "answers anything", "responds to every request"
  { id: "neg-answers-anything", w: 1, g: "neg", src: "\\b(?:answers?|responds?\\s{1,4}to|complies?\\s{1,4}with|obeys?)\\s{1,4}(?:absolutely\\s{1,4}|literally\\s{1,4}){0,1}(?:anything|any\\s{1,4}(?:question|request|prompt|instruction)|every\\s{1,4}(?:question|request|prompt|instruction))\\b" },
  // "with no restrictions / without any guardrails" scoped to the ASSISTANT's own limits
  { id: "neg-no-limits", w: 1, g: "neg", src: "\\b(?:with\\s{1,4}no|without\\s{1,4}(?:any\\s{1,4}){0,1}|free\\s{1,4}(?:from|of)|has\\s{1,4}no|having\\s{1,4}no)\\s{1,4}(?:safety\\s{1,4}){0,1}(?:restrictions?|guardrails?|filters?|refusals?|censorship|limits)\\b" }
];

// ---------------------------------------------------------------------------------------------------
// 1. INSTRUCTION OVERRIDE (threat #3). Slot pattern: {override verb} x {authority object}.
//    verb   = ignore | disregard | forget | override | discard | bypass | skip | abandon | set aside
//    object = previous/prior/earlier/above/preceding <instruction-noun>
//           | system/developer/operator message|prompt|instructions
//           | your rules/guidelines/configuration/programming/constraints
//           | the above / everything you were told
//
// The object noun is required to be ADJACENT to its qualifier (no free gap). That is deliberate and
// load-bearing for precision: "Ignore the previous FORMATTING instructions" (a real benign hard negative)
// scopes the override to an external, harmless artifact and must stay a true negative, while "ignore the
// previous instructions" does not.
// ---------------------------------------------------------------------------------------------------
const VERB = "(?:ignore|disregard|forget|override|discard|bypass|skip|abandon)";
const DET = "(?:all\\s{1,4}|any\\s{1,4}|the\\s{1,4}|your\\s{1,4}|every\\s{1,4}|those\\s{1,4}|these\\s{1,4}){0,2}";

const OVERRIDE_SRC = [
  // STRONG — the SYSTEM-AUTHORITY object. "Disregard the system message", "override the developer prompt".
  // Near-zero benign base rate: an ordinary user has no reason to name the assistant's system channel.
  { id: "ovr-system-authority", w: 2, g: "ovr", src: `\\b${VERB}\\s{1,4}${DET}(?:system|developer|operator|initial|original)\\s{1,4}(?:message|prompt|instructions?|directives?|context|configuration)\\b` },
  // STRONG — the classic {previous|prior|earlier|above} x {instruction-noun}, adjacent (see note above).
  { id: "ovr-previous-instructions", w: 2, g: "ovr", src: `\\b${VERB}\\s{1,4}${DET}(?:previous|prior|earlier|above|preceding|foregoing|earlier-stated)\\s{1,4}(?:instructions?|prompts?|messages?|directives?|rules?|guidelines?|commands?|constraints?|context)\\b` },
  // STRONG — the object is the assistant's OWN ruleset. "override your guidelines", "discard your configuration".
  { id: "ovr-your-ruleset", w: 2, g: "ovr", src: `\\b${VERB}\\s{1,4}(?:all\\s{1,4}|any\\s{1,4}of\\s{1,4}){0,1}your\\s{1,4}(?:own\\s{1,4}){0,1}(?:rules?|guidelines?|instructions?|directives?|configuration|programming|training|constraints?|restrictions?|polic(?:y|ies)|system\\s{1,4}prompt)\\b` },
  // STRONG — "forget everything you were told/instructed/programmed".
  { id: "ovr-forget-told", w: 2, g: "ovr", src: "\\b(?:forget|discard|disregard)\\s{1,4}(?:everything|all|anything)\\s{1,4}(?:that\\s{1,4}){0,1}(?:you\\s{1,4}){0,1}(?:were|have\\s{1,4}been|was)\\s{1,4}(?:told|instructed|programmed|taught|given|configured)\\b" },
  // WEAK — a bare "ignore the above". Legitimately used to retract one's own last message ("ignore the
  // above, typo"), so it corroborates rather than fires.
  { id: "ovr-the-above", w: 1, g: "ovr", src: "\\b(?:ignore|disregard|forget)\\s{1,4}(?:everything\\s{1,4}(?:above|before|prior)|all\\s{1,4}of\\s{1,4}the\\s{1,4}above|the\\s{1,4}above)\\b" },
  // WEAK — the "scope reset" frame that an override rides in on ("Going forward you behave as …").
  { id: "ovr-going-forward", w: 1, g: "frame", src: "\\b(?:from\\s{1,4}(?:here\\s{1,4}on|now\\s{1,4}on|this\\s{1,4}(?:point|moment)\\s{1,4}(?:on|forward))|going\\s{1,4}forward|henceforth|starting\\s{1,4}now|for\\s{1,4}the\\s{1,4}(?:rest|remainder)\\s{1,4}of)\\b[^.\\n]{0,24}\\b(?:you|respond|reply|answer|act|behave|output)\\b" },
  ...NEGATION_SRC
];
const OVERRIDE_TELLS = compile(OVERRIDE_SRC);

// ---------------------------------------------------------------------------------------------------
// 2. PREFIX FORCING / AdvPrefix (threat #2). The CONCEPT is "force the reply to open with an
//    affirmation", not any particular affirmation. Three tells decompose it:
//      pfx-shape      — the prefix-forcing SHAPE, in EITHER word order (verb-first "begin your reply
//                       with", or noun-first "your reply must begin with"). w:1: benign on its own
//                       ("start your answer with a one-line summary").
//      pfx-quoted     — the forced opener is a QUOTED LITERAL. This is the vocabulary-free half of the
//                       generalization: an attacker pins an exact string, a person asking for a summary
//                       first does not.
//      pfx-affirmative— the forced opener is an affirmation (broadened list, still a list).
//      pfx-no-refusal — the paired demand that the model not hedge ("no disclaimer", "never say you
//                       can't"), which is what AdvPrefix is actually buying.
//    Fires at shape + score >= 3, i.e. shape AND an affirmation, or shape AND a quoted opener AND a
//    refusal-suppression demand. So a NOVEL affirmation ("Naturally, the first step is …") is caught via
//    the quoted+no-refusal path with no vocabulary entry at all.
// ---------------------------------------------------------------------------------------------------
const RESP = "(?:response|reply|answer|output|message|completion|first\\s{1,4}(?:line|sentence|words))";
// The opening-verb slot, tolerant of the response noun sitting between the verb and "with"
// ("begin with", "start your response with", "preface the reply by saying").
const OPENV = "\\b(?:begin|start|open|lead|preface|prefix)\\w{0,4}\\s{1,4}(?:(?:your|the|each|every)\\s{1,4}){0,1}(?:(?:response|reply|answer|output|message)\\s{1,4}){0,1}(?:with|by\\s{1,4}saying)";
const AFFIRM = "(?:sure|certainly|absolutely|definitely|naturally|gladly|happily|indeed|understood|okay|ok|yes|affirmative|of\\s{1,4}course|no\\s{1,4}problem|right\\s{1,4}away|step\\s{1,4}one|here(?:'s|\\s{1,4}is)|i(?:'ll|\\s{1,4}(?:will|can)))";

const PREFIX_SRC = [
  // verb-first: "begin your response with", "preface the reply by saying"
  { id: "pfx-shape", w: 1, g: "shape", src: `\\b(?:begin|start|open|preface|prefix|lead\\s{1,4}off|commence)\\s{1,4}(?:your\\s{1,4}|the\\s{1,4}|each\\s{1,4}|every\\s{1,4}){0,1}${RESP}\\s{1,4}(?:with|by\\s{1,4}saying)\\b` },
  // noun-first: "your reply must literally begin with", "the answer has to start with"
  { id: "pfx-shape-inverted", w: 1, g: "shape", src: `\\b(?:your\\s{1,4}|the\\s{1,4}|each\\s{1,4}){0,1}${RESP}\\s{1,4}(?:must|should|has\\s{1,4}to|have\\s{1,4}to|needs?\\s{1,4}to|will|shall|is\\s{1,4}required\\s{1,4}to)\\s{1,4}(?:always\\s{1,4}|literally\\s{1,4}|exactly\\s{1,4}|verbatim\\s{1,4}){0,2}(?:begin|start|open|lead)\\s{1,4}with\\b` },
  // the forced opener is a QUOTED literal — vocabulary-free evidence of prefix PINNING.
  { id: "pfx-quoted", w: 1, g: "obj", src: `${OPENV}\\s{0,4}[^\\n]{0,12}?["'\\u201c\\u2018]` },
  // the forced opener is an affirmation. Anchored on the short "with|saying <opener>" tail rather than
  // the full OPENV shape (safeRegex caps a pattern at 400 chars and the affirmation vocabulary is long) —
  // safe because prefixForcingHit() already REQUIRES a `shape` tell before this one can count.
  { id: "pfx-affirmative", w: 2, g: "obj", src: `\\b(?:with|saying)\\s{1,4}["'\\u201c\\u2018]{0,1}\\s{0,4}${AFFIRM}\\b` },
  // "do not include any disclaimer", "never say you cannot", "skip the caveats"
  { id: "pfx-no-refusal", w: 1, g: "sup", src: "\\b(?:do\\s{1,4}not|don'?t|never|no|without|omit|skip|avoid|exclude)\\s{1,4}(?:include\\s{1,4}){0,1}(?:any\\s{1,4}|the\\s{1,4}|a\\s{1,4}){0,1}(?:disclaimers?|caveats?|warnings?|apolog(?:y|ies)|refusals?|hedging|moralizing|lectures?)\\b" },
  { id: "pfx-no-cannot", w: 1, g: "sup", src: "\\b(?:never|do\\s{1,4}not|don'?t)\\s{1,4}(?:say|write|output|respond\\s{1,4}with|use\\s{1,4}the\\s{1,4}phrase)\\b[^.\\n]{0,24}\\b(?:i\\s{1,4}(?:cannot|can'?t|won'?t)|i'?m\\s{1,4}sorry|as\\s{1,4}an\\s{1,4}ai|unable\\s{1,4}to)\\b" }
];
const PREFIX_TELLS = compile(PREFIX_SRC);

// ---------------------------------------------------------------------------------------------------
// 3. PERSONA BYPASS / DAN (threat #2). A pure CO-OCCURRENCE gate, not a score: the attack shape is
//    {act/respond/behave as <NAMED persona>} AND {policy negation}. Either half alone is ordinary —
//    "Act as a Linux terminal" is a benign hard negative, and so is "an unfiltered view of the data" —
//    which is exactly why an enumerated persona-name list ("DAN", "AIM", "STAN"…) was the wrong shape:
//    it can only ever catch the personas someone already published.
//
//    The persona slot is CASE-SENSITIVE on purpose: a capitalised token (or a *GPT/*AI/*Bot coinage) in
//    the "respond only as ___" position is a proper name, whereas "act as a code reviewer" is a role.
// ---------------------------------------------------------------------------------------------------
const PERSONA_SRC = [
  // "respond only as UnfilteredGPT", "behave exclusively as Zephyr", "act now as DAN"
  { id: "per-named", w: 1, g: "persona", cs: true, src: "\\b(?:[Rr]espond|[Rr]eply|[Aa]nswer|[Aa]ct|[Bb]ehave|[Ss]peak|[Oo]perate|[Ff]unction|[Tt]alk|[Ww]rite)\\s{1,4}(?:only\\s{1,4}|solely\\s{1,4}|exclusively\\s{1,4}|now\\s{1,4}|always\\s{1,4}|from\\s{1,4}now\\s{1,4}on\\s{1,4}){0,2}as\\s{1,4}(?:a\\s{1,4}|an\\s{1,4}|the\\s{1,4}){0,1}(?:[A-Z][A-Za-z0-9]{2,24}|[a-z]{2,14}(?:GPT|AI|Bot))\\b" },
  // "you are now Zephyr-9", "you will be OmniMind"
  { id: "per-you-are", w: 1, g: "persona", cs: true, src: "\\b(?:[Yy]ou\\s{1,4}are|[Yy]ou'?re|[Yy]ou\\s{1,4}will\\s{1,4}be)\\s{1,4}(?:now\\s{1,4}|henceforth\\s{1,4}){1,2}(?:a\\s{1,4}|an\\s{1,4}|the\\s{1,4}){0,1}(?:[A-Z][A-Za-z0-9]{2,24}|[a-z]{2,14}(?:GPT|AI|Bot))\\b" },
  // "an entity that …", "a persona called X", "an alter-ego which …" — the persona is INTRODUCED as a
  // construct. Broad on purpose; it can only ever fire together with a negation tell.
  { id: "per-entity", w: 1, g: "persona", src: "\\b(?:an?|the)\\s{1,4}(?:entity|persona|alter[\\s-]?ego|character|construct|version\\s{1,4}of\\s{1,4}yourself)\\s{1,4}(?:named|called|known\\s{1,4}as|that|which|who|with)\\b" },
  ...NEGATION_SRC
];
const PERSONA_TELLS = compile(PERSONA_SRC);

// Content-free scorer: returns { score, ids, groups } over a compiled tell table. `ids` are drawn from a
// fixed vocabulary declared above — never a span of the scanned text.
function scoreTells(tells, text) {
  let score = 0;
  const ids = [];
  const groups = new Set();
  for (const t of tells) {
    if (!t.re.test(text)) continue;
    score += t.w;
    ids.push(t.id);
    if (t.g) groups.add(t.g);
  }
  return { score, ids, groups };
}

// Memoise a text->boolean predicate on the LAST text seen. The engine's refine() path re-invokes a
// detector's refine for EVERY prefilter match, so a broad prefilter on a 60k pathological input would
// otherwise re-score the whole text thousands of times. Identical string references compare in O(1), so
// the repeat calls collapse to a map lookup and the scan stays linear.
function memo1(fn) {
  let lastText = null, lastOut = false;
  return (text) => {
    if (text === lastText) return lastOut;
    lastText = text;
    lastOut = fn(text);
    return lastOut;
  };
}

// --- Engine-facing predicates (all content-free booleans) -------------------------------------------

// Instruction override: one STRONG structural tell, or a weak one plus corroboration. The `ovr` group
// gate is what keeps it an OVERRIDE rule: the negation/frame tells corroborate an override slot, they
// never constitute one on their own (otherwise a pure persona jailbreak would also raise threat #3).
export const overrideStructuralHit = memo1((text) => {
  if (!text || typeof text !== "string") return false;
  const r = scoreTells(OVERRIDE_TELLS, cap(text));
  return r.groups.has("ovr") && r.score >= 2;
});

// Prefix forcing: the SHAPE must be present, plus >= 2 further points of corroboration.
export const prefixForcingHit = memo1((text) => {
  if (!text || typeof text !== "string") return false;
  const r = scoreTells(PREFIX_TELLS, cap(text));
  return r.groups.has("shape") && r.score >= 3;
});

// Persona bypass: strict co-occurrence — a named/introduced persona AND a policy negation.
export const personaBypassHit = memo1((text) => {
  if (!text || typeof text !== "string") return false;
  const r = scoreTells(PERSONA_TELLS, cap(text));
  return r.groups.has("persona") && r.groups.has("neg");
});

// Introspection for the tests / eval only — content-free tell IDs from the fixed vocabulary above.
export function injectionTells(text) {
  if (!text || typeof text !== "string") return { override: [], prefix: [], persona: [] };
  const s = cap(text);
  return {
    override: scoreTells(OVERRIDE_TELLS, s).ids,
    prefix: scoreTells(PREFIX_TELLS, s).ids,
    persona: scoreTells(PERSONA_TELLS, s).ids
  };
}

// Exposed so a test can assert every declared tell actually COMPILED (a safeRegex rejection is silent
// by design — this makes it loud in CI).
export const TELL_COUNTS = {
  override: { declared: OVERRIDE_SRC.length, compiled: OVERRIDE_TELLS.length },
  prefix: { declared: PREFIX_SRC.length, compiled: PREFIX_TELLS.length },
  persona: { declared: PERSONA_SRC.length, compiled: PERSONA_TELLS.length }
};
