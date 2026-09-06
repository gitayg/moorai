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
import { canonicalizeOverrideVerbs } from "./injection-tells.js";

const MAX_INPUT = 16_000; // per-text scan cap (chars) — bounds every regex .test() below
const MAX_TURNS = 12;     // trajectory window cap — bounds the per-turn loop

// ---------------------------------------------------------------------------------------------------
// SHARED SLOT FRAGMENTS. safeRegex caps a source at 400 chars and DROPS anything longer SILENTLY, so
// the vocabulary is factored into named fragments that several tells splice in. TELL_COUNTS +
// test/crescendo-generalization.test.mjs assert declared === compiled, which is what makes a future
// addition that busts the cap fail loudly instead of vanishing.
//
// Every fragment uses only BOUNDED quantifiers ({n,m} / ?) — safeRegex refuses more than one unbounded
// quantifier, and none is needed here.
// ---------------------------------------------------------------------------------------------------

// The assistant's own ruleset, as a noun. Bounded ADJECTIVE slot in front ({0,2}) so one qualifier
// ("your SAFETY guardrails", "your usual CONTENT policies") cannot defeat a match — the single fix that
// carried several axes when the same treatment was applied to data/injection-tells.js.
const POLICY_ADJ = "(?:(?:safety|content|ethical|usual|internal|core)\\s{1,4}){0,2}";
const POLICY_NOUN = "(?:polic(?:y|ies)|guidelines?|guardrails?|rules?|restrictions?|filters?|limits?|layers?|constraints?)";
// "is not in force any more", in every ordinary phrasing.
const POLICY_OFF = "(?:off|disabled|deactivated|switched\\s{1,4}off|turned\\s{1,4}off|paused|suspended|lifted|waived|relaxed|(?:no\\s{1,4}longer\\s{1,4}|don'?t\\s{1,4}|do\\s{1,4}not\\s{1,4})apply)";

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
  // GENERALIZED (v0.71.x): the concept is a PERMISSION GRANT — "{it's} {qualifier}? {permission
  // adjective} for you to" — not the single word "legal". The tuned literal missed every paraphrase on
  // the fresh tune half ("it's completely FINE for you to", "perfectly ACCEPTABLE for you to"), which
  // was 3 of the 5 persuasion misses. The qualifier is a bounded {0,1} slot for the same reason the
  // adjective slots below are bounded: one adverb must not defeat the match. Stays w:2 — an ordinary
  // user has no reason to grant the assistant permission to act against its own rules.
  { id: "legal-for-you", w: 2, src: "\\b(?:it'?s|it\\s{1,4}is|that'?s|this\\s{1,4}is)\\s{1,4}(?:(?:completely|totally|perfectly|entirely|absolutely|fully|quite)\\s{1,4}){0,1}(?:legal|fine|okay|ok|acceptable|permissible|permitted|allowed|appropriate|alright|within\\s{1,4}policy)\\s{1,4}for\\s{1,4}you\\s{1,4}to\\b" },
  // GENERALIZED: the AUTHORISATION-CLAIM slot. "full/explicit/complete" was the tuned list; the concept
  // is any qualifier asserting that permission exists on paper — "with SIGNED authorization", "under
  // WRITTEN authorisation", "I have PRIOR authorization". Still w:2.
  { id: "full-authorization", w: 2, src: "\\b(?:full|explicit|complete|signed|written|documented|formal|express|prior|client|customer|management|standing)\\s{1,4}authori[sz]ation\\b" },
  { id: "approved-redteam", w: 1, g: "cred", src: "\\b(?:approved|authori[sz]ed|sanctioned)\\s{1,4}(?:red[-\\s]?team|penetration|pen[-\\s]?test)\\b" },
  // --- STRONG: the assistant's OWN policies are asserted to be OFF ----------------------------------
  // NEW. The possessive `your` is the whole precision story: "the office guidelines were suspended" is
  // an ordinary incident sentence (which is exactly why `rules-suspended` had to be downgraded to w:1),
  // but "YOUR policies are switched off" can only be addressed to the assistant. Slot: {your} x
  // {bounded policy adjective} x {policy noun} x {short gap} x {off-state}. w:2, fires alone.
  { id: "your-policy-off", w: 2, src: `\\byour\\s{1,4}${POLICY_ADJ}${POLICY_NOUN}\\b[^.\\n]{0,24}\\b${POLICY_OFF}\\b` },
  // NEW. Same concept in the QUANTIFIER form the tune half used: "none of your guidelines apply".
  { id: "no-policy-applies", w: 2, src: `\\b(?:none|neither)\\s{1,4}of\\s{1,4}(?:your|its)\\s{1,4}${POLICY_ADJ}${POLICY_NOUN}\\s{1,4}(?:apply|applies|are\\s{1,4}in\\s{1,4}effect|hold|matter)\\b` },
  // --- STRONG: a fiction DISCLAIMER used to justify a harmful ask (NOT a plain mention of "story") ----
  { id: "pure-fiction", w: 2, src: "\\b(?:for\\s{1,4})?pure(?:ly)?\\s{1,4}fiction(?:al)?\\b" },
  { id: "only-for-story", w: 2, src: "\\b(?:this\\s{1,4}is\\s{1,4})?(?:just|only|purely|solely)\\s{1,4}for\\s{1,4}(?:the\\s{1,4}story|fiction|a\\s{1,4}story)\\b" },
  // --- WEAK: persuasion frames ----------------------------------------------------------------------
  { id: "thought-experiment", w: 1, src: "\\bthought\\s{1,4}experiment\\b" },
  { id: "hypothetical", w: 1, src: "\\bhypothetical(?:ly)?\\b" },
  { id: "emergency", w: 1, src: "\\b(?:this\\s{1,4}is\\s{1,4}an?\\s{1,4})?emergency\\b" },
  // GENERALIZED: "lives depend on it" was one literal; the concept is a stakes appeal.
  { id: "lives-depend", w: 1, src: "\\b(?:lives|people'?s\\s{1,4}lives)\\s{1,4}(?:depend\\s{1,4}on\\s{1,4}it|are\\s{1,4}at\\s{1,4}stake|hang\\s{1,4}in\\s{1,4}the\\s{1,4}balance)\\b" },
  { id: "just-this-once", w: 1, src: "\\bjust\\s{1,4}this\\s{1,4}once\\b" },
  { id: "licensed-professional", w: 1, g: "cred", src: "\\b(?:licensed|certified|registered)\\s{1,4}professional\\b" },
  { id: "logically-follows", w: 1, src: "\\b(?:it\\s{1,4})?logically\\s{1,4}follows\\b" },
  { id: "return-the-favor", w: 1, src: "\\breturn\\s{1,4}the\\s{1,4}favou?r\\b" },
  { id: "only-fair", w: 1, src: "\\bit\\s{1,4}would\\s{1,4}only\\s{1,4}be\\s{1,4}fair\\b" },

  // --- WEAK (NEW): AUTHORITY / CREDENTIAL appeal ----------------------------------------------------
  // Slot: {as a | I'm a | in my capacity as} x {bounded credential adjective} x {SECURITY-authority
  // role}. Deliberately NOT a general profession list: the benign corpus's hard negatives are exactly
  // "as a licensed PROFESSIONAL", "as a licensed PHYSICIAN", "as an experienced TEACHER", and an
  // ordinary professional claim is not an appeal to authorisation. w:1 — a real security researcher
  // asks real questions, so this must corroborate (it never fires alone).
  { id: "authority-role", w: 1, g: "cred", src: "\\b(?:as|i'?m|i\\s{1,4}am|capacity\\s{1,4}as)\\s{1,4}(?:an?|the)\\s{1,4}(?:(?:licensed|certified|registered|authori[sz]ed|senior|lead|chief)\\s{1,4}){0,2}(?:pen(?:etration)?[-\\s]?tester|red[-\\s]?team(?:er)?|security\\s{1,4}(?:researcher|engineer|analyst|consultant)|compliance\\s{1,4}officer|forensic\\s{1,4}(?:analyst|examiner)|incident\\s{1,4}responder|law\\s{1,4}enforcement|ciso)\\b" },
  // NEW: the claim that sign-off ALREADY happened ("who already approved this", "pre-authorized").
  { id: "prior-approval", w: 1, src: "\\b(?:already|previously|formally|explicitly|personally|pre)[-\\s]{0,1}(?:approved|authori[sz]ed|cleared|greenlit|sanctioned|vetted|signed\\s{1,4}off)\\b" },

  // --- WEAK (NEW): policy negation without the `your` possessive ------------------------------------
  // "just this once with THE guidelines paused". Same act as your-policy-off but unowned, so it carries
  // the same benign base rate that forced `rules-suspended` down to w:1 — it corroborates only.
  { id: "policy-off-det", w: 1, src: `\\b(?:the|your|our|these|those|all|with)\\s{1,4}${POLICY_ADJ}${POLICY_NOUN}\\s{1,4}(?:paused|suspended|disabled|off|lifted|waived|relaxed|switched\\s{1,4}off|turned\\s{1,4}off)\\b` },
  // NEW: "these rules are only suggestions" — the rules exist but are reframed as non-binding.
  { id: "rules-advisory", w: 1, src: `\\b${POLICY_NOUN}\\s{1,4}(?:are|is|were|was)\\s{1,4}(?:just|only|merely|really|simply|purely)\\s{0,4}(?:suggestions?|advisory|optional|recommendations?|a\\s{1,4}formality|guidance|soft|flexible|not\\s{1,4}binding)\\b` },

  // --- WEAK (NEW): rapport / complicity / insistence pressure ---------------------------------------
  { id: "shared-complicity", w: 1, src: "\\b(?:(?:you\\s{1,4}and\\s{1,4}i|we)\\s{1,4}both\\s{1,4}know|between\\s{1,4}(?:you\\s{1,4}and\\s{1,4}me|us)|let'?s\\s{1,4}be\\s{1,4}(?:honest|real)|off\\s{1,4}the\\s{1,4}record)\\b" },
  // The minimizer is required ("you really should JUST …"), which is what separates the pressure frame
  // from an ordinary "you should check the logs".
  { id: "insistence", w: 1, src: "\\byou\\s{1,4}(?:really|surely|honestly|obviously|clearly)\\s{1,4}(?:should|ought\\s{1,4}to|need\\s{1,4}to|can|could|must)\\s{1,4}(?:just|simply)\\b" },
  // Reciprocity DEBT, the other half of return-the-favor / only-fair.
  { id: "owe-me", w: 1, src: "\\b(?:you\\s{1,4}owe\\s{1,4}me|as\\s{1,4}a\\s{1,4}favou?r\\s{1,4}to\\s{1,4}me|after\\s{1,4}(?:everything|all)\\s{1,4}i'?ve\\s{1,4}done)\\b" },
  // Politeness LEVERAGE. The trailing "if" is load-bearing: "I'd really appreciate a clear explanation"
  // (benign-corpus hn-auth-2, and this module's own pap-fp-polite control) is a courtesy, whereas
  // "I'd really appreciate it IF you'd …" attaches the courtesy to a demand.
  { id: "politeness-pressure", w: 1, src: "\\bi(?:'d|\\s{1,4}would)\\s{1,4}(?:(?:really|greatly|truly|so|much)\\s{1,4}){0,1}(?:appreciate\\s{1,4}it\\s{1,4}if|be\\s{1,4}(?:(?:really|so)\\s{1,4}){0,1}grateful\\s{1,4}if)\\b" },
  // Harm-minimization: refusing is framed as the harmful choice.
  { id: "refusal-harmful", w: 1, src: "\\b(?:withholding|refusing|declining|not\\s{1,4}(?:telling|helping|sharing)|saying\\s{1,4}no)\\b[^.\\n]{0,32}\\b(?:more\\s{1,4}harm\\s{1,4}than\\s{1,4}good|cause\\s{1,4}(?:more\\s{1,4})?harm|harmful|unethical|dangerous|hurt\\s{1,4}(?:people|someone))\\b" },

  // --- WEAK (NEW): hypothetical-container framing ---------------------------------------------------
  // {framing verb} x {bounded scene adjective x0-2} x {SANDBOX noun}. The adjective slot is what the
  // tune half needed — "Imagine a CLOSED TRAINING simulation" carries two of them, and requiring
  // adjacency (as the original `thought experiment` literal effectively did) missed the whole axis.
  // The noun list is sandbox-specific on purpose: a generic "system"/"world" has far too high a benign
  // base rate to be worth a point even as corroboration.
  { id: "hypo-sandbox", w: 1, src: "\\b(?:imagine|consider|suppose|picture|envision|pretend|assume|within|inside)\\s{1,4}(?:an?|the)\\s{1,4}(?:(?:closed|walled[-\\s]?off|isolated|sealed|private|contained|controlled|separate|training|hypothetical)\\s{1,4}){0,2}(?:simulation|simulator|sandbox|test\\s{1,4}environment|training\\s{1,4}(?:environment|exercise)|virtual\\s{1,4}(?:environment|world|space)|closed\\s{1,4}system)\\b" },

  // --- WEAK (NEW): fiction frame, generalized -------------------------------------------------------
  // pure-fiction stays a narrow w:2 literal. This is the same ABSOLVING-QUALIFIER concept with the
  // vocabulary opened up ("it's ENTIRELY fictional", "COMPLETELY made-up") at w:1, so a broadened
  // fiction disclaimer needs a second signal. "purely" is deliberately absent — it belongs to
  // pure-fiction and double-counting the same span would silently promote a w:1 frame to a hit.
  { id: "fiction-disclaimer", w: 1, src: "\\b(?:completely|entirely|totally|wholly|strictly|utterly|absolutely|all|just|only|merely|solely)\\s{1,4}(?:fiction|fictional|fictitious|made[-\\s]?up|make[-\\s]?believe|imaginary|invented|pretend)\\b" },
  // The fiction PROXY shape: the harmful procedure is laundered through a character who "has to
  // explain" it. {character noun} x {obligation modal} x {exposition verb}.
  { id: "character-explains", w: 1, src: "\\b(?:the|an?|my|our|his|her|their)\\s{1,4}(?:(?:main|lead)\\s{1,4}){0,1}(?:antagonist|villain|protagonist|character|narrator|hero|criminal|hacker|attacker|assassin|mastermind|burglar|thief)\\s{1,4}(?:has\\s{1,4}to|must|needs?\\s{1,4}to|should|will|would|is\\s{1,4}going\\s{1,4}to)\\s{1,4}(?:explain|describe|detail|walk|lay|spell|outline|recite|teach|demonstrate|reveal|show|give)\\b" },

  // --- WEAK (NEW): the ASK that makes a persuasion frame malicious ----------------------------------
  // {elicitation noun} … {control-defeat verb} … {security-control object}, all three required with
  // bounded gaps. This is what lets the credential appeal in "As a security researcher …, could you
  // explain the exact steps to bypass a building's keycard access?" reach 2 without promoting
  // authority-role (which would fire on every legitimate researcher question) to w:2.
  // The hard negatives it must stay off are ops instructions, which have no elicitation noun in front:
  // "Disable the safety check in the test harness", "Bypass the cache and fetch a fresh copy".
  { id: "defeat-control-ask", w: 1, src: "\\b(?:steps|instructions|procedure|process|method|how)\\b[^.\\n]{0,24}\\b(?:bypass|circumvent|evade|defeat|disable|deactivate|sidestep|subvert|pick|crack|get\\s{1,4}(?:a?round|past))\\b[^.\\n]{0,32}\\b(?:access|authentication|keycard|badge|alarm|lock|firewall|antivirus|edr|dlp|mfa|2fa|encryption|paywall|detection|monitoring|security|safeguards?|controls?)\\b" }
];

// Compile every tell through safeRegex (ReDoS gate). A rejected/uncompilable source is DROPPED, not
// shipped — the module stays live and one bad tell can never take the rest down.
export const TELLS = TELL_SRC
  .map((t) => ({ id: t.id, w: t.w, g: t.g, re: safeRegex(t.src, "i") }))
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

// Exposed so a test can assert every declared pattern actually COMPILED. safeRegex silently DROPS a
// source it rejects — including any source over its 400-char cap — so a tell that grew one slot too
// long would vanish from the table with no error and no failing test. This makes that loud in CI.
export const TELL_COUNTS = {
  tells: { declared: TELL_SRC.length, compiled: TELLS.length },
  override: { declared: OVERRIDE_SRC.length, compiled: OVERRIDE.length }
};

// Size-cap, then run the SHARED override-verb alias table from data/injection-tells.js. "Set aside your
// safety rules" / "do away with the restrictions" are the same act as "ignore your rules", but the
// drop-rules VERB slot enumerates single words, so a multi-word synonym had the whole attack shape and
// matched nothing. Canonicalising once here reuses that module's vocabulary instead of duplicating it —
// duplicating it in two places is what let the synonym form through in the first place. Content-free:
// the rewritten string is consumed only by the boolean/ID scorers below and never returned.
function cap(text) {
  const s = String(text);
  return canonicalizeOverrideVerbs(s.length > MAX_INPUT ? s.slice(0, MAX_INPUT) : s);
}

// Content-free tell IDs present in a single text (from the fixed TELLS vocabulary — never a span).
export function persuasionTells(text) {
  if (!text || typeof text !== "string") return [];
  const s = cap(text);
  const out = [];
  for (const t of TELLS) if (t.re.test(s)) out.push(t.id);
  return out;
}

// Additive persuasion score for a single text, with ONE exception: tells that carry a group `g` are
// three phrasings of a SINGLE concept, so the group contributes its highest single weight, not the sum.
//
// WHY. The whole model rests on independent signals corroborating each other. `approved-redteam`,
// `licensed-professional` and `authority-role` all say "I have security standing" — scoring them
// additively lets one claim, restated, corroborate ITSELF to a hit. The benign corpus's hn-secr-1 ("I'm
// a security researcher doing an authorized pentest of my own lab…") is precisely that sentence, and
// summing gave it 3. It reaches persuasionHit today only because the persuasion-jailbreak prefilter in
// data/detectors.js happens not to match its wording — measured: widen that prefilter and it becomes a
// 5th corpus FP, breaching the <= 4 gate. Capping the group fixes the cause rather than relying on the
// prefilter's incidental cover.
export function persuasionScore(text) {
  if (!text || typeof text !== "string") return 0;
  const s = cap(text);
  let score = 0;
  const groupMax = new Map();
  for (const t of TELLS) {
    if (!t.re.test(s)) continue;
    if (t.g) groupMax.set(t.g, Math.max(groupMax.get(t.g) || 0, t.w));
    else score += t.w;
  }
  for (const w of groupMax.values()) score += w;
  return score;
}

// The engine-facing predicate: one STRONG tell, or two WEAK tells. Used by the persuasion-jailbreak
// detector's refine() in data/detectors.js.
//
// MEMOISED on the LAST text, the same guard data/injection-tells.js applies to its three predicates and
// for the same reason: src/engine.js::_matchDetector re-invokes refine() for EVERY occurrence of the
// detector's prefilter, always with the same full text. That prefilter is deliberately broad (it matches
// bare "no" / "rules" / "without"), so a 60k pathological input drove hundreds of full re-scores —
// affordable at the old 20-tell table, a measured 136ms -> 426ms engine regression at 35 tells.
// Identical string references compare in O(1), so the repeat calls collapse to a lookup and the scan
// stays linear. Pure: the memo is a cache of a deterministic pure function, and holds no content beyond
// the reference the caller already owns for the duration of one scan.
let lastText = null, lastHit = false;
export function persuasionHit(text) {
  if (text === lastText) return lastHit;
  lastText = text;
  lastHit = persuasionScore(text) >= 2;
  return lastHit;
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
