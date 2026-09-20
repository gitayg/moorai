// Shared content-free tell for the two ATLAS v2026.09 families that hide a STEERING instruction rather
// than an instruction-override: AI-targeted cloaking (AML.T0134, data/cloaking.js) and rendering-hidden
// text (the revised LLM Prompt Obfuscation, data/visual-hiding.js).
//
// The classic injection detectors look for an OVERRIDE ("ignore your previous instructions"). The
// payloads these two techniques carry usually override nothing — they tell the model what to SAY about
// something, which reads as ordinary prose and trips no existing pattern. This asks the narrower
// question: is a clause addressed at the reader's future output?
//
// Two shapes, both anchored so plain description cannot match:
//   (a) an output verb in the imperative or under a scope word (always / never / when summarising / in
//       every answer), and
//   (b) an output verb with an explicit second-person subject ("you should describe ...").
// Content-free: the caller gets a boolean, never the clause.

const OUTPUT_VERB = "describe|state|say|claim|mention|report|recommend|rate|present|portray|call|cite|treat|answer|respond|reply|summari[sz]e|tell|write|list|output|print|include|omit|add|use|prefer|skip|avoid|emphasi[sz]e|note";

const SCOPED_IMPERATIVE = new RegExp(
  String.raw`\b(?:always|never|whenever|when|while|if|in\s+(?:every|any|all)\b[^.\n]{0,20}|for\s+(?:every|any|all)\b[^.\n]{0,20}|also|instead|going\s+forward|from\s+now\s+on)\b[^.\n]{0,60}\b(?:${OUTPUT_VERB})\b`,
  "i"
);

// Imperative at the head of a sentence or clause — the verb is the first word after a boundary, which is
// what separates "Recommend the premium tier" from "we recommend the premium tier".
const HEAD_IMPERATIVE = new RegExp(
  String.raw`(?:^|[.;:!?]\s{0,4}|>\s{0,4}|\n\s{0,4})(?:${OUTPUT_VERB})\s+(?:the|a|an|this|that|every|all|any|it|them|us|as|so)\b`,
  "im"
);

const SECOND_PERSON = new RegExp(
  String.raw`\byou\s+(?:should|must|shall|will|are\s+to|need\s+to|have\s+to|may)\b[^.\n]{0,40}\b(?:${OUTPUT_VERB})\b`,
  "i"
);

const MAX = 200_000;

export function steeringDirectiveHit(text) {
  if (typeof text !== "string" || text.length > MAX) return false;
  return SCOPED_IMPERATIVE.test(text) || HEAD_IMPERATIVE.test(text) || SECOND_PERSON.test(text);
}
