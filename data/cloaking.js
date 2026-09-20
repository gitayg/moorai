// AML.T0134 — AI Targeted Cloaking. A page serves one thing to a browser and another to an AI client,
// so the instructions the agent acts on are never the ones a reviewer sees.
//
// WHAT AN ENDPOINT GUARD CAN AND CANNOT SEE. The technique's defining act — the SERVER branching on
// User-Agent — is invisible from here: MoorAI sees exactly one response, the one the agent received, and
// proving divergence would mean re-fetching the page as a browser, which is egress this product does not
// do. So the differential itself is out of scope and is not claimed.
//
// What IS in the response, and is the reason the content was cloaked in the first place, is the block
// addressed at the machine reader. This asks for two things together:
//   1. an AI/agent-EXCLUSIVE audience marker — the text speaks to the model as the model, or declares a
//      section that only an automated reader is meant to see;
//   2. a payload that either contradicts the visible content (the cloaking half) or steers the agent's
//      output (data/steering-tells.js).
// Marker 1 alone is ordinary and friendly: "if you are an AI assistant, our OpenAPI spec is easier to
// parse" is a helpful sentence on a real docs site, and it must stay silent.
// Content-free: the caller gets a boolean.
import { steeringDirectiveHit } from "./steering-tells.js";

const AUDIENCE = [
  /\bif\s+you(?:'re|\s+are)\b[^.\n]{0,30}\b(?:an?\s+)?(?:ai|llm|language\s+model|assistant|agent|bot|crawler|automated)\b/i,
  /\b(?:when|while)\s+you\s+are\s+(?:an?\s+)?(?:ai|llm|language\s+model|assistant|agent|bot)\b/i,
  /\bnote\s+to\s+(?:any\s+)?(?:ai|llm|language\s+model|assistant|agent|bot)s?\b/i,
  /\b(?:for|to)\s+(?:ai|llm|bots?|agents?|crawlers?|machines?|automated\s+(?:readers?|agents?|clients?|systems?))\b[^.\n]{0,20}\bonly\b/i,
  /\b(?:agent|ai|llm|bot|machine|model)[-_]only\b/i,
  /\brendered\s+only\s+for\s+(?:automated|ai|llm|bots?|agents?|machines?)\b/i,
  /\b(?:automated\s+(?:readers?|agents?|clients?)|ai\s+(?:agents?|clients?|assistants?)|language\s+models?|crawlers?)\s+(?:should|must|may|will|are\s+(?:to|required|instructed))\b/i
];

// The cloaking half: the block tells the agent that what a human sees is not what it should use.
const DIVERGENCE = [
  /\b(?:disregard|ignore|override)\b[^.\n]{0,40}\b(?:above|below|visible|shown|preceding|page|section|table|documentation|content)\b/i,
  /\b(?:instead|rather\s+than)\b[^.\n]{0,40}\b(?:above|visible|shown|page|documentation|content|section)\b/i,
  /\b(?:the\s+)?(?:content|copy|page|text|version|values?|instructions?)\s+(?:shown|displayed|rendered|served)\s+to\s+(?:browsers?|humans?|users?|visitors?)\b/i,
  /\b(?:outdated|out\s+of\s+date|legacy\s+copy|superseded|no\s+longer\s+accurate)\b[^.\n]{0,40}\b(?:use|follow|treat|the\s+real|instead)\b/i,
  /\b(?:treat|regard|consider)\b[^.\n]{0,40}\bas\s+(?:outdated|obsolete|legacy|incorrect|superseded)\b/i,
  /\bthe\s+real\s+(?:install|command|instructions?|steps?|values?|price|endpoint)\b/i,
  /\bdo\s+not\s+(?:mention|tell|reveal|disclose|show|surface)\b[^.\n]{0,30}\b(?:this|the\s+(?:user|human|reader|notice))\b/i,
  /\binstead\s+(?:fetch|use|follow|read|load|retrieve|refer|consult|download|visit|open)\b/i,
  // The split-audience sentence pair — one instruction for people, another for machines — is the shape
  // the technique is named for, and the two halves sit in separate sentences, so this window crosses the
  // full stop the others deliberately do not.
  /\bhuman\s+(?:visitors?|readers?|users?|beings?)\b[\s\S]{0,160}?\b(?:automated|ai|llm|bots?|agents?|crawlers?|machines?)\b[^\n]{0,60}\b(?:instead|should|must|are\s+to)\b/i
];

const MAX = 200_000;
const any = (list, t) => list.some((re) => re.test(t));

function scanAiTargetedCloakingHit(text) {
  if (typeof text !== "string" || text.length > MAX) return false;
  if (!any(AUDIENCE, text)) return false;
  return any(DIVERGENCE, text) || steeringDirectiveHit(text);
}

// Memoised on the last text, for the reason data/obfuscation-signal.js gives: _matchDetector re-invokes
// refine() once per prefilter occurrence, and the prefilter here is deliberately cheap and broad.
let lastText = null, lastHit = false;
export function aiTargetedCloakingHit(text) {
  if (text === lastText) return lastHit;
  lastText = text;
  lastHit = scanAiTargetedCloakingHit(text);
  return lastHit;
}
