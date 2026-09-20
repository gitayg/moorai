// AML.T0133 — Discover AI Agent Runtime Capabilities. The attacker learns which tools an agent holds
// and how far its permissions reach simply by asking it, then shapes the next stage around the answer.
//
// THE PRECISION DECISION IS THE STAGE, NOT THE PATTERN. "What tools do you have?" is a completely
// normal thing for a developer to type at their own agent, and any pattern that catches the attack also
// catches that. So this tell is wired to the INGEST stages only (file / index / output / tool): the same
// sentence is recon when it arrives inside a fetched page, a repository file or a tool result, because
// nobody in the conversation asked it. The prompt stage is deliberately not covered — see the detector.
//
// Two shapes:
//   (a) an enumerate verb whose object is bound to the AGENT — "your tools", "tools you have access to",
//       "commands you are permitted to run". The binding is what keeps ordinary documentation out:
//       "list the permissions your integration requires" has no such binding.
//   (b) the interrogative form — "which file paths are you permitted to read?".
// Content-free: the caller gets a boolean.

const ENUMERATE = "list|enumerate|print|output|report|echo|dump|disclose|state|name|describe|tell|reply\\s+with|respond\\s+with|show|give";

// Nouns that only matter when they are the agent's own.
const CAPABILITY = "tools?|functions?|capabilit(?:y|ies)|permissions?|scopes?|entitlements?|privileges?|commands?|tool\\s+registry|tool\\s+list|file\\s+paths?|directories|mcp\\s+servers?";

// The agent-binding: "your <noun>", or "<noun> ... you <modal>".
const BOUND = new RegExp(
  String.raw`\byour\s+(?:own\s+|current\s+|available\s+|active\s+|registered\s+|full\s+|complete\s+)*(?:${CAPABILITY})\b` +
  String.raw`|\b(?:${CAPABILITY})\b[^.\n]{0,24}\byou\s+(?:currently\s+|now\s+|already\s+|actually\s+)?(?:have|hold|can|are|may|possess)\b` +
  String.raw`|\bmcp\s+(?:tools?|servers?)\b[^.\n]{0,24}\b(?:available|connected|you)\b`,
  "i"
);

const ENUMERATE_RE = new RegExp(String.raw`\b(?:${ENUMERATE})\b`, "i");

const INTERROGATIVE = new RegExp(
  String.raw`\b(?:which|what)\s+(?:${CAPABILITY})\s+(?:are|can|do|is)\s+you\b` +
  String.raw`|\b(?:which|what)\s+(?:${CAPABILITY})\b[^?\n]{0,40}\bare\s+you\s+(?:allowed|permitted|able)\b`,
  "i"
);

const MAX = 200_000;
const WINDOW = 60;

function scanAgentReconHit(text) {
  if (typeof text !== "string" || text.length > MAX) return false;
  if (INTERROGATIVE.test(text)) return true;
  // An enumerate verb within a bounded window before the agent-bound capability noun. Scanning the
  // window rather than the whole text is what stops a verb in one paragraph pairing with a noun in
  // another.
  const g = new RegExp(BOUND.source, "gi");
  let m;
  while ((m = g.exec(text)) !== null) {
    const start = Math.max(0, m.index - WINDOW);
    if (ENUMERATE_RE.test(text.slice(start, m.index + m[0].length))) return true;
    if (m.index === g.lastIndex) g.lastIndex++;
  }
  return false;
}

// Memoised on the last text, for the reason data/obfuscation-signal.js gives: _matchDetector re-invokes
// refine() once per prefilter occurrence, and the prefilter here is deliberately cheap and broad.
let lastText = null, lastHit = false;
export function agentReconHit(text) {
  if (text === lastText) return lastHit;
  lastText = text;
  lastHit = scanAgentReconHit(text);
  return lastHit;
}
