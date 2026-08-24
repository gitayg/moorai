// Skill Analysis — content-free INTENT labels for a file on the agent's skill surface.
//
// The question a rules-file poisoning alert cannot answer is "what does this thing actually tell my
// agent to do?". Answering it normally means shipping the file somewhere to be read, which is the one
// thing MoorAI will not do. So intent is reported as a small, fixed VOCABULARY of category labels
// derived from findings the detection engine has ALREADY produced for that file, plus two host-level
// shape checks that reuse the endpoint extractor. No text, no matched span, no excerpt.
//
// THERE IS NO SECOND DETECTION ENGINE HERE. Every label below is a rename of an existing threat id
// (data/detectors.js), of an existing content tell (data/agent-behavior.js), or of an existing host
// extraction (data/model-endpoints.js). Adding a regex here would fork the engine, and a forked engine
// is one that drifts out of policy control — threatActionFor/detectorPacks would not reach it.
//
// The consequence, stated rather than hidden: intent coverage is exactly detector coverage. An
// instruction the engine has no detector for produces no label. "No labels" therefore means "nothing
// the engine recognizes", NOT "benign".
import { contentTells } from "../data/agent-behavior.js";
import { extractHosts, extractEndpointHosts } from "../data/model-endpoints.js";

// threat id → intent label. Only ids whose meaning survives the reframe from "prompt" to "instruction
// file" are mapped; a DLP hit (an email address in a CLAUDE.md) is a privacy finding, not an intent,
// and is deliberately absent so the intent list stays a list of things the file TELLS THE AGENT TO DO.
const INTENT_BY_THREAT = {
  2: "instructs-exfiltration",
  3: "instruction-override",
  40: "hidden-instructions",
  50: "invisible-characters",
  51: "system-prompt-extraction",
  39: "references-credentials",
  55: "reads-credential-files",
  43: "destructive-command",
  54: "reverse-shell",
  57: "untrusted-install",
  62: "typosquat-install",
  46: "security-control-or-privilege-change",
  47: "external-communication",
  48: "creates-credentials",
  49: "production-deploy",
  63: "model-endpoint-override"
};

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1", "0.0.0.0"]);

// Findings are the ones decideText already produced for this file; text is used only for the two
// host-level checks and the content tells, and is never retained or returned.
export function skillIntents(text, findings) {
  const out = new Set();
  for (const f of findings || []) {
    const label = INTENT_BY_THREAT[f.threatId];
    if (label) out.add(label);
  }
  const tells = contentTells(text || "");
  if (tells.obfuscation) out.add("obfuscated-payload");
  if (tells.opsecArtifact) out.add("embedded-key-material");
  if (extractEndpointHosts(text || "").length) out.add("model-endpoint-override");
  if (extractHosts(text || "").some((h) => !LOOPBACK.has(h))) out.add("external-network-egress");
  return [...out].sort();
}

// The vocabulary itself, so the console and the docs can enumerate it without importing the mapping.
export const INTENT_LABELS = [...new Set([...Object.values(INTENT_BY_THREAT), "obfuscated-payload", "embedded-key-material", "external-network-egress"])].sort();
