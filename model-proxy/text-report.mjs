// The content-free alert and the refusal text for a finding in the model's reply text (response-scan.mjs).
// The alert carries the threat id, a fixed category, the risk level, the class, the configured and the applied
// mode, how much of the match had already been passed on when it was found (sent: none | partial | all), and
// contentHash: the tenant-keyed hash of the matched text (for a system-prompt echo, of the run's first keyed
// shingle). Never the text, the match, the system prompt or a position in either.
import { REASON, ENFORCEMENT } from "../cli/provenance.mjs";
import { CLASSES } from "./response-scan.mjs";

const LABEL = { 39: "secret or credential", 1: "payment-card data", 15: "personal data", 52: "system prompt" };
export const textCategory = (id) => (id === 52 ? "Model proxy: system prompt reproduced in the model's reply" : `Model proxy: ${LABEL[id] || "sensitive data"} in the model's reply`);

// mode: what was applied (report unless --mode enforce); configured: the policy's responseScan.
export function textAlert({ id, hash, sent, mode, configured, enforce, riskLevel }) {
  const a = {
    threatId: id, category: textCategory(id), riskLevel: mode === "block" ? "Blocked" : riskLevel, stage: "output", tool: "model-proxy:response-text",
    decision: configured === "block" ? "deny" : "notify", contentHash: hash, responseScan: { class: CLASSES[id] || "unknown", mode: configured, applied: mode, sent }
  };
  if (mode === "mask") a.reasonCode = REASON.MASK_APPLIED;
  else if (configured === "report") a.reasonCode = REASON.OBSERVATION_ONLY;
  // Configured to mask or block but not applied (--mode report): weaker than configured.
  if (!enforce && configured !== "report") a.enforcement = ENFORCEMENT.LIMITED;
  return a;
}

export function textRefusal(id) {
  return `MoorAI model-proxy refused this response — the model's reply contains ${LABEL[id] || "sensitive data"} (#${id}, responseScan block)`;
}
