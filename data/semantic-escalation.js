// #21 — policy dimension for opportunistic semantic escalation. Same convention as capture-tiers.js /
// data-tiers.js: a small, shared-identically module that defines the allowed values, the default, and a
// resolver, so the agent and the console agree on the flag. Enforcement is unchanged by this flag —
// regex/entropy still owns the allow/deny decision; the model is only ever a bounded second opinion.
//
// policy.semanticEscalation values:
//   "off"      — DEFAULT. No model is ever consulted. Zero cost, zero extra egress. (Absent / unknown
//                value / false also resolve to "off".)
//   "local"    — only the on-device loopback model (Ollama on 127.0.0.1) may be consulted. Zero egress.
//   "provider" — local first, else the agent's OWN provider key already on the device (the disclosed
//                device-inference path). No key → no provider call. No NEW third party, no NEW egress.
// A bare boolean `true` resolves to the most privacy-preserving enabled mode ("local"), so opting in
// with `true` never silently turns on provider egress.
export const SEMANTIC_MODES = ["off", "local", "provider"];
export const SEMANTIC_DEFAULT = "off";

export function semanticMode(policy) {
  const m = policy && policy.semanticEscalation;
  if (m === true) return "local";
  return SEMANTIC_MODES.includes(m) ? m : SEMANTIC_DEFAULT;
}

export function semanticEnabled(policy) {
  return semanticMode(policy) !== "off";
}
