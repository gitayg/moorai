// #90 — cardholder data (a payment-card number, a card security code). Its detectors (dlp-payment-card,
// pci-cvv) reported as #1 until v1.43.0; #1 keeps the IBAN and clipboard-to-sink findings.
//
// POLICY. A signed policy written before #90 existed says what to do with cards through threatPolicy[1]. So a
// policy that sets threatPolicy[1] and not threatPolicy[90] gives #90 the same action (threatPolicyEntry);
// one that sets threatPolicy[90] decides #90 alone. #90 sits in the same data tier as #1 (data/data-tiers.js
// "regulated"), so tierPolicy treats both alike, and neither has a built-in default, so both default to notify.
//
// EVIDENCE. A card number is drawn from a small space (16 digits less the Luhn check digit and the issuer
// ranges), so a hash keyed with the tenant's install token can be enumerated back to the number by anyone who
// holds the token, the console included. A #90 finding therefore never carries the matched text or the
// argument text, at any capture tier (data/capture-tiers.js NO_SPAN_TEXT_THREATS, kept self-contained because
// the console holds an identical copy of that file), and its contentHash is an HMAC under a key
// random to the process that computed it (cli/span-hash.mjs, "proc:" and 16 hex), as the model proxy already
// does for a card or personal data in a reply.
export const CARD_THREAT = 90;
export const CARD_POLICY_FALLBACK = 1;

// Threats whose span hash is process-keyed.
export const PROCESS_KEYED_THREATS = Object.freeze([CARD_THREAT]);

// The policy's own threatPolicy entry for `id`; for #90 with none, the entry for #1.
export function threatPolicyEntry(policy, id) {
  const tp = policy && policy.threatPolicy;
  if (!tp || typeof tp !== "object") return undefined;
  const own = tp[id];
  if (own || Number(id) !== CARD_THREAT) return own;
  return tp[CARD_POLICY_FALLBACK];
}
