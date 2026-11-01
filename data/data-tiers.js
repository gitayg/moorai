// Sensitive-data classification tiers. Each tier groups the threat ids that carry that class of
// data, so an admin can set one default action per tier (policy.tierPolicy) instead of tuning every
// detector. A per-threat action still overrides the tier default — nothing existing is lost.
export const DATA_TIERS = {
  pii: [15],          // emails, phone, national ID, passport — personal data
  secret: [39],       // API keys, tokens, private keys
  source: [9],        // IP: roadmap, architecture, source, trade secrets
  regulated: [1, 44, 90]  // payment-card / PCI (#90 cards, #1 IBAN), PHI / HIPAA
};

// Reverse index: threatId → tier.
export const TIER_OF = Object.fromEntries(
  Object.entries(DATA_TIERS).flatMap(([tier, ids]) => ids.map((id) => [id, tier]))
);

export const TIER_LABELS = { pii: "PII", secret: "Secrets", source: "Source / IP", regulated: "Regulated (PHI/PCI)" };
