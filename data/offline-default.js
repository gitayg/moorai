// Break-glass / offline fail-closed (#33) — the conservative built-in policy applied ONLY when the
// device is offline AND there is no cached policy at all AND the durable last-known posture is
// "fail-closed". It is deliberately small and reviewable: an org that opted into fail-closed still gets
// sensible, content-free enforcement when it cannot reach the policy server. It is NEVER used for a
// device whose posture is "fail-open" (the default) — that path stays exactly as before (exit 0/allow).
//
// What it enforces (via the same policy mechanism as a real policy — no special engine path):
//   - block   secrets / PII / regulated-data egress   (threats 39, 15, 1, 44)
//   - justify destructive commands                    (threat 43 — also the built-in default anyway)
//   - justify (ask) on every MCP tool-call            (mcpFloor: raises an otherwise-allowed call to ask)
// Benign reads / commands still resolve to allow — fail-closed hardens the high-risk categories, it does
// not brick the workflow. Content-free throughout: the capture tier is pinned to "content-free".
export const OFFLINE_DEFAULT_POLICY = {
  offlineMode: "fail-closed",
  captureTier: "content-free",
  builtinDefault: true, // content-free provenance marker — used only for labels/signals, never enforcement
  mcpFloor: "ask",      // fail-closed MCP floor: every MCP tool-call needs justification unless already denied
  threatPolicy: {
    39: "block",   // Secrets — API keys, tokens, private keys
    15: "block",   // PII — email, phone, national ID, passport
    1: "block",    // Payment-card data / PCI
    44: "block",   // PHI / HIPAA
    43: "justify"  // Destructive / delete commands (43 already defaults to justify; explicit for review)
  }
};
