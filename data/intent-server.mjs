// Intent alignment for server surfaces (model proxy, moorai-serve sidecar, Agent SDK): in-memory,
// per-session state over the pure logic in data/intent-alignment.js. FROZEN CONTRACT (stub) —
// implemented on feat/servers-intent-sdk; consumed by model-proxy on feat/servers-proxy.
//
// createIntentStore({ key, maxSessions, ttlMs, maxFeatures, now }) -> store
//   key          Buffer|string, HMAC key for feature hashes (never leaves the process)
//   store.captureTask(sessionId, promptText)          -> { features: number }   (prompt held in memory only for the call)
//   store.judge(sessionId, tool, input, findings)     -> null | { aligned: boolean, class: string, targetHash: string, firstForTarget: boolean }
//   store.size()                                      -> number of sessions held
// intentModeFromPolicy(policy) -> "off" | "report" | "ask" | "block"   (policy.intentAlignment; default "report")
export function createIntentStore() {
  throw new Error("intent-server: not implemented");
}
export function intentModeFromPolicy() {
  throw new Error("intent-server: not implemented");
}
