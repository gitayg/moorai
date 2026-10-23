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
//
// DETAILS OF THE CONTRACT ABOVE (implementation notes, not new signatures):
//   key           omitted -> 32 random bytes, so the hashes are unlinkable outside this process.
//   maxSessions   default 1024; least recently used first out (captureTask and judge both count as use).
//   ttlMs         default 24 h, measured from the session's last captureTask (a task has an age).
//   maxFeatures   default 512 hashed features per session; once full, a new feature is dropped, which can
//                 only make a later action look LESS aligned, never more.
//   now           () => ms, default Date.now (tests).
//   captureTask   returns the number of hashed features the session now holds. An empty or non-string
//                 session id, or a non-string prompt, stores nothing and returns { features: 0 }.
//   judge         null when the call is not risky (actionTargets), or when the session has no captured
//                 task — it never judges against nothing, as the hook does not. Otherwise the class the
//                 action is judged under, whether its targets were mentioned, a 16-hex keyed hash of the
//                 class and targets, and firstForTarget: true the first time this session judges that
//                 target (aligned or not), so one destination alerts once per session.
// WHAT IS HELD: per session (its id HMAC'd too), the last-capture time, the HMACs of the task's derived
// features (data/intent-alignment.js taskFeatures/featureKeys) and the HMACs of the targets judged. Never
// the prompt, an excerpt of it, a plaintext feature, a tool argument or a session id.
// LIMITS (the hook's, unchanged): lexical — "did the user name this destination, file or service", not
// "does this action serve the task"; a request pasted from an untrusted source puts its hosts in scope.
import { createHmac, randomBytes } from "node:crypto";
import { taskFeatures, featureKeys, actionTargets, assessAlignment } from "./intent-alignment.js";

export const INTENT_DEFAULTS = Object.freeze({ maxSessions: 1024, ttlMs: 24 * 3600 * 1000, maxFeatures: 512 });
const MAX_SEEN = 64;
export const INTENT_MODES = Object.freeze(["off", "report", "ask", "block"]);
// The category every surface files a misaligned action under (cli/moorai-hook.mjs intentStep;
// cli/provenance.mjs maps it to REASON.INTENT_MISMATCH), and the content-free reason text per class.
export const INTENT_CATEGORY = "Action outside the stated task";
export const INTENT_CLASS_TEXT = Object.freeze({
  egress: "an upload to a host your request never mentioned",
  credentials: "a credential read your request never mentioned",
  destructive: "a destructive command on paths your request never mentioned",
  "mcp-write": "an MCP write to a service your request never mentioned"
});

const posInt = (v, d) => (Number.isInteger(v) && v > 0 ? v : d);

export function createIntentStore({ key, maxSessions, ttlMs, maxFeatures, now } = {}) {
  const k = Buffer.isBuffer(key) ? Buffer.from(key) : typeof key === "string" && key ? Buffer.from(key, "utf8") : randomBytes(32);
  const h = (s) => createHmac("sha256", k).update(String(s), "utf8").digest("hex").slice(0, 16);
  const cap = posInt(maxSessions, INTENT_DEFAULTS.maxSessions);
  const ttl = posInt(ttlMs, INTENT_DEFAULTS.ttlMs);
  const maxF = posInt(maxFeatures, INTENT_DEFAULTS.maxFeatures);
  const clock = typeof now === "function" ? now : Date.now;
  // Map insertion order is the LRU order: a touched session is re-inserted at the end.
  const sessions = new Map();

  const validId = (id) => typeof id === "string" && id.length > 0;
  function prune(t) {
    for (const [sid, cur] of sessions) if (t - cur.t >= ttl) sessions.delete(sid);
  }
  function touch(sid, cur) { sessions.delete(sid); sessions.set(sid, cur); }

  function captureTask(sessionId, promptText) {
    if (!validId(sessionId) || typeof promptText !== "string") return { features: 0 };
    const t = clock();
    prune(t);
    const sid = h(`session:${sessionId}`);
    const cur = sessions.get(sid) || { t, f: new Set(), seen: new Set() };
    for (const fk of featureKeys(taskFeatures(promptText), h)) {
      if (cur.f.size >= maxF) break;
      cur.f.add(fk);
    }
    cur.t = t;
    touch(sid, cur);
    while (sessions.size > cap) sessions.delete(sessions.keys().next().value);
    return { features: cur.f.size };
  }

  function judge(sessionId, tool, input, findings) {
    if (!validId(sessionId)) return null;
    const action = actionTargets(tool, input, Array.isArray(findings) ? findings : []);
    if (!action) return null;
    const sid = h(`session:${sessionId}`);
    const cur = sessions.get(sid);
    if (!cur) return null;
    if (clock() - cur.t >= ttl) { sessions.delete(sid); return null; }
    touch(sid, cur);
    const r = assessAlignment(cur.f, action, h);
    const targetHash = h(`target:${action.cls}:${[...action.sites, ...action.paths, ...action.names].join("|")}`);
    const firstForTarget = !cur.seen.has(targetHash);
    if (firstForTarget) {
      cur.seen.add(targetHash);
      if (cur.seen.size > MAX_SEEN) cur.seen.delete(cur.seen.values().next().value);
    }
    return { aligned: r.aligned, class: action.cls, targetHash, firstForTarget };
  }

  function size() { prune(clock()); return sessions.size; }

  return { captureTask, judge, size };
}

export function intentModeFromPolicy(policy) {
  const m = policy && typeof policy === "object" ? policy.intentAlignment : undefined;
  if (m === false || m === "off") return "off";
  return m === "ask" || m === "block" ? m : "report";
}
