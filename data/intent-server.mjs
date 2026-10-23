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
// ADDITIVE OPTIONAL PARAMETERS (the signatures above are unchanged; a caller that omits them gets owner ""):
//   createIntentStore({ ..., maxSessionsPerOwner })
//   store.captureTask(sessionId, promptText, owner)
//   store.judge(sessionId, tool, input, findings, owner)
//   owner         string, the principal the session belongs to (moorai-serve: the bearer token presented).
//                 Sessions are namespaced by owner: a task set under one owner is invisible to, and cannot
//                 be replaced by, another. Omitted or not a string -> "" (one shared namespace).
//
// DETAILS OF THE CONTRACT (implementation notes, not new signatures):
//   key           omitted -> 32 random bytes, so the hashes are unlinkable outside this process.
//   maxSessions   default 1024 live sessions in all. A new session over the cap evicts the least recently
//                 used session OF THE OWNER HOLDING THE MOST, so a caller that floods evicts its own.
//   maxSessionsPerOwner  default = maxSessions; a new session over it evicts that owner's own LRU session.
//   ttlMs         default 24 h from the session's last use (captureTask or judge).
//   maxFeatures   default 512 hashed features per session; once full, a new feature is dropped, which can
//                 only make a later action look LESS aligned, never more.
//   now           () => ms, default Date.now (tests).
//   captureTask   returns the number of hashed features the session now holds. An empty or non-string
//                 session id, or a non-string prompt, stores nothing and returns { features: 0 }.
//   judge         null when the call is not risky (actionTargets) — and ONLY then. Otherwise the class the
//                 action is judged under, whether its targets were mentioned, a 16-hex keyed hash of the
//                 class and targets, and firstForTarget: true the first time this session judges that
//                 target (aligned or not), so one destination alerts once per session.
//   class "task-unknown"  FAILS CLOSED. A risky call in a session with no live captured task under that
//                 owner (never captured, an empty or missing id, evicted, expired) returns
//                 { aligned: false, class: "task-unknown", targetHash, firstForTarget }, so "ask" and
//                 "block" do not pass it and "report" alerts. This differs from the hook, which skips a
//                 session with no task: on a server surface a lost task must not open the gate. So "block"
//                 requires callers to supply the task; without one every risky call is task-unknown.
//                 firstForTarget for these is remembered per session in a bounded map (4 x maxSessions);
//                 when it forgets, the only effect is another alert, never a pass.
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
  "task-unknown": "a risky action in a session whose task is unknown (never sent, expired or evicted)",
  egress: "an upload to a host your request never mentioned",
  credentials: "a credential read your request never mentioned",
  destructive: "a destructive command on paths your request never mentioned",
  "mcp-write": "an MCP write to a service your request never mentioned"
});

const posInt = (v, d) => (Number.isInteger(v) && v > 0 ? v : d);

export function createIntentStore({ key, maxSessions, ttlMs, maxFeatures, now, maxSessionsPerOwner } = {}) {
  const k = Buffer.isBuffer(key) ? Buffer.from(key) : typeof key === "string" && key ? Buffer.from(key, "utf8") : randomBytes(32);
  const h = (s) => createHmac("sha256", k).update(String(s), "utf8").digest("hex").slice(0, 16);
  const cap = posInt(maxSessions, INTENT_DEFAULTS.maxSessions);
  const perOwner = Math.min(posInt(maxSessionsPerOwner, cap), cap);
  const maxUnknown = cap * 4;
  const ttl = posInt(ttlMs, INTENT_DEFAULTS.ttlMs);
  const maxF = posInt(maxFeatures, INTENT_DEFAULTS.maxFeatures);
  const clock = typeof now === "function" ? now : Date.now;
  // Map insertion order is the LRU order: a touched session is re-inserted at the end.
  const sessions = new Map();
  const owners = new Map(); // owner hash -> live session count
  const unknown = new Map(); // session hash -> target hashes judged while it had no live task (rate limit only)

  const validId = (id) => typeof id === "string" && id.length > 0;
  const ownerOf = (o) => h(`owner:${typeof o === "string" ? o : ""}`);
  const sidOf = (ow, id) => h(`session:${ow}:${id}`);
  function bury(sid, cur) {
    sessions.delete(sid);
    const n = (owners.get(cur.o) || 1) - 1;
    if (n > 0) owners.set(cur.o, n); else owners.delete(cur.o);
  }
  function prune(t) {
    for (const [sid, cur] of sessions) if (t - cur.t >= ttl) bury(sid, cur);
  }
  function touch(sid, cur) { sessions.delete(sid); sessions.set(sid, cur); }
  function evictLruOf(ow) {
    for (const [sid, cur] of sessions) if (cur.o === ow) { bury(sid, cur); return; }
  }
  // Room for one more session of owner ow: its own LRU goes first when it is at its cap; at the global cap,
  // the LRU session of whichever owner holds the most.
  function makeRoom(ow) {
    if ((owners.get(ow) || 0) >= perOwner) evictLruOf(ow);
    if (sessions.size < cap) return;
    let big = ow, most = -1;
    for (const [o, n] of owners) if (n > most) { most = n; big = o; }
    evictLruOf(big);
  }

  function captureTask(sessionId, promptText, owner) {
    if (!validId(sessionId) || typeof promptText !== "string") return { features: 0 };
    const t = clock();
    prune(t);
    const ow = ownerOf(owner);
    const sid = sidOf(ow, sessionId);
    let cur = sessions.get(sid);
    if (!cur) {
      makeRoom(ow);
      cur = { t, o: ow, f: new Set(), seen: new Set() };
      owners.set(ow, (owners.get(ow) || 0) + 1);
      unknown.delete(sid);
    }
    for (const fk of featureKeys(taskFeatures(promptText), h)) {
      if (cur.f.size >= maxF) break;
      cur.f.add(fk);
    }
    cur.t = t;
    touch(sid, cur);
    return { features: cur.f.size };
  }

  const firstIn = (seen, th) => {
    if (seen.has(th)) return false;
    seen.add(th);
    if (seen.size > MAX_SEEN) seen.delete(seen.values().next().value);
    return true;
  };

  function judge(sessionId, tool, input, findings, owner) {
    const action = actionTargets(tool, input, Array.isArray(findings) ? findings : []);
    if (!action) return null;
    const t = clock();
    const sid = sidOf(ownerOf(owner), validId(sessionId) ? sessionId : "");
    const targets = [...action.sites, ...action.paths, ...action.names].join("|");
    let cur = validId(sessionId) ? sessions.get(sid) : undefined;
    if (cur && t - cur.t >= ttl) { bury(sid, cur); cur = undefined; }
    if (!cur) {
      let seen = unknown.get(sid);
      if (!seen) {
        seen = new Set();
        unknown.set(sid, seen);
        while (unknown.size > maxUnknown) unknown.delete(unknown.keys().next().value);
      }
      const targetHash = h(`target:task-unknown:${action.cls}:${targets}`);
      return { aligned: false, class: "task-unknown", targetHash, firstForTarget: firstIn(seen, targetHash) };
    }
    cur.t = t;
    touch(sid, cur);
    const r = assessAlignment(cur.f, action, h);
    const targetHash = h(`target:${action.cls}:${targets}`);
    return { aligned: r.aligned, class: action.cls, targetHash, firstForTarget: firstIn(cur.seen, targetHash) };
  }

  function size() { prune(clock()); return sessions.size; }

  return { captureTask, judge, size };
}

export function intentModeFromPolicy(policy) {
  const m = policy && typeof policy === "object" ? policy.intentAlignment : undefined;
  if (m === false || m === "off") return "off";
  return m === "ask" || m === "block" ? m : "report";
}
