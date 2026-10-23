// A test double for data/intent-server.mjs that honours its frozen contract:
//   createIntentStore({ key, maxSessions, ttlMs, maxFeatures, now }) → { captureTask, judge, size }
//   intentModeFromPolicy(policy) → "off" | "report" | "ask" | "block" (policy.intentAlignment, default "report")
// Deliberately small: a task's "features" are the dotted host names it mentions; a Bash command with an
// http(s) URL is an egress call, aligned iff its host was mentioned in the session's captured task. Every call
// is recorded, so a test can see exactly which texts were captured as the task.
import { createHash } from "node:crypto";

export function createFakeIntentLib() {
  const calls = { capture: [], judge: [], created: [] };
  return {
    calls,
    createIntentStore(opts) {
      calls.created.push({ keyBytes: Buffer.from(opts.key).length, maxSessions: opts.maxSessions, ttlMs: opts.ttlMs, maxFeatures: opts.maxFeatures });
      const sessions = new Map();
      return {
        captureTask(sessionId, promptText) {
          calls.capture.push({ sessionId, promptText });
          const s = sessions.get(sessionId) || { hosts: new Set(), seen: new Set() };
          for (const m of String(promptText).matchAll(/\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/gi)) s.hosts.add(m[1].toLowerCase());
          sessions.set(sessionId, s);
          return { features: s.hosts.size };
        },
        judge(sessionId, tool, input, findings) {
          calls.judge.push({ sessionId, tool, findings });
          const s = sessions.get(sessionId);
          if (!s) return null;
          const m = tool === "Bash" ? /https?:\/\/([^/\s"']+)/.exec(String((input && input.command) || "")) : null;
          if (!m) return null;
          const host = m[1].toLowerCase();
          const aligned = s.hosts.has(host);
          const targetHash = createHash("sha256").update(`egress:${host}`).digest("hex").slice(0, 16);
          const firstForTarget = !aligned && !s.seen.has(targetHash);
          if (firstForTarget) s.seen.add(targetHash);
          return { aligned, class: "egress", targetHash, firstForTarget };
        },
        size: () => sessions.size
      };
    },
    intentModeFromPolicy(policy) {
      const m = policy && policy.intentAlignment;
      return m === "off" || m === "ask" || m === "block" ? m : "report";
    }
  };
}
