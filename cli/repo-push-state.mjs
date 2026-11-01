// The hook's half of cli/repo-push.mjs: remotes the agent added or re-pointed in an earlier call of the same
// session, so `git remote add x <url>` in one call and `git push x` in the next is judged as a push to <url>.
//
// WHAT IS STORED (~/.moorai/repo-push.json, mode 0600, via cli/session-state.mjs): { v: 1, r: { hash: time } },
// each hash HMAC(session.key, "rp:" + session + repository root + remote name). 256 entries, 24 h. NEVER
// STORED: a URL, a remote name, a path or a command.
//
// Recorded on PreToolUse whatever the call's verdict: a record only makes a later push stricter. Fail-open
// like the rest of session state. WHAT THIS DOES NOT DEFEND: the agent runs as the same user and can delete
// the file, which loses the record of the remotes it added (their pushes are then judged as pushes to a
// configured remote, and pass).
import { readSessionState, writeSessionState, sessionKeyedHash } from "./session-state.mjs";
import { repoPushVerdict } from "./repo-push.mjs";

export const REPO_PUSH_FILE = "repo-push.json";
const TTL = 24 * 3600 * 1000, MAX = 256;
const HINT = /\bgit\b|\bgh\b/;

export function repoPushStep({ policy, sessionId, command, ps = false, cwd = "", now = Date.now() } = {}) {
  try {
    if (typeof command !== "string" || !HINT.test(command)) return { hits: [] };
    const prev = readSessionState(REPO_PUSH_FILE);
    const rec = {};
    if (prev && prev.r && typeof prev.r === "object") for (const [k, t] of Object.entries(prev.r)) if (typeof t === "number" && now - t <= TTL && t <= now + 60000) rec[k] = t;
    const key = (root, name) => sessionKeyedHash(`rp:${sessionId || ""}\n${root}\n${name}`);
    const added = (root, name) => { const k = key(root, name); return !!k && k in rec; };
    const v = repoPushVerdict({ command, ps, cwd, policy, added });
    if (v.remotes.length) {
      for (const r of v.remotes) { const k = key(r.root, r.name); if (k) rec[k] = now; }
      const ks = Object.keys(rec);
      if (ks.length > MAX) for (const k of ks.sort((a, b) => rec[a] - rec[b]).slice(0, ks.length - MAX)) delete rec[k];
      writeSessionState(REPO_PUSH_FILE, { v: 1, r: rec });
    }
    return { hits: v.hits };
  } catch { return { hits: [] }; }
}
