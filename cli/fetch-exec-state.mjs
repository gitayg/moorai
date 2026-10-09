// Fetch-then-execute ACROSS tool calls (#57). The single-command detector (data/detectors-net-exec.js)
// sees `curl -o /tmp/u.sh … && bash /tmp/u.sh`; an agent that downloads in one Bash call and runs the file
// in the next shows each call a harmless half. So the hook records, per session, which files a Bash call
// downloaded, and a later call of the same session that runs one of them gets #57.
//
// WHAT IS STORED (~/.moorai/fetch-exec.json, mode 0600, via cli/session-state.mjs): per keyed session id,
// a list of [keyed hash, time]. Each hash is HMAC(session.key, "fx-f:" + path) for a downloaded file, or
// "fx-d:" + directory for a download directory (wget -P, curl --output-dir). The path is the normalised
// absolute path (data/net-exec.js normPath against the call's cwd, `~` expanded, lowercased on Windows),
// so `cd /tmp && curl -O …/i.sh` then `bash /tmp/i.sh` matches. NEVER STORED: a path, a URL or a command.
//
// BOUNDS, chosen: 64 entries per session (oldest dropped first), 32 sessions (least recently active
// evicted), and 24 h per entry — the same session count and lifetime the session-risk and circuit-breaker
// state use. The gap this closes is seconds to minutes between the two calls; 24 h leaves room for a
// long agent session without keeping a record of a day-old download. File reads over 1 MiB read as empty.
//
// Fail-open like the rest of session state: a missing or unreadable file means "nothing recorded", every
// write error is swallowed, and parallel hook calls can lose one another's update (one observation).
// WHAT THIS DOES NOT DEFEND: the agent runs as the same user and can delete or edit the file, or copy the
// downloaded file to a new name before running it (the copy is not tracked).
import { readSessionState, writeSessionState, sessionKeyedHash } from "./session-state.mjs";
import { dirOf } from "../data/net-exec.js";

export const FETCH_EXEC_FILE = "fetch-exec.json";
export const FETCH_EXEC_LIMITS = Object.freeze({ sessions: 32, perSession: 64, ttlMs: 24 * 3600 * 1000 });

const live = (rec, now) => (rec && Array.isArray(rec.f) ? rec.f.filter((e) => Array.isArray(e) && typeof e[0] === "string" && typeof e[1] === "number" && now - e[1] <= FETCH_EXEC_LIMITS.ttlMs && e[1] <= now + 60000) : []);

// Does a path this call runs name a file (or a file in a directory) an earlier call of the session
// downloaded?
export function fetchedExecHit({ sessionId, executed, now = Date.now() }) {
  try {
    if (!sessionId || !Array.isArray(executed) || !executed.length) return false;
    const sk = sessionKeyedHash(`fx:${sessionId}`);
    const state = readSessionState(FETCH_EXEC_FILE);
    if (!sk || !state) return false;
    const seen = new Set(live(state[sk], now).map((e) => e[0]));
    if (!seen.size) return false;
    return executed.some((p) => seen.has(sessionKeyedHash(`fx-f:${p}`)) || seen.has(sessionKeyedHash(`fx-d:${dirOf(p)}`)));
  } catch { return false; }
}

// Record what this call downloaded: [{ kind: "f"|"d", path }] from data/net-exec.js fetchExecFacts.
export function recordFetched({ sessionId, fetched, now = Date.now() }) {
  try {
    if (!sessionId || !Array.isArray(fetched) || !fetched.length) return;
    const sk = sessionKeyedHash(`fx:${sessionId}`);
    if (!sk) return;
    const prev = readSessionState(FETCH_EXEC_FILE) || {};
    const state = {};
    for (const [k, rec] of Object.entries(prev)) { const f = live(rec, now); if (f.length) state[k] = { t: typeof rec.t === "number" ? rec.t : 0, f }; }
    const rec = state[sk] || { t: now, f: [] };
    for (const x of fetched) {
      const hash = sessionKeyedHash(`fx-${x.kind === "d" ? "d" : "f"}:${x.path}`);
      if (!hash) continue;
      rec.f = rec.f.filter((e) => e[0] !== hash);
      rec.f.push([hash, now]);
    }
    rec.f = rec.f.slice(-FETCH_EXEC_LIMITS.perSession);
    rec.t = now;
    state[sk] = rec;
    const keys = Object.keys(state).sort((a, b) => state[b].t - state[a].t);
    for (const k of keys.slice(FETCH_EXEC_LIMITS.sessions)) delete state[k];
    writeSessionState(FETCH_EXEC_FILE, state);
  } catch { /* best-effort; never affects the decision */ }
}
