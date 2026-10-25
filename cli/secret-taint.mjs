// #65 — the secrets an agent READ during a session, tracked as keyed fingerprints so a later outbound flow
// that carries one (raw or encoded) is caught even when the value lives in no known secret store.
//
// Two trackers, one shape ({ kr, learn(values), entries() }):
//   sessionTracker   the shell hook: one process per tool call, so the set persists in
//                    ~/.moorai/secret-taint.json (0600) under the device's session key (cli/session-state.mjs
//                    session.key, through one HMAC with a domain label). Per hashed session id: each secret as
//                    its alert hash (the tenant-keyed contentHash that already leaves the device), its learn
//                    time, and its forms as [encoding, length, 20-bit fingerprint, 96-bit HMAC]. No value
//                    and no prefix; the raw form's length is the value's byte length.
//   memoryTracker    a long-lived process (the SDK runtime behind moorai-serve and the model proxy, the MCP
//                    gateway): the same entries in memory under a random per-process key.
//
// TTL: a secret expires `ttlMs` after it was last read (the session-risk window, policy.sessionRisk.windowMin,
// 30 min by default). CAP: at most `cap` secrets per session (64). Past the cap the OLDEST are dropped and
// the newest kept — learning never stops, so the secret just read is always matched — and the learn
// result says `overflow`, which the caller reports once per window as a content-free alert.
// Fail-open on I/O only: an unreadable or oversized state file reads as empty, a write error is swallowed.
// Same trust boundary as every ~/.moorai file: the agent runs as the same user and can read the key.
import { formsOf, ENCODINGS } from "./secret-forms.mjs";
import { keyring, trackForm } from "./secret-match.mjs";
import { contentHash } from "./content-hash.mjs";

export const SECRET_TAINT_FILE = "secret-taint.json";
export const DEFAULT_CAP = 64;
export const DEFAULT_TTL_MS = 30 * 60000;
const MAX_SESSIONS = 16;

// The tracked record of one value: { sid, hash, f: [[encIdx, len, fp, h], ...] }. sid = the raw form's HMAC.
export function recordOf(kr, value, hashFn = contentHash) {
  const f = [];
  for (const { enc, form } of formsOf(value)) {
    const t = trackForm(kr, form);
    if (t) f.push([ENCODINGS.indexOf(enc), t.len, t.fp, t.h]);
  }
  if (!f.length || f[0][0] !== 0) return null;
  return { sid: f[0][3], hash: hashFn(value), f };
}

// Index entries for a list of records: [{ len, fp, h, sid, enc, hash, src }].
export function entriesOf(records, src) {
  const out = [];
  for (const r of records) for (const [ei, len, fp, h] of r.f || []) out.push({ len, fp, h, sid: r.sid, enc: ENCODINGS[ei] || "raw", hash: r.hash, src });
  return out;
}

// Merge freshly read values into a list of { sid, hash, t, f } records: refresh, add, expire, cap.
function merge(kr, list, values, { now, ttlMs, cap, hashFn }) {
  let added = 0, dropped = 0;
  const live = list.filter((r) => r && now - r.t <= ttlMs);
  const bySid = new Map(live.map((r) => [r.sid, r]));
  for (const v of values) {
    const rec = recordOf(kr, v, hashFn);
    if (!rec) continue;
    const prior = bySid.get(rec.sid);
    if (prior) { prior.t = now; continue; }
    const r = { ...rec, t: now };
    bySid.set(r.sid, r);
    live.push(r);
    added++;
  }
  live.sort((a, b) => a.t - b.t);
  if (live.length > cap) { dropped = live.length - cap; live.splice(0, dropped); }
  return { list: live, added, dropped };
}

export function memoryTracker({ key, ttlMs = DEFAULT_TTL_MS, cap = DEFAULT_CAP, hashFn = contentHash } = {}) {
  const kr = keyring(key);
  let list = [];
  let overflowAt = -Infinity;
  return {
    kr,
    learn(values, { now = Date.now(), ttl = ttlMs } = {}) {
      const m = merge(kr, list, values, { now, ttlMs: ttl, cap, hashFn });
      list = m.list;
      const overflow = m.dropped > 0;
      const report = overflow && now - overflowAt > ttl;
      if (report) overflowAt = now;
      return { added: m.added, dropped: m.dropped, overflow, report, size: list.length, cap };
    },
    entries({ now = Date.now(), ttl = ttlMs } = {}) { return entriesOf(list.filter((r) => now - r.t <= ttl), "session-read"); },
    size() { return list.length; }
  };
}

// The hook's persistent tracker for one session. `io` = { read(name), write(name, obj), keyBytes } —
// cli/session-state.mjs in production (see hookTaintIO), injectable for tests.
export function sessionTracker({ sessionId, io, ttlMs = DEFAULT_TTL_MS, cap = DEFAULT_CAP, hashFn = contentHash }) {
  const key = io && io.keyBytes;
  if (!key || !sessionId) return null;
  const kr = keyring(key);
  const sk = kr && trackSessionKey(kr, sessionId);
  const load = () => {
    const raw = io.read(SECRET_TAINT_FILE);
    return raw && raw.v === 1 && raw.s && typeof raw.s === "object" ? raw : { v: 1, s: {} };
  };
  return {
    kr,
    learn(values, { now = Date.now(), ttl = ttlMs } = {}) {
      const st = load();
      const sess = st.s[sk] && typeof st.s[sk] === "object" ? st.s[sk] : { x: [] };
      const m = merge(kr, Array.isArray(sess.x) ? sess.x : [], values, { now, ttlMs: ttl, cap, hashFn });
      const overflow = m.dropped > 0;
      const report = overflow && !(now - (sess.oa || 0) <= ttl);
      st.s[sk] = { t: now, x: m.list, ...(report ? { oa: now } : sess.oa ? { oa: sess.oa } : {}) };
      for (const k of Object.keys(st.s)) if (!st.s[k] || now - (st.s[k].t || 0) > ttl) delete st.s[k];
      const keys = Object.keys(st.s).sort((a, b) => st.s[b].t - st.s[a].t);
      for (const k of keys.slice(MAX_SESSIONS)) delete st.s[k];
      if (m.added || m.dropped || values.length) io.write(SECRET_TAINT_FILE, st);
      return { added: m.added, dropped: m.dropped, overflow, report, size: m.list.length, cap };
    },
    entries({ now = Date.now(), ttl = ttlMs } = {}) {
      const sess = load().s[sk];
      const list = sess && Array.isArray(sess.x) ? sess.x.filter((r) => r && now - r.t <= ttl) : [];
      return entriesOf(list, "session-read");
    }
  };
}

// The state-file key of a session id: an HMAC under the tracker's key, never the id itself.
function trackSessionKey(kr, sessionId) {
  return trackForm(kr, `session:${String(sessionId).padEnd(8, " ")}`).h;
}
