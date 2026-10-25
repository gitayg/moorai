// #65 — the secrets an agent READ during a session, tracked as keyed fingerprints so a later outbound flow
// that carries one (raw or encoded) is caught even when the value lives in no known secret store.
//
// Two trackers, one shape ({ kr, learn(values, { cred }), entries(), overflowed() }):
//   sessionTracker   the shell hook: one process per tool call, so the set persists in
//                    ~/.moorai/secret-taint.json (0600) under the device's session key (cli/session-state.mjs
//                    session.key, through one HMAC with a domain label). Per hashed session id: each secret as
//                    its alert hash (the tenant-keyed contentHash that already leaves the device), its learn
//                    time, its pool, and its forms as [encoding, length, 20-bit fingerprint, 96-bit HMAC]. No
//                    value and no prefix; the raw form's length is the value's byte length. Updates go through
//                    io.update (a lockfile around read-merge-write) so parallel hook calls keep every learn.
//   memoryTracker    a long-lived process (the SDK runtime behind moorai-serve and the model proxy, the MCP
//                    gateway): the same records in memory under a random per-process key.
//
// TTL: a secret expires `ttlMs` after it was last read (the session-risk window, policy.sessionRisk.windowMin,
// 30 min by default).
// POOLS: values from a credential source (a credential file, an environment dump, an MCP read of a
// credential path) live in the `cred` pool; values pattern-matched out of any other text live in the
// `pattern` pool. Each pool holds POOL_CAP (64), so text full of secret-shaped junk can never evict a
// credential-file secret.
// QUOTA: one learn call adds at most LEARN_QUOTA (32) new secrets; the rest are not tracked.
// OVERFLOW FAILS CLOSED: when a pool evicts a secret, or a call goes past its quota, the session is
// `overflowed` until every secret it could not keep would have expired (its last read + TTL; now + TTL for
// a secret never kept). While overflowed, every egress check that consults this tracker returns an
// `unverified` match (cli/secret-egress.mjs), so #65's action applies. The learn result says `overflow`,
// which the caller reports once per window as a content-free alert.
// SESSION TABLE: at most MAX_SESSIONS sessions (16 in the state file, 256 per process in memory). A session
// with no live secret and no overflow window is dropped; one that is still live is evicted only when the
// table is full of live sessions, least recently learned first, and its key (a keyed hash in the file) goes
// to an evicted-until map (EVICTED_MAX keys) holding its last learn + TTL (or its overflow window, if later):
// until then overflowed() stays true for that session, so eviction fails closed. The learn result counts the
// live sessions evicted (`evictedLive`), which the caller reports, content-free.
// Fail-open on I/O only: an unreadable or oversized state file reads as empty, a write error is swallowed.
// Same trust boundary as every ~/.moorai file: the agent runs as the same user and can read the key.
import { formsOf, ENCODINGS } from "./secret-forms.mjs";
import { keyring, trackForm } from "./secret-match.mjs";
import { contentHash } from "./content-hash.mjs";

export const SECRET_TAINT_FILE = "secret-taint.json";
export const POOL_CAP = 64;
export const LEARN_QUOTA = 32;
export const DEFAULT_CAP = POOL_CAP;
export const DEFAULT_TTL_MS = 30 * 60000;
export const MAX_SESSIONS = 16;
export const MAX_MEMORY_SESSIONS = 256;
const EVICTED_MAX = 4096;
const POOLS = ["cred", "pattern"];

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

// One session's state { x: records, ou: overflow-until, oa: overflow alerted at } after a learn call.
// Returns the new state and { added, dropped, overQuota, overflow, report, size }.
function learnInto(kr, sess, values, { now, ttlMs, cap, quota, cred, hashFn }) {
  const pool = cred ? "cred" : "pattern";
  const live = (Array.isArray(sess.x) ? sess.x : []).filter((r) => r && now - r.t <= ttlMs);
  const bySid = new Map(live.map((r) => [r.sid, r]));
  let added = 0, overQuota = 0, dropped = 0, ou = sess.ou && sess.ou > now ? sess.ou : 0;
  for (const v of values) {
    const rec = recordOf(kr, v, hashFn);
    if (!rec) continue;
    const prior = bySid.get(rec.sid);
    if (prior) { prior.t = now; if (cred) prior.p = "cred"; continue; }
    if (added >= quota) { overQuota++; continue; }
    const r = { ...rec, t: now, p: pool };
    bySid.set(r.sid, r);
    live.push(r);
    added++;
  }
  if (overQuota) ou = Math.max(ou, now + ttlMs);
  const kept = [];
  for (const p of POOLS) {
    const inPool = live.filter((r) => (r.p === "cred" ? "cred" : "pattern") === p).sort((a, b) => a.t - b.t);
    const over = inPool.length - cap;
    if (over > 0) { for (const r of inPool.slice(0, over)) ou = Math.max(ou, r.t + ttlMs); dropped += over; }
    kept.push(...inPool.slice(Math.max(0, over)));
  }
  const overflow = dropped > 0 || overQuota > 0;
  const report = overflow && !(sess.oa && now - sess.oa <= ttlMs);
  const next = { t: now, x: kept, ...(ou ? { ou } : {}), ...(report ? { oa: now } : sess.oa ? { oa: sess.oa } : {}) };
  return { next, res: { added, dropped, overQuota, overflow, report, size: kept.length, cap, pool } };
}

export function memoryTracker({ key, ttlMs = DEFAULT_TTL_MS, cap = POOL_CAP, quota = LEARN_QUOTA, hashFn = contentHash } = {}) {
  const kr = keyring(key);
  let sess = { x: [] };
  return {
    kr,
    learn(values, { now = Date.now(), ttl = ttlMs, cred = false } = {}) {
      const { next, res } = learnInto(kr, sess, values, { now, ttlMs: ttl, cap, quota, cred, hashFn });
      sess = next;
      return res;
    },
    entries({ now = Date.now(), ttl = ttlMs } = {}) { return entriesOf(sess.x.filter((r) => now - r.t <= ttl), "session-read"); },
    overflowed({ now = Date.now() } = {}) { return !!(sess.ou && sess.ou > now); },
    // When this tracker stops holding anything that matters: its newest secret's expiry or its overflow window.
    liveUntil({ now = Date.now(), ttl = ttlMs } = {}) { return liveUntilOf(sess, now, ttl); },
    size() { return sess.x.length; }
  };
}

// The hook's persistent tracker for one session. `io` = { read(name), write(name, obj), update?(name, fn),
// keyBytes } — cli/secret-taint-hook.mjs in production (a lockfile around update), injectable for tests.
export function sessionTracker({ sessionId, io, ttlMs = DEFAULT_TTL_MS, cap = POOL_CAP, quota = LEARN_QUOTA, hashFn = contentHash }) {
  const key = io && io.keyBytes;
  if (!key || !sessionId) return null;
  const kr = keyring(key);
  const sk = trackSessionKey(kr, sessionId);
  const norm = (raw) => (raw && raw.v === 1 && raw.s && typeof raw.s === "object" ? raw : { v: 1, s: {} });
  const sessOf = () => { const s = norm(io.read(SECRET_TAINT_FILE)).s[sk]; return s && typeof s === "object" ? s : null; };
  return {
    kr,
    learn(values, { now = Date.now(), ttl = ttlMs, cred = false } = {}) {
      let res = null;
      const apply = (raw) => {
        const st = norm(raw);
        const sess = st.s[sk] && typeof st.s[sk] === "object" ? st.s[sk] : { x: [] };
        const r = learnInto(kr, sess, values, { now, ttlMs: ttl, cap, quota, cred, hashFn });
        res = r.res;
        st.s[sk] = r.next;
        const ev = evictInto(st, now, ttl);
        res.evictedLive = ev;
        return st;
      };
      if (typeof io.update === "function") io.update(SECRET_TAINT_FILE, apply);
      else io.write(SECRET_TAINT_FILE, apply(io.read(SECRET_TAINT_FILE)));
      return res;
    },
    entries({ now = Date.now(), ttl = ttlMs } = {}) {
      const sess = sessOf();
      return entriesOf(sess && Array.isArray(sess.x) ? sess.x.filter((r) => r && now - r.t <= ttl) : [], "session-read");
    },
    overflowed({ now = Date.now() } = {}) {
      const st = norm(io.read(SECRET_TAINT_FILE));
      const sess = st.s[sk];
      return !!((sess && sess.ou > now) || (st.e && st.e[sk] > now));
    }
  };
}

function liveUntilOf(sess, now, ttl) {
  const last = (Array.isArray(sess.x) ? sess.x : []).reduce((m, r) => (r && r.t > m ? r.t : m), 0);
  const u = Math.max(last ? last + ttl : 0, sess.ou || 0);
  return u > now ? u : 0;
}

// Session-table upkeep for the state file: drop dead sessions, evict live ones only past MAX_SESSIONS into
// the evicted-until map. Returns how many live sessions were evicted.
function evictInto(st, now, ttl) {
  const e = st.e && typeof st.e === "object" ? st.e : {};
  for (const k of Object.keys(e)) if (!(e[k] > now)) delete e[k];
  for (const k of Object.keys(st.s)) if (!st.s[k] || !liveUntilOf(st.s[k], now, ttl)) delete st.s[k];
  let evicted = 0;
  for (const k of Object.keys(st.s).sort((a, b) => st.s[b].t - st.s[a].t).slice(MAX_SESSIONS)) {
    e[k] = Math.max(e[k] || 0, liveUntilOf(st.s[k], now, ttl));
    delete st.s[k];
    evicted++;
  }
  const keys = Object.keys(e);
  if (keys.length > EVICTED_MAX) for (const k of keys.sort((a, b) => e[a] - e[b]).slice(0, keys.length - EVICTED_MAX)) delete e[k];
  if (Object.keys(e).length) st.e = e; else delete st.e;
  return evicted;
}

// Per-session memory trackers for a long-lived process, under one key: get(id) for learning and matching,
// overflowed(id) also true for a live session evicted from the table (until its last learn + TTL).
// onEvict(count) is called when live sessions are evicted.
export function memorySessions({ key, maxSessions = MAX_MEMORY_SESSIONS, ttlMs = DEFAULT_TTL_MS, cap = POOL_CAP, quota = LEARN_QUOTA, hashFn = contentHash, onEvict } = {}) {
  const k = key || keyring().hk;
  const table = new Map(); // id -> { tr, t }
  const evicted = new Map(); // id -> until
  const upkeep = (now, ttl) => {
    for (const [id, u] of evicted) if (!(u > now)) evicted.delete(id);
    for (const [id, s] of table) if (!s.tr.liveUntil({ now, ttl })) table.delete(id);
    let n = 0;
    if (table.size > maxSessions) {
      for (const [id, s] of [...table].sort((a, b) => a[1].t - b[1].t).slice(0, table.size - maxSessions)) {
        evicted.set(id, Math.max(evicted.get(id) || 0, s.tr.liveUntil({ now, ttl })));
        table.delete(id);
        n++;
      }
    }
    while (evicted.size > EVICTED_MAX) evicted.delete(evicted.keys().next().value);
    if (n && onEvict) onEvict(n);
  };
  const shared = keyring(k);
  return {
    kr: shared,
    learn(id, values, { now = Date.now(), ttl = ttlMs, cred = false } = {}) {
      const sid = String(id || "");
      let s = table.get(sid);
      if (!s) { s = { tr: memoryTracker({ key: k, ttlMs, cap, quota, hashFn }), t: now }; table.set(sid, s); }
      s.t = now;
      const r = s.tr.learn(values, { now, ttl, cred });
      upkeep(now, ttl);
      return r;
    },
    entries(id, { now = Date.now(), ttl = ttlMs } = {}) { const s = table.get(String(id || "")); return s ? s.tr.entries({ now, ttl }) : []; },
    overflowed(id, { now = Date.now() } = {}) {
      const sid = String(id || "");
      const s = table.get(sid);
      return !!((s && s.tr.overflowed({ now })) || evicted.get(sid) > now);
    },
    size() { return table.size; }
  };
}

// The state-file key of a session id: an HMAC under the tracker's key, never the id itself.
function trackSessionKey(kr, sessionId) {
  return trackForm(kr, `session:${String(sessionId).padEnd(8, " ")}`).h;
}
