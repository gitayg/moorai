// #65 — the secrets an agent READ during a session, tracked as keyed fingerprints so a later outbound flow
// that carries one (raw or encoded) is caught even when the value lives in no known secret store.
//
// A tracked secret is its matching material only: per form [encoding, length, 24-bit keyed fingerprint of
// the first 8 bytes, 96-bit HMAC-SHA-256], plus its tenant-keyed alert hash and its last-read time. No value
// and no prefix; the raw form's length is the value's byte length.
//
// TIERS, per session:
//   pools     `cred` (values from a credential source: a credential file, an environment dump, an MCP read
//             of a credential path) and `pattern` (values pattern-matched out of any other text), POOL_CAP
//             (64) each, so text full of secret-shaped junk never displaces a credential-file secret. One
//             learn call adds at most LEARN_QUOTA (32) records to the pools.
//   retained  what a pool evicts, and what a call learned past its quota, kept packed (18 bytes a form)
//             and still matched: RETAIN_CAP records (4,096 in the hook's state, 1,024 per in-memory session).
// Every record expires `ttlMs` after it was last read (the session-risk window, 30 min by default).
// OVERFLOW: only when the retained store itself is full is a record lost; the session is then `overflowed`
// until that record would have expired, and every egress check consulting the tracker returns an
// `unverified` match (cli/secret-egress.mjs). Overflowing a pool does not.
//
// SESSION TABLE: MAX_SESSIONS sessions (16 in the hook's state file; 256 per owner in memory). A session with
// nothing live is dropped; a live one is evicted only when the table is full of live sessions, least recently
// learned first, into an evicted-until map (EVICTED_MAX keys) holding its last learn + TTL (or its overflow
// window): until then overflowed() stays true for it. When that map is itself full, the soonest-expiring
// entries leave it and that table's `overflowedUntil` is raised to the latest of their expiries, so every
// session of that table fails closed until then rather than any evicted one failing open. In memory every
// owner has its own table, map and overflowedUntil; the hook's state file is one device user's table.
// STATE: the hook's file carries `v` (STATE_V) and `fpw` (the fingerprint width); a file of any other version
// or width, or a session whose retained file is missing, oversized or of another generation, is held as
// unverifiable until its last read + TTL.
//
// trackers: sessionTracker (the hook; ~/.moorai/secret-taint.json plus one packed retained file per session
// in ~/.moorai/secret-taint.d/, all 0600, updated under one lockfile by the io the caller passes) and
// memorySessions (a long-lived process; one tracker per owner + session id, in memory under a per-process
// key). An unreadable JSON state reads as empty; a missing, oversized or mismatched retained file holds its
// session. Same trust boundary as every ~/.moorai file.
import { formsOf, ENCODINGS } from "./secret-forms.mjs";
import { keyring, trackForm, FP_BITS } from "./secret-match.mjs";
import { contentHash } from "./content-hash.mjs";

export const SECRET_TAINT_FILE = "secret-taint.json";
export const SECRET_TAINT_DIR = "secret-taint.d";
export const POOL_CAP = 64;
export const LEARN_QUOTA = 32;
export const RETAIN_CAP = 4096;
export const RETAIN_CAP_MEMORY = 1024;
export const DEFAULT_CAP = POOL_CAP;
export const DEFAULT_TTL_MS = 30 * 60000;
export const MAX_SESSIONS = 16;
export const MAX_MEMORY_SESSIONS = 256;
export const EVICTED_MAX = 4096;
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

// ---- packed retained records: t (6) flags (1) hash (8) nf (1), then per form ei (1) len (2) fp (3) h (12) ----
const HEAD = 16, FORM = 18;
export function packRecords(records) {
  const bufs = [];
  for (const r of records) {
    const b = Buffer.alloc(HEAD + FORM * r.f.length);
    b.writeUIntBE(Math.max(0, Math.min(r.t, 2 ** 48 - 1)), 0, 6);
    const hx = /^h2:([0-9a-f]{16})$/.exec(r.hash || "");
    b[6] = (hx ? 1 : 0) | (r.p === "cred" ? 2 : 0);
    if (hx) Buffer.from(hx[1], "hex").copy(b, 7);
    b[15] = r.f.length;
    r.f.forEach(([ei, len, fp, h], i) => { const o = HEAD + FORM * i; b[o] = ei; b.writeUInt16BE(Math.min(len, 65535), o + 1); b.writeUIntBE(fp >>> 0, o + 3, 3); Buffer.from(h, "hex").copy(b, o + 6); });
    bufs.push(b);
  }
  return Buffer.concat(bufs);
}
export function unpackRecords(buf) {
  const out = [];
  if (!Buffer.isBuffer(buf)) return out;
  for (let o = 0; o + HEAD <= buf.length;) {
    const nf = buf[o + 15], end = o + HEAD + FORM * nf;
    if (!nf || end > buf.length) break;
    const f = [];
    for (let i = 0; i < nf; i++) { const p = o + HEAD + FORM * i; f.push([buf[p], buf.readUInt16BE(p + 1), buf.readUIntBE(p + 3, 3), buf.subarray(p + 6, p + 18).toString("hex")]); }
    const flags = buf[o + 6];
    out.push({ t: buf.readUIntBE(o, 6), hash: flags & 1 ? "h2:" + buf.subarray(o + 7, o + 15).toString("hex") : "h2:nokey", p: flags & 2 ? "cred" : "pattern", sid: f[0][3], f });
    o = end;
  }
  return out;
}

// One learn call into a session { x: pool records, ou, oa, ra } and its retained records. Pure.
function learnInto(kr, sess, retained, values, { now, ttlMs, cap, quota, retainCap, cred, hashFn }) {
  const pool = cred ? "cred" : "pattern";
  const live = (Array.isArray(sess.x) ? sess.x : []).filter((r) => r && now - r.t <= ttlMs);
  let kept = retained.filter((r) => r && now - r.t <= ttlMs);
  const bySid = new Map(live.map((r) => [r.sid, r]));
  const retBySid = new Map(kept.map((r) => [r.sid, r]));
  let added = 0, overQuota = 0, dropped = 0, retainedDropped = 0, ou = sess.ou && sess.ou > now ? sess.ou : 0;
  const toRetain = [];
  for (const v of values) {
    const rec = recordOf(kr, v, hashFn);
    if (!rec) continue;
    const prior = bySid.get(rec.sid);
    if (prior) { prior.t = now; if (cred) prior.p = "cred"; continue; }
    const r = { ...rec, t: now, p: pool };
    if (added >= quota) { overQuota++; toRetain.push(r); continue; }
    if (retBySid.has(rec.sid)) { kept = kept.filter((x) => x.sid !== rec.sid); retBySid.delete(rec.sid); }
    bySid.set(r.sid, r);
    live.push(r);
    added++;
  }
  const pools = [];
  for (const p of POOLS) {
    const inPool = live.filter((r) => (r.p === "cred" ? "cred" : "pattern") === p).sort((a, b) => a.t - b.t);
    const over = inPool.length - cap;
    if (over > 0) { toRetain.push(...inPool.slice(0, over)); dropped += over; }
    pools.push(...inPool.slice(Math.max(0, over)));
  }
  for (const r of toRetain) {
    const prior = retBySid.get(r.sid);
    if (prior) { prior.t = Math.max(prior.t, r.t); continue; }
    retBySid.set(r.sid, r);
    kept.push(r);
  }
  kept.sort((a, b) => a.t - b.t);
  if (kept.length > retainCap) {
    retainedDropped = kept.length - retainCap;
    for (const r of kept.slice(0, retainedDropped)) ou = Math.max(ou, r.t + ttlMs);
    kept = kept.slice(retainedDropped);
  }
  const poolFull = dropped > 0 || overQuota > 0;
  const report = poolFull && !(sess.oa && now - sess.oa <= ttlMs);
  const reportRetained = retainedDropped > 0 && !(sess.ra && now - sess.ra <= ttlMs);
  const next = { t: now, x: pools, ...(ou ? { ou } : {}), ...(report ? { oa: now } : sess.oa ? { oa: sess.oa } : {}), ...(reportRetained ? { ra: now } : sess.ra ? { ra: sess.ra } : {}) };
  return { next, retained: kept, res: { added, dropped, overQuota, retainedDropped, retained: kept.length, overflow: poolFull, report, reportRetained, unverified: !!ou, size: pools.length, cap, retainCap, pool } };
}

function liveUntilOf(sess, retained, now, ttl) {
  let last = 0;
  for (const r of [...(Array.isArray(sess.x) ? sess.x : []), ...(retained || [])]) if (r && r.t > last) last = r.t;
  const u = Math.max(last ? last + ttl : 0, sess.ou || 0);
  return u > now ? u : 0;
}

// One session's tracker in memory.
export function memoryTracker({ key, ttlMs = DEFAULT_TTL_MS, cap = POOL_CAP, quota = LEARN_QUOTA, retainCap = RETAIN_CAP_MEMORY, hashFn = contentHash } = {}) {
  const kr = keyring(key);
  let sess = { x: [] };
  let retained = Buffer.alloc(0);
  return {
    kr,
    learn(values, { now = Date.now(), ttl = ttlMs, cred = false } = {}) {
      const r = learnInto(kr, sess, unpackRecords(retained), values, { now, ttlMs: ttl, cap, quota, retainCap, cred, hashFn });
      sess = r.next;
      retained = packRecords(r.retained);
      return r.res;
    },
    entries({ now = Date.now(), ttl = ttlMs } = {}) {
      return entriesOf([...sess.x, ...unpackRecords(retained)].filter((r) => now - r.t <= ttl), "session-read");
    },
    overflowed({ now = Date.now() } = {}) { return !!(sess.ou && sess.ou > now); },
    liveUntil({ now = Date.now(), ttl = ttlMs } = {}) { return liveUntilOf(sess, unpackRecords(retained), now, ttl); },
    size() { return sess.x.length; }
  };
}

// Trim an evicted-until map to `max` keys. The keys that leave raise the returned table-wide overflowedUntil
// to the latest of their expiries (they fail closed together instead of failing open one by one).
function trimEvicted(entries, max, now) {
  const live = entries.filter(([, u]) => u > now).sort((a, b) => a[1] - b[1]);
  const out = live.length > max ? live.length - max : 0;
  let until = 0;
  for (const [, u] of live.slice(0, out)) until = Math.max(until, u);
  return { keep: live.slice(out), trimmed: out, until };
}

// The hook's persistent tracker for one session. `io` = { read(name), write(name, obj), update?(name, fn),
// readBin(name), writeBin(name, buf|null), keyBytes } — cli/secret-taint-hook.mjs in production (update holds
// the lockfile across the whole read-merge-write, retained files included), injectable for tests.
// The state file's format: STATE_V with FP_BITS-wide fingerprints. A file of any other version or width
// cannot be matched against, so every session in it is held as unverifiable until its last read + TTL.
export const STATE_V = 2;
// A retained file is MAGIC + the session's generation (uint32) + packed records. The JSON records the same
// generation and the record count; the retained file is written first and the JSON second, under one lock,
// so a writer killed between the two leaves a generation mismatch, which reads as unverifiable.
const MAGIC = Buffer.from("MTR1");
export function wrapRetained(gen, packed) { const h = Buffer.alloc(8); MAGIC.copy(h); h.writeUInt32BE(gen >>> 0, 4); return Buffer.concat([h, packed]); }
function unwrapRetained(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 8 || !buf.subarray(0, 4).equals(MAGIC)) return null;
  return { gen: buf.readUInt32BE(4), recs: unpackRecords(buf.subarray(8)) };
}
// A session's retained records, checked against what the JSON says: { ok, recs }.
function retainedOf(sess, bin) {
  if (!sess || !(sess.rc > 0)) return { ok: true, recs: [] };
  const u = unwrapRetained(bin);
  if (!u || u.gen !== sess.g || u.recs.length !== sess.rc) return { ok: false, recs: [] };
  return { ok: true, recs: u.recs };
}
const sessionLiveUntil = (sess, now, ttl) => { const u = Math.max((sess.t || 0) + ttl, sess.ou || 0); return u > now ? u : 0; };

// The hook's persistent tracker for one session. `io` = { read(name), write(name, obj), update?(name, fn),
// view?(fn), readBin(name), writeBin(name, buf|null), keyBytes } — cli/secret-taint-hook.mjs in production:
// update and view both hold the lockfile, so a reader never sees the JSON and a retained file from two
// different writes. Injectable for tests.
export function sessionTracker({ sessionId, io, ttlMs = DEFAULT_TTL_MS, cap = POOL_CAP, quota = LEARN_QUOTA, retainCap = RETAIN_CAP, evictedMax = EVICTED_MAX, hashFn = contentHash }) {
  const key = io && io.keyBytes;
  if (!key || !sessionId) return null;
  const kr = keyring(key);
  const sk = trackSessionKey(kr, sessionId);
  const binOf = (k) => `${SECRET_TAINT_DIR}/${k}.bin`;
  const readBin = (k) => (typeof io.readBin === "function" ? io.readBin(binOf(k)) : null);
  const writeBin = (k, b) => { if (typeof io.writeBin === "function") io.writeBin(binOf(k), b); };
  const view = (fn) => (typeof io.view === "function" ? io.view(fn) : fn());
  const norm = (raw, ttl) => {
    if (!raw || typeof raw !== "object" || !raw.s || typeof raw.s !== "object") return { v: STATE_V, fpw: FP_BITS, s: {} };
    if (raw.v === STATE_V && raw.fpw === FP_BITS) return raw;
    const s = {};
    for (const [k, x] of Object.entries(raw.s)) if (x && typeof x === "object") s[k] = { t: x.t || 0, x: [], ou: Math.max(x.ou || 0, (x.t || 0) + ttl), g: 0, rc: 0 };
    return { v: STATE_V, fpw: FP_BITS, s, ...(raw.e && typeof raw.e === "object" ? { e: raw.e } : {}), ...(raw.ovu ? { ovu: raw.ovu } : {}) };
  };
  const snapshot = (ttl) => view(() => {
    const st = norm(io.read(SECRET_TAINT_FILE), ttl);
    const sess = st.s[sk];
    return { st, sess, ret: retainedOf(sess, sess && sess.rc > 0 ? readBin(sk) : null) };
  });
  return {
    kr,
    learn(values, { now = Date.now(), ttl = ttlMs, cred = false } = {}) {
      let res = null;
      const apply = (raw) => {
        const st = norm(raw, ttl);
        const sess = st.s[sk] && typeof st.s[sk] === "object" ? st.s[sk] : { x: [] };
        const ret = retainedOf(sess, sess.rc > 0 ? readBin(sk) : null);
        if (!ret.ok) sess.ou = Math.max(sess.ou || 0, (sess.t || now) + ttl);
        const r = learnInto(kr, sess, ret.recs, values, { now, ttlMs: ttl, cap, quota, retainCap, cred, hashFn });
        res = r.res;
        const g = ((sess.g || 0) + 1) >>> 0;
        writeBin(sk, r.retained.length ? wrapRetained(g, packRecords(r.retained)) : null);
        st.s[sk] = { ...r.next, g, rc: r.retained.length };
        // Session table: drop dead sessions, evict live ones only past MAX_SESSIONS.
        const e = new Map(Object.entries(st.e && typeof st.e === "object" ? st.e : {}));
        for (const k of Object.keys(st.s)) {
          if (k === sk) continue;
          if (!st.s[k] || !sessionLiveUntil(st.s[k], now, ttl)) { delete st.s[k]; writeBin(k, null); }
        }
        let evictedLive = 0;
        for (const k of Object.keys(st.s).sort((a, b) => st.s[b].t - st.s[a].t).slice(MAX_SESSIONS)) {
          e.set(k, Math.max(e.get(k) || 0, sessionLiveUntil(st.s[k], now, ttl)));
          delete st.s[k];
          writeBin(k, null);
          evictedLive++;
        }
        const tr = trimEvicted([...e], evictedMax, now);
        if (tr.trimmed) st.ovu = Math.max(st.ovu || 0, tr.until);
        if (!(st.ovu > now)) delete st.ovu;
        if (tr.keep.length) st.e = Object.fromEntries(tr.keep); else delete st.e;
        res.evictedLive = evictedLive;
        res.evictedMapTrimmed = tr.trimmed;
        return st;
      };
      if (typeof io.update === "function") io.update(SECRET_TAINT_FILE, apply);
      else io.write(SECRET_TAINT_FILE, apply(io.read(SECRET_TAINT_FILE)));
      return res;
    },
    entries({ now = Date.now(), ttl = ttlMs } = {}) {
      const { sess, ret } = snapshot(ttl);
      const pools = sess && Array.isArray(sess.x) ? sess.x : [];
      return entriesOf([...pools, ...ret.recs].filter((r) => r && now - r.t <= ttl), "session-read");
    },
    overflowed({ now = Date.now(), ttl = ttlMs } = {}) {
      const { st, sess, ret } = snapshot(ttl);
      return !!((sess && sess.ou > now) || (sess && !ret.ok && sessionLiveUntil(sess, now, ttl)) || (st.e && st.e[sk] > now) || st.ovu > now);
    }
  };
}

// Per-owner, per-session memory trackers for a long-lived process, under one key. Every owner (moorai-serve's
// bearer principal, "" otherwise) has its own table: maxSessions sessions, evictedMax evicted keys and its own
// overflowedUntil, so one principal filling its table or its evicted map holds only itself.
//   learn(owner, session, values)  into that session's tracker ("" session = the owner's unattributed one)
//   entries(owner, session)        a session's own records plus its owner's unattributed ones; with no
//                                  session, the union of every live tracker of that owner (no owner = "")
//   overflowed(owner, session)     the same scope: any tracker in it overflowed, any key in it evicted
//                                  while live (until its last learn + TTL), or the owner's overflowedUntil
// onEvict({ evictedLive, evictedMapTrimmed }) is called when live sessions are evicted or a map is trimmed.
export function memorySessions({ key, maxSessions = MAX_MEMORY_SESSIONS, evictedMax = EVICTED_MAX, ttlMs = DEFAULT_TTL_MS, cap = POOL_CAP, quota = LEARN_QUOTA, retainCap = RETAIN_CAP_MEMORY, hashFn = contentHash, onEvict } = {}) {
  const k = key || keyring().hk;
  const owners = new Map(); // owner -> { table: Map(session -> { tr, t }), evicted: Map(session -> until), ovu }
  const ownerOf = (o) => {
    let x = owners.get(o);
    if (!x) { x = { table: new Map(), evicted: new Map(), ovu: 0 }; owners.set(o, x); }
    return x;
  };
  const scope = (x, session) => {
    const s = String(session || "");
    return s ? [s, ""] : [...x.table.keys()];
  };
  const upkeep = (o, x, now, ttl) => {
    for (const [sid, s] of x.table) if (!s.tr.liveUntil({ now, ttl })) x.table.delete(sid);
    let evictedLive = 0;
    if (x.table.size > maxSessions) {
      for (const [sid, s] of [...x.table].sort((a, b) => a[1].t - b[1].t).slice(0, x.table.size - maxSessions)) {
        x.evicted.set(sid, Math.max(x.evicted.get(sid) || 0, s.tr.liveUntil({ now, ttl })));
        x.table.delete(sid);
        evictedLive++;
      }
    }
    const tr = trimEvicted([...x.evicted], evictedMax, now);
    x.evicted = new Map(tr.keep);
    if (tr.trimmed) x.ovu = Math.max(x.ovu, tr.until);
    if (!x.table.size && !x.evicted.size && !(x.ovu > now)) owners.delete(o);
    if ((evictedLive || tr.trimmed) && onEvict) onEvict({ evictedLive, evictedMapTrimmed: tr.trimmed });
  };
  return {
    kr: keyring(k),
    learn(owner, session, values, { now = Date.now(), ttl = ttlMs, cred = false } = {}) {
      const o = String(owner || ""), x = ownerOf(o), sid = String(session || "");
      let s = x.table.get(sid);
      if (!s) { s = { tr: memoryTracker({ key: k, ttlMs, cap, quota, retainCap, hashFn }), t: now }; x.table.set(sid, s); }
      s.t = now;
      const r = s.tr.learn(values, { now, ttl, cred });
      upkeep(o, x, now, ttl);
      return r;
    },
    entries(owner, session, { now = Date.now(), ttl = ttlMs } = {}) {
      const x = owners.get(String(owner || ""));
      const out = [];
      if (x) for (const sid of scope(x, session)) { const s = x.table.get(sid); if (s) out.push(...s.tr.entries({ now, ttl })); }
      return out;
    },
    overflowed(owner, session, { now = Date.now() } = {}) {
      const x = owners.get(String(owner || ""));
      if (!x) return false;
      if (x.ovu > now) return true;
      const sess = String(session || "");
      for (const sid of scope(x, session)) { const s = x.table.get(sid); if (s && s.tr.overflowed({ now })) return true; }
      for (const [sid, u] of x.evicted) if (u > now && (!sess || sid === sess || sid === "")) return true;
      return false;
    },
    overflowedUntil: (owner) => { const x = owners.get(String(owner || "")); return x ? x.ovu : 0; },
    size() { let n = 0; for (const x of owners.values()) n += x.table.size; return n; }
  };
}

// The state-file key of a session id: an HMAC under the tracker's key, never the id itself.
function trackSessionKey(kr, sessionId) {
  return trackForm(kr, `session:${String(sessionId).padEnd(8, " ")}`).h;
}
