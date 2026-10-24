// Task-bound tool calls on the endpoint hook (the pure logic is data/task-bound.js): the object check
// (policy.intentArgs) and task allowlists (policy.taskAllowlists) for the MCP tool calls the hook sees.
//
//   captureTaskTerms(input, policy)   UserPromptSubmit, from cli/intent-alignment.mjs captureTask: a person's
//                                     prompt (isUserPrompt) becomes keyed hashes of its terms. Runs when
//                                     intentAlignment is not "off" or an allowlist is configured.
//   taskBoundStep(policy, sessionId, tool, toolInput, { dec, reasons, alts }, { post, coach, verdict })
//                                     PreToolUse, after intentStep on an MCP call. Returns the adjusted
//                                     { dec, reasons, alts }; never touches a deny.
//
// DECISIONS. object-not-in-task (a high-impact MCP call whose object fields name nothing in the task):
// policy.intentAlignment "report" (default) alerts once per session and target; "ask" raises allow to ask;
// "block" denies (the hook's existing intent classes stop at ask; this class honours block); "off" skips
// it. A session with no captured task is not judged, as the hook's intent check does. outside-task-allowlist
// (the session's task matches a taskAllowlists entry by keyword, and the tool or an argument value is not
// in it): held at the entry's default, "deny" or "ask", whatever intentAlignment says. The hook has no
// explicit task id. An unreadable entry denies what it would have covered (an unreadable match: every
// session) and raises one "Task-bound policy invalid" alert per session. An unenrolled device (coach)
// coaches instead, as every hook verdict does.
//
// MATCHED ENTRIES are recorded at capture from the WHOLE prompt (data/task-bound.js entriesNamedIn: every
// word and phrase, however long the prompt), as keyed hashes of the entries' own text, per session, apart
// from the capped term set (MAX_MATCH_SESSIONS sessions). A later judge applies a recorded entry, or one the
// held terms name. Terms are kept in two tiers across prompts — words, tokens and numbers first
// (MAX_WORDS), phrases after (MAX_PHRASES) — so one prompt's phrases never crowd out a later prompt's words.
//
// TAMPER (allowlists only). The state file carries an HMAC over its contents, keyed by a key derived from the
// device signing key (data/agency-sign.mjs, ~/.moorai/agency-ed25519.key: sha256 of its deterministic ed25519
// signature over a fixed label; the key itself is never read here). The state is TAMPERED when the file is
// unreadable, oversized, of another version or fails the HMAC, or is missing while the intent device key
// exists (a capture happened on this device). Tampered: every allowlist entry is applied to the call as if
// its task matched, and anything one of them would hold is denied (reason "state-tampered"), with a
// content-free "Task-bound state tampered" alert on every such call; the tampered file is never re-signed. The
// next capture starts a fresh signed state that records the tamper time and CARRIES OVER the (keyed) session
// ids the tampered file still showed, if it could be parsed. For 24 h after the tamper a session is judged
// normally only when it is PROVEN NEW: its first capture in the fresh state came after the tamper, it is not
// carried over, and its transcript (the hook input's transcript_path) was created after the tamper. Any other
// session — carried over, never captured since, or captured without that proof (then marked carried over) —
// has every allowlist entry applied as if selected, as for a tampered file, so neither deleting the file nor
// a new prompt in an old session reopens it. Each session's first capture time is recorded.
//
// WHO DECIDES. The verified policy the hook loaded and the root-owned admin binding (cli/server-mode.mjs
// systemConfig), which wins key by key. Nothing user-writable.
//
// WHAT IS STORED (~/.moorai/task-terms.json, 0600): per session (its id HMAC'd with the device key
// ~/.moorai/intent.key), the last capture time, up to MAX_WORDS + MAX_PHRASES 16-hex HMACs of the task's
// words, tokens, numbers and two- to five-word phrases (data/task-bound.js taskTerms), and the HMACs of the
// targets already alerted on (MAX_SESSIONS sessions); per session the HMACs of the matched entries
// (MAX_MATCH_SESSIONS sessions); the tamper time; the HMAC. 24 h. Never the prompt or an argument.
// WHAT THIS DOES NOT DEFEND: the agent runs as the same user. It can read both keys, dictionary-attack the
// hashed words (the prompt is already in its own transcript) and re-sign an edited file; deleting the
// intent key together with the file returns the device to "never captured", which no user-writable state
// can tell from a fresh install; more than MAX_MATCH_SESSIONS prompted sessions in 24 h evict the oldest
// session's record; the proof of newness is a transcript file's creation time, which the same user can
// reset by recreating the file of a session the tampered state no longer showed (a deleted state shows
// none). A privileged witness (moorai-guardd) would close these; it is not installed.
import { createHmac, createHash, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, renameSync, statSync } from "node:fs";
import { deviceReceiptSigner } from "../data/agency-sign.mjs";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { deviceKey, isUserPrompt, CLASS_TEXT } from "./intent-alignment.mjs";
import { systemConfig } from "./server-mode.mjs";
import { saferAlternativesFor } from "./hook-core.mjs";
import { REASON } from "./provenance.mjs";
import { taskTerms, termKey, resolveTaskBound, objectChecks, judgeObjects, applicableEntries, judgeAllowlists, hasAllowlists, entriesNamedIn, OBJECT_CLASS, ALLOWLIST_CLASS } from "../data/task-bound.js";

export const TERMS_FILE = "task-terms.json";
const VERSION = 2;
const MAX_SESSIONS = 32;
const MAX_WORDS = 1536;
const MAX_PHRASES = 512;
const MAX_MATCH_SESSIONS = 1024;
const MAX_MATCHES = 64;
const MAX_SEEN = 64;
const TTL_MS = 24 * 3600 * 1000;
const MAX_BYTES = 4 << 20;
const CATEGORY = "Action outside the stated task";

export function boundMode(policy) {
  const m = policy && policy.intentAlignment;
  if (m === false || m === "off") return "off";
  return m === "ask" || m === "block" ? m : "report";
}
const admin = () => { try { return systemConfig(); } catch { return null; } };
const hasher = (k) => (s) => createHmac("sha256", k).update(String(s), "utf8").digest("hex").slice(0, 16);

let _mac;
function macKey() {
  if (_mac !== undefined) return _mac;
  try {
    const signer = deviceReceiptSigner();
    _mac = signer ? createHash("sha256").update(signer.sign(Buffer.from("moorai/task-terms/mac-key/v1"))).digest() : null;
  } catch { _mac = null; }
  return _mac;
}
const macOf = (k, body) => createHmac("sha256", k).update(`task-terms:v${VERSION}\0${body}`, "utf8").digest("hex");
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const fresh = () => ({ v: VERSION, s: {}, m: {}, tamperedAt: 0, carried: [] });
const SID = /^[0-9a-f]{16}$/;
// The session ids a state that failed verification still shows, when it parses: they are carried over.
function priorSessions(o) {
  if (!isObj(o)) return [];
  const ids = [...(isObj(o.s) ? Object.keys(o.s) : []), ...(isObj(o.m) ? Object.keys(o.m) : []), ...(Array.isArray(o.carried) ? o.carried : [])];
  return [...new Set(ids.filter((x) => typeof x === "string" && SID.test(x)))];
}
const bodyOf = (o) => ({ v: o.v, s: o.s, m: o.m, tamperedAt: Number(o.tamperedAt) || 0, carried: Array.isArray(o.carried) ? o.carried : [] });
// -> { st, status: "ok" | "missing" | "bad", prior: [session ids a bad but parseable file showed] }
function readState() {
  const p = join(STATE_DIR, TERMS_FILE);
  let raw;
  try {
    if (statSync(p).size > MAX_BYTES) return { st: fresh(), status: "bad", prior: [] };
    raw = readFileSync(p, "utf8");
  } catch (e) { return { st: fresh(), status: e && e.code === "ENOENT" ? "missing" : "bad", prior: [] }; }
  let o;
  try { o = JSON.parse(raw); } catch { return { st: fresh(), status: "bad", prior: [] }; }
  try {
    const k = macKey();
    if (!k || !isObj(o) || o.v !== VERSION || !isObj(o.s) || !isObj(o.m) || typeof o.mac !== "string") return { st: fresh(), status: "bad", prior: priorSessions(o) };
    const want = Buffer.from(macOf(k, JSON.stringify(bodyOf(o))), "hex");
    const got = Buffer.from(o.mac, "hex");
    if (got.length !== want.length || !timingSafeEqual(got, want)) return { st: fresh(), status: "bad", prior: priorSessions(o) };
    return { st: bodyOf(o), status: "ok", prior: [] };
  } catch { return { st: fresh(), status: "bad", prior: priorSessions(o) }; }
}
function writeState(st) {
  try {
    const k = macKey();
    if (!k) return;
    const now = Date.now();
    const keep = (o, n) => Object.fromEntries(Object.entries(o).filter(([, v]) => v && now - v.t < TTL_MS).sort((a, b) => b[1].t - a[1].t).slice(0, n));
    const inWindow = now - st.tamperedAt < TTL_MS;
    const body = { v: VERSION, s: keep(st.s, MAX_SESSIONS), m: keep(st.m, MAX_MATCH_SESSIONS), tamperedAt: inWindow ? st.tamperedAt : 0, carried: inWindow ? [...new Set(st.carried)].slice(-4 * MAX_MATCH_SESSIONS) : [] };
    mkdirSync(STATE_DIR, { recursive: true });
    const p = join(STATE_DIR, TERMS_FILE);
    const tmp = `${p}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ ...body, mac: macOf(k, JSON.stringify(body)) }), { mode: 0o600 });
    renameSync(tmp, p);
  } catch { /* best-effort; a lost write only means a later alert repeats or a task is unknown */ }
}
// Missing counts as tampered once a capture has happened on this device (the intent device key exists).
const tamperedStatus = (status) => status === "bad" || (status === "missing" && deviceKey(false) !== null);
// Proof that a session started after time t: its transcript file was created after t.
function createdAfter(path, t) {
  try {
    if (typeof path !== "string" || !path || path.length > 4096) return false;
    const b = statSync(path).birthtimeMs;
    return b > 0 && b > t;
  } catch { return false; }
}
// Within 24 h of a tamper: whether a session must be judged as if every allowlist entry were selected.
function unproven(st, sid, now) {
  if (!(now - st.tamperedAt < TTL_MS)) return false;
  const rec = isObj(st.m[sid]) ? st.m[sid] : null;
  return st.carried.includes(sid) || !rec || rec.ok !== true || !(Number(rec.f) >= st.tamperedAt);
}

export function captureTaskTerms(input, policy) {
  try {
    if (!input || !input.session_id || typeof input.prompt !== "string" || !isUserPrompt(input)) return;
    if (boundMode(policy) === "off" && !hasAllowlists(resolveTaskBound(policy, admin()))) return;
    const before = readState();
    const tamperedBefore = tamperedStatus(before.status);
    const k = deviceKey(true);
    if (!k) return;
    const h = hasher(k);
    let { st, status, prior } = readState();
    // A tampered file is never re-signed: start fresh, remember when, and carry over the sessions it showed.
    if (tamperedBefore || status === "bad") st = { ...fresh(), tamperedAt: Date.now(), carried: [...new Set([...before.prior, ...prior])] };
    const sid = h(`session:${input.session_id}`);
    const now = Date.now();
    const cur = isObj(st.s[sid]) ? st.s[sid] : { t: 0, n: 0, wu: [], wn: [], seen: [] };
    const wu = new Set(Array.isArray(cur.wu) ? cur.wu : []), wn = new Set(Array.isArray(cur.wn) ? cur.wn : []);
    for (const term of taskTerms(input.prompt)) {
      const phrase = term.startsWith("w:") && term.includes(" ");
      if (phrase) { if (wn.size < MAX_PHRASES) wn.add(termKey(term, h)); } else if (wu.size < MAX_WORDS) wu.add(termKey(term, h));
    }
    st.s[sid] = { t: now, n: (cur.n || 0) + 1, wu: [...wu], wn: [...wn], seen: Array.isArray(cur.seen) ? cur.seen : [] };
    const lists = resolveTaskBound(policy, admin()).lists;
    const rec = isObj(st.m[sid]) ? st.m[sid] : null;
    const e = new Set(rec && Array.isArray(rec.e) ? rec.e : []);
    for (const x of entriesNamedIn(lists, input.prompt)) if (e.size < MAX_MATCHES) e.add(h(`tb-entry:${x.key}`));
    // First capture of this session in this state: proven new, or (within 24 h of a tamper) carried over.
    let ok = rec ? rec.ok === true : true;
    if (!rec && now - st.tamperedAt < TTL_MS) {
      ok = !st.carried.includes(sid) && createdAfter(input.transcript_path, st.tamperedAt);
      if (!ok) st.carried = [...st.carried, sid];
    }
    st.m[sid] = { t: now, e: [...e], f: rec && Number(rec.f) ? Number(rec.f) : now, ok };
    writeState(st);
  } catch { /* capture is advisory */ }
}

export function taskBoundStep(policy, sessionId, tool, toolInput, it, { post = () => {}, coach = false, verdict = null } = {}) {
  try {
    if (!it || it.dec === "deny" || !sessionId) return it;
    const cfg = resolveTaskBound(policy, admin());
    const mode = boundMode(policy);
    const checks = mode !== "off" ? objectChecks(tool, toolInput, cfg.args) : null;
    if (!checks && !cfg.lists.length) return it;
    const { st, status } = readState();
    const tamperedFile = cfg.lists.length > 0 && tamperedStatus(status);
    // Never created here: the key's existence is the witness that a capture happened on this device.
    const k = deviceKey(false);
    if (!k && !cfg.lists.length) return it; // nothing captured on this device and no allowlist to apply
    const h = k ? hasher(k) : (x) => x;
    const sid = h(`session:${sessionId}`);
    const now = Date.now();
    const live = isObj(st.s[sid]) && now - st.s[sid].t < TTL_MS ? st.s[sid] : null;
    const matched = isObj(st.m[sid]) && now - st.m[sid].t < TTL_MS && Array.isArray(st.m[sid].e) ? new Set(st.m[sid].e) : null;
    // Within 24 h of a tamper, a session not proven new is judged as if every entry were selected.
    const carriedOver = cfg.lists.length > 0 && !tamperedFile && unproven(st, sid, now);
    const tampered = tamperedFile || carriedOver;
    const cur = live || { t: now, n: 0, wu: [], wn: [], seen: [] };
    const terms = cur.n ? new Set([...(cur.wu || []), ...(cur.wn || [])]) : null;
    const has = terms ? (t) => terms.has(termKey(t, h)) : null;
    let { dec, reasons, alts } = it;
    let dirty = false;
    const first = (th) => { if (cur.seen.includes(th)) return false; cur.seen = [...cur.seen, th].slice(-MAX_SEEN); dirty = true; return true; };
    const hold = (why) => {
      if (verdict) verdict.reason = REASON.INTENT_MISMATCH;
      if (dec === "allow") { dec = "ask"; reasons = [why]; alts = saferAlternativesFor([64]); } else reasons = [...reasons, why];
    };
    if (checks && has) {
      const r = judgeObjects(checks, has);
      if (!r.aligned) {
        if (first(h(`seen:${OBJECT_CLASS}:${tool}:${r.target}`))) post({ threatId: 64, category: CATEGORY, riskLevel: mode === "block" ? "Blocked" : "Medium", stage: "behavior", tool: `hook:${tool}`, reasonCode: REASON.INTENT_MISMATCH, contentHash: `intent:${OBJECT_CLASS}`, intent: { class: OBJECT_CLASS, unmatched: r.unmatched, targets: r.fields, prompts: cur.n, mode } });
        const why = `action outside the stated task — ${CLASS_TEXT[OBJECT_CLASS]}`;
        if (mode === "block" && !coach) { if (verdict) verdict.reason = REASON.INTENT_MISMATCH; dec = "deny"; reasons = [why]; alts = saferAlternativesFor([64]); }
        else if (mode !== "report" || coach) hold(why);
      }
    }
    if (dec !== "deny" && tampered) {
      const r = judgeAllowlists(cfg.lists, tool, toolInput);
      if (r) {
        post({ threatId: 0, category: "Task-bound state tampered", riskLevel: "High", stage: "policy", tool: `hook:${tool}`, reasonCode: REASON.FAIL_CLOSED, contentHash: `task-bound-state:${tamperedFile ? status : "carried-over"}`, taskBoundState: { problem: tamperedFile ? (status === "missing" ? "missing" : "unverified") : "carried-over" } });
        if (verdict) verdict.reason = REASON.INTENT_MISMATCH;
        return { dec: "deny", reasons: [`outside the task allowlist (state-tampered)`], alts: saferAlternativesFor([64]) };
      }
      return { dec, reasons, alts };
    }
    if (dec !== "deny" && cfg.lists.length) {
      const r = judgeAllowlists(applicableEntries(cfg.lists, has, null, matched ? (e) => matched.has(h(`tb-entry:${e.key}`)) : null), tool, toolInput);
      if (r) {
        if (first(h(`seen:${ALLOWLIST_CLASS}:${r.index}:${r.reason}:${tool}`))) {
          post({ threatId: 64, category: CATEGORY, riskLevel: r.outcome === "deny" ? "Blocked" : "High", stage: "behavior", tool: `hook:${tool}`, reasonCode: REASON.INTENT_MISMATCH, contentHash: `intent:${ALLOWLIST_CLASS}`, intent: { class: ALLOWLIST_CLASS, mode: r.outcome, task: r.task, reason: r.reason, prompts: cur.n } });
          if (r.invalid && cfg.problems.length) post({ threatId: 0, category: "Task-bound policy invalid", riskLevel: "High", stage: "policy", tool: `hook:${tool}`, reasonCode: REASON.FAIL_CLOSED, contentHash: `task-bound-policy:${cfg.problems.join(",")}`, taskBoundPolicy: { problems: cfg.problems } });
        }
        const why = `outside the task allowlist${r.task ? ` "${r.task}"` : ""} (${r.reason})`;
        if (r.outcome === "deny") { if (verdict) verdict.reason = REASON.INTENT_MISMATCH; dec = "deny"; reasons = [why]; alts = saferAlternativesFor([64]); }
        else hold(why);
      }
    }
    if (dirty && k && !tamperedFile && (live || status === "ok")) { st.s[sid] = cur; writeState(st); }
    return { dec, reasons, alts };
  } catch { return it; }
}
