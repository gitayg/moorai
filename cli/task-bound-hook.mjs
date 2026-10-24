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
// next capture starts a fresh signed state that records the tamper time (a fixed timestamp, HMAC-covered).
// For the whole 24 h window after it, EVERY session — an old one capturing a new prompt, one created after the
// tamper, any number of new ones — is judged the same way: every allowlist entry applied as if selected. No
// proof of newness, no per-session list to evict. The cost: legitimate new sessions are held for the window too.
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
// session's record. A privileged witness (moorai-guardd) would close these; it is not installed.
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
const fresh = () => ({ v: VERSION, s: {}, m: {}, tamperedAt: 0 });
const bodyOf = (o) => ({ v: o.v, s: o.s, m: o.m, tamperedAt: Number(o.tamperedAt) || 0 });
// -> { st, status: "ok" | "missing" | "bad" }
function readState() {
  const p = join(STATE_DIR, TERMS_FILE);
  let raw;
  try {
    if (statSync(p).size > MAX_BYTES) return { st: fresh(), status: "bad" };
    raw = readFileSync(p, "utf8");
  } catch (e) { return { st: fresh(), status: e && e.code === "ENOENT" ? "missing" : "bad" }; }
  try {
    const o = JSON.parse(raw);
    const k = macKey();
    if (!k || !isObj(o) || o.v !== VERSION || !isObj(o.s) || !isObj(o.m) || typeof o.mac !== "string") return { st: fresh(), status: "bad" };
    const want = Buffer.from(macOf(k, JSON.stringify(bodyOf(o))), "hex");
    const got = Buffer.from(o.mac, "hex");
    if (got.length !== want.length || !timingSafeEqual(got, want)) return { st: fresh(), status: "bad" };
    return { st: bodyOf(o), status: "ok" };
  } catch { return { st: fresh(), status: "bad" }; }
}
function writeState(st) {
  try {
    const k = macKey();
    if (!k) return;
    const now = Date.now();
    const keep = (o, n) => Object.fromEntries(Object.entries(o).filter(([, v]) => v && now - v.t < TTL_MS).sort((a, b) => b[1].t - a[1].t).slice(0, n));
    const body = { v: VERSION, s: keep(st.s, MAX_SESSIONS), m: keep(st.m, MAX_MATCH_SESSIONS), tamperedAt: inWindow(st, now) ? st.tamperedAt : 0 };
    mkdirSync(STATE_DIR, { recursive: true });
    const p = join(STATE_DIR, TERMS_FILE);
    const tmp = `${p}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ ...body, mac: macOf(k, JSON.stringify(body)) }), { mode: 0o600 });
    renameSync(tmp, p);
  } catch { /* best-effort; a lost write only means a later alert repeats or a task is unknown */ }
}
// Missing counts as tampered once a capture has happened on this device (the intent device key exists).
const tamperedStatus = (status) => status === "bad" || (status === "missing" && deviceKey(false) !== null);
// The 24 h after a detected tamper, during which every session is held as for a tampered file.
const inWindow = (st, now) => st.tamperedAt > 0 && now - st.tamperedAt < TTL_MS;

export function captureTaskTerms(input, policy) {
  try {
    if (!input || !input.session_id || typeof input.prompt !== "string" || !isUserPrompt(input)) return;
    if (boundMode(policy) === "off" && !hasAllowlists(resolveTaskBound(policy, admin()))) return;
    const tamperedBefore = tamperedStatus(readState().status);
    const k = deviceKey(true);
    if (!k) return;
    const h = hasher(k);
    let { st, status } = readState();
    // A tampered file is never re-signed: start fresh and remember when; the window holds every session.
    if (tamperedBefore || status === "bad") st = { ...fresh(), tamperedAt: Date.now() };
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
    const e = new Set(isObj(st.m[sid]) && Array.isArray(st.m[sid].e) ? st.m[sid].e : []);
    for (const x of entriesNamedIn(lists, input.prompt)) if (e.size < MAX_MATCHES) e.add(h(`tb-entry:${x.key}`));
    st.m[sid] = { t: now, e: [...e] };
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
    // Within 24 h of a detected tamper, every session is judged as if every entry were selected.
    const window = cfg.lists.length > 0 && !tamperedFile && inWindow(st, now);
    const tampered = tamperedFile || window;
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
        post({ threatId: 0, category: "Task-bound state tampered", riskLevel: "High", stage: "policy", tool: `hook:${tool}`, reasonCode: REASON.FAIL_CLOSED, contentHash: `task-bound-state:${tamperedFile ? status : "tamper-window"}`, taskBoundState: { problem: tamperedFile ? (status === "missing" ? "missing" : "unverified") : "tamper-window" } });
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
