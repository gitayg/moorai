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
// WHO DECIDES. The verified policy the hook loaded and the root-owned admin binding (cli/server-mode.mjs
// systemConfig), which wins key by key. Nothing user-writable.
//
// WHAT IS STORED (~/.moorai/task-terms.json, 0600): per session (its id HMAC'd with the device key
// ~/.moorai/intent.key), the last capture time, up to MAX_TERMS 16-hex HMACs of the task's words, two- to
// five-word phrases, whitespace-delimited tokens and numbers (data/task-bound.js taskTerms), and the HMACs of
// the targets already alerted on. 32 sessions, 24 h. Never the prompt or an argument. The same trust boundary
// as intent-alignment.json: an agent running as the user can read the key and dictionary-attack the hashed
// words (the prompt is already in the agent's own transcript on the same disk), or write the file to widen a
// task — that only ever relaxes the object check or makes a keyword entry match (which restricts).
import { createHmac } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, renameSync, statSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { deviceKey, isUserPrompt, CLASS_TEXT } from "./intent-alignment.mjs";
import { systemConfig } from "./server-mode.mjs";
import { saferAlternativesFor } from "./hook-core.mjs";
import { REASON } from "./provenance.mjs";
import { taskTerms, termKey, resolveTaskBound, objectChecks, judgeObjects, applicableEntries, judgeAllowlists, hasAllowlists, OBJECT_CLASS, ALLOWLIST_CLASS } from "../data/task-bound.js";

export const TERMS_FILE = "task-terms.json";
const MAX_SESSIONS = 32;
const MAX_TERMS = 768;
const MAX_SEEN = 64;
const TTL_MS = 24 * 3600 * 1000;
const MAX_BYTES = 1 << 20;
const CATEGORY = "Action outside the stated task";

export function boundMode(policy) {
  const m = policy && policy.intentAlignment;
  if (m === false || m === "off") return "off";
  return m === "ask" || m === "block" ? m : "report";
}
const admin = () => { try { return systemConfig(); } catch { return null; } };
const hasher = (k) => (s) => createHmac("sha256", k).update(String(s), "utf8").digest("hex").slice(0, 16);

function readState() {
  try {
    const p = join(STATE_DIR, TERMS_FILE);
    if (statSync(p).size > MAX_BYTES) return { v: 1, s: {} };
    const o = JSON.parse(readFileSync(p, "utf8"));
    return o && o.s && typeof o.s === "object" ? o : { v: 1, s: {} };
  } catch { return { v: 1, s: {} }; }
}
function writeState(st) {
  try {
    const now = Date.now();
    st.s = Object.fromEntries(Object.entries(st.s).filter(([, v]) => v && now - v.t < TTL_MS).sort((a, b) => b[1].t - a[1].t).slice(0, MAX_SESSIONS));
    mkdirSync(STATE_DIR, { recursive: true });
    const p = join(STATE_DIR, TERMS_FILE);
    const tmp = `${p}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(st), { mode: 0o600 });
    renameSync(tmp, p);
  } catch { /* best-effort; a lost write only means a later alert repeats or a task is unknown */ }
}

export function captureTaskTerms(input, policy) {
  try {
    if (!input || !input.session_id || typeof input.prompt !== "string" || !isUserPrompt(input)) return;
    if (boundMode(policy) === "off" && !hasAllowlists(resolveTaskBound(policy, admin()))) return;
    const k = deviceKey(true);
    if (!k) return;
    const h = hasher(k);
    const st = readState();
    const sid = h(`session:${input.session_id}`);
    const cur = st.s[sid] || { t: 0, n: 0, w: [], seen: [] };
    const w = new Set(Array.isArray(cur.w) ? cur.w : []);
    for (const term of taskTerms(input.prompt)) { if (w.size >= MAX_TERMS) break; w.add(termKey(term, h)); }
    st.s[sid] = { ...cur, t: Date.now(), n: (cur.n || 0) + 1, w: [...w], seen: Array.isArray(cur.seen) ? cur.seen : [] };
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
    const k = deviceKey(cfg.lists.length > 0);
    if (!k) return it; // nothing captured on this device and no allowlist to apply
    const h = hasher(k);
    const st = readState();
    const sid = h(`session:${sessionId}`);
    const live = st.s[sid] && Date.now() - st.s[sid].t < TTL_MS ? st.s[sid] : null;
    const cur = live || { t: Date.now(), n: 0, w: [], seen: [] };
    const terms = cur.n ? new Set(cur.w) : null;
    const has = terms ? (t) => terms.has(termKey(t, h)) : null;
    let { dec, reasons, alts } = it;
    let dirty = false;
    const fresh = (th) => { if (cur.seen.includes(th)) return false; cur.seen = [...cur.seen, th].slice(-MAX_SEEN); dirty = true; return true; };
    const hold = (why) => {
      if (verdict) verdict.reason = REASON.INTENT_MISMATCH;
      if (dec === "allow") { dec = "ask"; reasons = [why]; alts = saferAlternativesFor([64]); } else reasons = [...reasons, why];
    };
    if (checks && has) {
      const r = judgeObjects(checks, has);
      if (!r.aligned) {
        if (fresh(h(`seen:${OBJECT_CLASS}:${tool}:${r.target}`))) post({ threatId: 64, category: CATEGORY, riskLevel: mode === "block" ? "Blocked" : "Medium", stage: "behavior", tool: `hook:${tool}`, reasonCode: REASON.INTENT_MISMATCH, contentHash: `intent:${OBJECT_CLASS}`, intent: { class: OBJECT_CLASS, unmatched: r.unmatched, targets: r.fields, prompts: cur.n, mode } });
        const why = `action outside the stated task — ${CLASS_TEXT[OBJECT_CLASS]}`;
        if (mode === "block" && !coach) { if (verdict) verdict.reason = REASON.INTENT_MISMATCH; dec = "deny"; reasons = [why]; alts = saferAlternativesFor([64]); }
        else if (mode !== "report" || coach) hold(why);
      }
    }
    if (dec !== "deny" && cfg.lists.length) {
      const r = judgeAllowlists(applicableEntries(cfg.lists, has, null), tool, toolInput);
      if (r) {
        if (fresh(h(`seen:${ALLOWLIST_CLASS}:${r.index}:${r.reason}:${tool}`))) {
          post({ threatId: 64, category: CATEGORY, riskLevel: r.outcome === "deny" ? "Blocked" : "High", stage: "behavior", tool: `hook:${tool}`, reasonCode: REASON.INTENT_MISMATCH, contentHash: `intent:${ALLOWLIST_CLASS}`, intent: { class: ALLOWLIST_CLASS, mode: r.outcome, task: r.task, reason: r.reason, prompts: cur.n } });
          if (r.invalid && cfg.problems.length) post({ threatId: 0, category: "Task-bound policy invalid", riskLevel: "High", stage: "policy", tool: `hook:${tool}`, reasonCode: REASON.FAIL_CLOSED, contentHash: `task-bound-policy:${cfg.problems.join(",")}`, taskBoundPolicy: { problems: cfg.problems } });
        }
        const why = `outside the task allowlist${r.task ? ` "${r.task}"` : ""} (${r.reason})`;
        if (r.outcome === "deny") { if (verdict) verdict.reason = REASON.INTENT_MISMATCH; dec = "deny"; reasons = [why]; alts = saferAlternativesFor([64]); }
        else hold(why);
      }
    }
    if (dirty) { st.s[sid] = cur; writeState(st); }
    return { dec, reasons, alts };
  } catch { return it; }
}
