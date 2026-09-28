// Intent alignment — on-device state, the hashing key, and the optional loopback-model tier.
// The pure logic lives in data/intent-alignment.js; cli/moorai-hook.mjs calls captureTask() at
// UserPromptSubmit and judgeAction() on already-risky PreToolUse calls.
//
// WHAT IS STORED, AND WHERE (~/.moorai):
//   intent.key              32 random bytes (hex), mode 0600, created on first capture. The HMAC key
//                           for every feature below. Device-local rather than the tenant key
//                           (cli/content-hash.mjs) because these hashes never leave the device, and
//                           because an unenrolled device has no tenant key at all.
//   intent-alignment.json   per session (session id hashed with the same key): last-seen time, number
//                           of prompts captured, and a set of 16-hex-char HMACs of the task's derived
//                           features — "site:github.com", "path:readme.md", "name:slack",
//                           "label:credentials". Plus the HMACs of targets already alerted on, so one
//                           destination alerts once. 64 sessions max, 24h TTL, 512 features/session.
// NEVER STORED: the prompt, any excerpt of it, or the model's reply. The loopback model sees the
// prompt in memory at UserPromptSubmit time and returns labels from a fixed three-word vocabulary.
//
// WHAT THIS DOES NOT DEFEND: the agent runs as the same user. It can read intent.key and dictionary-
// attack the hashed sites and paths (a small space), and it can write intent-alignment.json to add a
// host to the task. Same trust boundary as every other ~/.moorai file.
import { createHmac, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, renameSync, statSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { taskFeatures, featureKeys, actionTargets, assessAlignment, LABELS } from "../data/intent-alignment.js";
import { localHost } from "../data/model-escalation.mjs";
import { semanticEnabled } from "../data/semantic-escalation.js";

export const INTENT_FILE = "intent-alignment.json";
export const INTENT_KEY_FILE = "intent.key";
const MAX_SESSIONS = 64;
const TTL_MS = 24 * 3600 * 1000;
const MAX_FEATURES = 512;
const MAX_SEEN = 64;
const MAX_BYTES = 1 << 20;

// "off" | "report" (default) | "ask". Unknown values resolve to the default.
export function intentMode(policy) {
  const m = policy && policy.intentAlignment;
  if (m === false || m === "off") return "off";
  return m === "ask" ? "ask" : "report";
}

// Only prompts a person authored count as the task. `system` (peer/channel messages, task
// notifications, auto-continuation) and `poll_event` are machine-injected and may carry third-party
// text; letting them in would let an injected turn put its own destination into scope.
const USER_SOURCES = new Set(["user", "sdk", "loop_wakeup", "schedule_wakeup"]);
export function isUserPrompt(input) { return !input.source || USER_SOURCES.has(input.source); }

let _key;
function key(create) {
  if (_key) return _key;
  const p = join(STATE_DIR, INTENT_KEY_FILE);
  try { const k = readFileSync(p, "utf8").trim(); if (/^[0-9a-f]{64}$/.test(k)) return (_key = Buffer.from(k, "hex")); } catch { /* absent */ }
  if (!create) return null;
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    const k = randomBytes(32);
    writeFileSync(p, k.toString("hex"), { mode: 0o600, flag: "wx" });
    return (_key = k);
  } catch { return key(false); } // lost a creation race: read the winner's key
}
const hasher = (k) => (s) => createHmac("sha256", k).update(String(s), "utf8").digest("hex").slice(0, 16);

function readState() {
  try {
    const p = join(STATE_DIR, INTENT_FILE);
    if (statSync(p).size > MAX_BYTES) return { v: 1, s: {} };
    const o = JSON.parse(readFileSync(p, "utf8"));
    return o && o.s && typeof o.s === "object" ? o : { v: 1, s: {} };
  } catch { return { v: 1, s: {} }; }
}
function writeState(st) {
  try {
    const now = Date.now();
    const live = Object.entries(st.s).filter(([, v]) => v && now - v.t < TTL_MS).sort((a, b) => b[1].t - a[1].t).slice(0, MAX_SESSIONS);
    st.s = Object.fromEntries(live);
    mkdirSync(STATE_DIR, { recursive: true });
    const p = join(STATE_DIR, INTENT_FILE);
    const tmp = `${p}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(st), { mode: 0o600 });
    renameSync(tmp, p);
  } catch { /* state is best-effort; never affects the decision */ }
}

// The optional semantic tier: the LOOPBACK model labels the task, in memory, once per prompt. Only
// when the org opted into model escalation (policy.modelEscalation + semanticEscalation ≠ off), and
// only ever the local model — "provider" mode does not widen this to a cloud call. Bounded by
// MOORAI_INTENT_TIMEOUT_MS (default 1500ms) across the probe and the generate; any failure → no labels.
const INTENT_PROMPT =
  "You label which kinds of risky actions a developer's request to a coding agent would legitimately need. " +
  "Kinds: credentials (reading or changing secrets, keys, tokens, .env or cloud credentials), destructive " +
  "(deleting, resetting or overwriting files or data), mcp-write (posting, sending or creating something in " +
  "an external service such as a chat, tracker or repository host). Respond with ONLY compact JSON " +
  '{"expects":[...]} using only those kind names, or {"expects":[]} if none. REQUEST:\n';
export async function modelLabels(prompt, policy) {
  if (!policy || !policy.modelEscalation || !semanticEnabled(policy)) return [];
  const budget = Number(process.env.MOORAI_INTENT_TIMEOUT_MS) || 1500;
  const signal = AbortSignal.timeout(budget);
  try {
    const tags = await fetch(localHost() + "/api/tags", { signal });
    if (!tags.ok) return [];
    const r = await fetch(localHost() + "/api/generate", {
      method: "POST", headers: { "Content-Type": "application/json" }, signal,
      body: JSON.stringify({ model: process.env.MOORAI_LOCAL_MODEL || "llama3:latest", prompt: INTENT_PROMPT + String(prompt).slice(0, 4000), stream: false, format: "json", options: { temperature: 0 } })
    });
    if (!r.ok) return [];
    const j = await r.json();
    const exp = JSON.parse(j.response || "{}").expects;
    return Array.isArray(exp) ? exp.filter((l) => LABELS.includes(l)) : [];
  } catch { return []; }
}

// UserPromptSubmit. Returns nothing; writes only hashes.
export async function captureTask(input, policy) {
  try {
    if (intentMode(policy) === "off" || !input.session_id || typeof input.prompt !== "string" || !isUserPrompt(input)) return;
    const k = key(true);
    if (!k) return;
    const h = hasher(k);
    const f = taskFeatures(input.prompt);
    const sem = await modelLabels(input.prompt, policy);
    const keys = featureKeys({ ...f, labels: [...new Set([...f.labels, ...sem])] }, h);
    const st = readState();
    const sid = h(`session:${input.session_id}`);
    const cur = st.s[sid] || { t: 0, n: 0, f: [], seen: [], sem: 0 };
    cur.f = [...new Set([...cur.f, ...keys])].slice(0, MAX_FEATURES);
    cur.n += 1;
    cur.t = Date.now();
    if (sem.length) cur.sem = 1;
    st.s[sid] = cur;
    writeState(st);
  } catch { /* capture is advisory; fail-open */ }
}

// PreToolUse, called only after the hook's own verdict. Returns null (not risky, no task captured,
// aligned, already alerted, or off) or { cls, unmatched, targets, prompts, semantic, fresh, mode }.
export function judgeAction(policy, sessionId, tool, toolInput, findings) {
  try {
    const mode = intentMode(policy);
    if (mode === "off" || !sessionId) return null;
    const action = actionTargets(tool, toolInput, findings);
    if (!action) return null;
    const k = key(false);
    if (!k) return null; // nothing was ever captured on this device
    const h = hasher(k);
    const st = readState();
    const sid = h(`session:${sessionId}`);
    const cur = st.s[sid];
    if (!cur || !cur.n) return null; // no task for this session: never judge against nothing
    const r = assessAlignment(new Set(cur.f), action, h);
    if (r.aligned) return null;
    const seenKey = h(`seen:${action.cls}:${[...action.sites, ...action.paths, ...action.names].join("|")}`);
    const fresh = !cur.seen.includes(seenKey);
    if (fresh) { cur.seen = [...cur.seen, seenKey].slice(-MAX_SEEN); writeState(st); }
    return { cls: action.cls, unmatched: r.unmatched, targets: r.targets, prompts: cur.n, semantic: Boolean(cur.sem), fresh, mode };
  } catch { return null; }
}

export const CLASS_TEXT = {
  egress: "an upload to a host your request never mentioned",
  credentials: "a credential read your request never mentioned",
  destructive: "a destructive command on paths your request never mentioned",
  "mcp-write": "an MCP write to a service your request never mentioned"
};
