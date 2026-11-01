// The allow trail (opt-in, policy key `actionTrail`): one content-free record per tool call the hook
// allows, queued on the device and delivered to the console in batches (POST /api/actions).
//
// Without it the console only sees findings (ask / deny / alert) and per-session totals; the calls that
// were simply allowed live only in the device-local action audit log. With `actionTrail: "allowed"` in the
// signed policy, the PreToolUse path appends one record per allowed call to a local queue and a detached
// worker flushes it. Nothing on the decision path touches the network.
//
// WHAT A RECORD CARRIES (RECORD_FIELDS, built by buildActionRecord, nothing else is copied): ts, the keyed
// session hash, seq (this file's own counter, field `seq` on the wire and in the console's storage,
// separate from the alert seq), event, the tool name (sanitizeToolName), its capability tags, the MCP server name, decision "allow", basis (rule | default | exception),
// the signed policy's iat, the agent and MoorAI versions, the identity alerts carry, the keyed
// contentHash of the normalized call, the call's W3C trace context (traceId, spanId, parentSpanId; hex
// only, cli/trace-context.mjs), the session's context tree at decision time (contextRoot, 64 hex, and
// contextSize, its leaf count; cli/context-tree.mjs) and, on a sub-agent's records, contextSession (the keyed
// id of the sub-agent's own tree, which contextRoot belongs to; `session` names the parent session), and on a
// model proxy's records the provider (an enum)
// and the model string (at most 64 of [A-Za-z0-9._:/@-]), and origin (where the call came from, enums only,
// cli/origin.mjs). Never an argument, a path, a URL, a command, prompt
// text or file contents: the hash is one-way and keyed per tenant (cli/content-hash.mjs).
//
// THE MODE COMES ONLY FROM THE SIGNED POLICY (actionTrailMode): a policy body with no signature envelope
// reads "off", and nothing in the environment or a user config file is consulted. The policy itself is only
// ever fetched from the console the binding names, and an admin binding wins over the user's file
// (cli/config.mjs).
//
// THE QUEUE IS AGENT-WRITABLE. It sits in ~/.moorai with the rest of the hook state, at the same trust
// level: the governed agent can delete or edit queued records before they are posted. seq goes up by one
// per record, so the console sees a naive deletion as a gap and a rewound counter as a regression. Making
// the queue tamper-proof needs state the agent cannot write (trust-anchor design, phase 3).
//
// Delivery is at-least-once: a batch whose 2xx was lost is sent again, and the console de-duplicates by
// (device, user, seq).
import { readFileSync, writeFileSync, appendFileSync, openSync, closeSync, unlinkSync, statSync, mkdirSync, renameSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { readConsoleBackoff, backoffDelay, BACKOFF_BASE_MS, BACKOFF_CAP_MS } from "./console-backoff.mjs";
import { normalizeCommand } from "./claim-check.mjs";
import { TAGS } from "../data/tool-tags.js";
import { validTraceId, validSpanId } from "./trace-context.mjs";
import { NO_KEY } from "./content-hash.mjs";
import { sanitizeOrigin } from "./origin.mjs";

export const QUEUE_FILE = "action-trail.jsonl";
export const STATE_FILE = "action-trail-state.json";
export const LOCK_FILE = ".action-trail.lock";
export const MAX_RECORDS = 10000;
export const MAX_BYTES = 5 * 1024 * 1024;
// A full queue drops its oldest records down to this share of each bound, so a console that stays away
// costs one rewrite per ~1,000 calls rather than a 5 MB rewrite on every call.
export const TRIM_TO = 0.9;
export const FLUSH_AT_RECORDS = 200;
export const FLUSH_AT_AGE_MS = 30000;
export const BATCH_MAX = 500;
// One flush in flight: the call that decides a flush is due takes this lease (in the state file, under the
// lock) and spawns the worker; no other call spawns one until the worker releases it or it runs out.
export const FLUSH_LEASE_MS = 60000;
export const POST_TIMEOUT_MS = 10000;
export const MAX_BATCHES_PER_RUN = Math.ceil(MAX_RECORDS / BATCH_MAX);
// The console rejects a record whose ts is over 90 days old. At flush time anything past 89 days (a day of
// margin for clock skew and a slow flush) is dropped here and counted in `dropped` (actionTrailDropped).
export const MAX_AGE_MS = 89 * 86400000;
export const TOOL_MAX = 256;
const LOCK_WAIT_MS = 200;
const LOCK_STALE_MS = 5000;

export const RECORD_FIELDS = Object.freeze(["ts", "session", "seq", "event", "tool", "toolTags", "mcpServer", "decision", "basis", "policyIat", "agentName", "agentVersion", "appVersion", "user", "device", "platform", "tenant", "actor", "contentHash", "traceId", "spanId", "parentSpanId", "contextRoot", "contextSize", "contextSession", "provider", "model", "origin"]);
export const BASES = Object.freeze(["rule", "default", "exception"]);
// A model-proxy record's provider, and the model string's shape (else the field is left out).
export const PROVIDERS = Object.freeze(["anthropic", "openai", "google", "ollama", "other"]);
export const MODEL_RE = /^[A-Za-z0-9._:\/@-]{1,64}$/;
// The event a record names: "PreToolUse" unless the caller names another (the model proxy: "ModelRequest").
// A letters-only token of at most 32, else the default.
const EVENT_RE = /^[A-Za-z]{1,32}$/;
// A context tree's keyed id (cli/context-tree.mjs sessionFile's rule).
const CONTEXT_SESSION_RE = /^[A-Za-z0-9_:]{1,128}$/;

// "allowed" only when the policy carries a signature envelope and says so; every other value, an unsigned
// body and no policy at all read "off".
export function actionTrailMode(policy) {
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) return "off";
  const s = policy.policySig;
  if (!s || typeof s !== "object" || typeof s.sig !== "string" || !s.sig) return "off";
  return policy.actionTrail === "allowed" ? "allowed" : "off";
}

// The text whose keyed hash identifies the call: the tool name and its input, normalized (a shell command
// with its whitespace collapsed, as the session ledger keys it; any other input as JSON with sorted keys).
export function callFingerprintText(tool, toolInput) {
  const t = String(tool || "");
  const ti = toolInput && typeof toolInput === "object" ? toolInput : {};
  if ((t === "Bash" || t === "PowerShell") && typeof ti.command === "string") return `${t}|${normalizeCommand(ti.command)}`;
  return `${t}|${stableJson(ti)}`;
}
function stableJson(v, depth = 0) {
  if (depth > 32) return "null";
  if (Array.isArray(v)) return `[${v.map((x) => stableJson(x, depth + 1)).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stableJson(v[k], depth + 1)}`).join(",")}}`;
  const s = JSON.stringify(v);
  return s === undefined ? "null" : s;
}

const str = (v, max) => (typeof v === "string" && v ? v.slice(0, max) : "");
// The console's tool-name rule (RAISEME-server server/action-trail.js toolName): 1 to 256 code points after
// NFKC, none a control, format or surrogate code unit or whitespace. Each such code point becomes "_" and
// the name is cut to 256 code points, so no record is rejected for its name. No name reads "unknown".
const TOOL_BAD_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Z}\s]/gu;
export function sanitizeToolName(v) {
  let s = typeof v === "string" ? v : "";
  for (let i = 0; i < 4; i++) {
    const n = [...s.normalize("NFKC").replace(TOOL_BAD_RE, "_")].slice(0, TOOL_MAX).join("");
    if (n === s) break;
    s = n;
  }
  return s && s === s.normalize("NFKC") && !/[\p{Cc}\p{Cf}\p{Cs}\p{Z}\s]/u.test(s) ? s : "unknown";
}
// One record, from named fields only. seq is added when the record is queued.
export function buildActionRecord(f = {}) {
  const r = { ts: str(f.ts, 40) || new Date().toISOString() };
  const put = (k, v) => { if (v) r[k] = v; };
  put("session", str(f.session, 128));
  r.event = typeof f.event === "string" && EVENT_RE.test(f.event) ? f.event : "PreToolUse";
  r.tool = sanitizeToolName(f.tool);
  r.toolTags = Array.isArray(f.toolTags) ? TAGS.filter((t) => f.toolTags.includes(t)) : [];
  put("mcpServer", str(f.mcpServer, 128));
  r.decision = "allow";
  r.basis = BASES.includes(f.basis) ? f.basis : "default";
  put("policyIat", str(f.policyIat, 40));
  put("agentName", str(f.agentName, 64));
  put("agentVersion", str(f.agentVersion, 64));
  put("appVersion", str(f.appVersion, 64));
  for (const k of ["user", "device", "platform", "tenant", "actor", "contentHash"]) put(k, str(f[k], 256));
  // W3C trace context (cli/trace-context.mjs): lowercase hex only, else left out.
  if (validTraceId(f.traceId)) r.traceId = f.traceId;
  if (validSpanId(f.spanId)) r.spanId = f.spanId;
  if (validSpanId(f.parentSpanId)) r.parentSpanId = f.parentSpanId;
  // The context tree's root and size (cli/context-tree.mjs): 64 lowercase hex and a leaf count, together or
  // not at all.
  if (typeof f.contextRoot === "string" && /^[0-9a-f]{64}$/.test(f.contextRoot) && Number.isSafeInteger(f.contextSize) && f.contextSize >= 0) { r.contextRoot = f.contextRoot; r.contextSize = f.contextSize; }
  // The tree contextRoot belongs to, when it is not the session's own (a sub-agent's tree, keyed on its
  // session and agent id): a keyed id like `session` ([A-Za-z0-9_:], at most 128, never the no-key
  // sentinel), only alongside contextRoot and only when it differs from `session`.
  if (r.contextRoot && typeof f.contextSession === "string" && CONTEXT_SESSION_RE.test(f.contextSession) && f.contextSession !== NO_KEY && f.contextSession !== r.session) r.contextSession = f.contextSession;
  // Model proxy records: provider (an enum) and the request's model string (MODEL_RE), else left out.
  if (PROVIDERS.includes(f.provider)) r.provider = f.provider;
  if (typeof f.model === "string" && MODEL_RE.test(f.model)) r.model = f.model;
  // Where the call came from (cli/origin.mjs): enums only, kind and status re-derived from the basis table.
  const origin = sanitizeOrigin(f.origin);
  if (origin) r.origin = origin;
  return r;
}

// ---- state + lock ----
const paths = (dir) => ({ queue: join(dir, QUEUE_FILE), state: join(dir, STATE_FILE), lock: join(dir, LOCK_FILE) });
const SLEEP = new Int32Array(new SharedArrayBuffer(4));
const nap = (ms) => { try { Atomics.wait(SLEEP, 0, 0, ms); } catch { /* best-effort */ } };
// fn(held): held is false when the lock could not be had in LOCK_WAIT_MS (a crashed holder's lock older
// than LOCK_STALE_MS is broken). An append still goes ahead unlocked (it can at worst repeat a seq); a
// rewrite does not.
function withLock(dir, fn) {
  const { lock } = paths(dir);
  let fd = null;
  const until = Date.now() + LOCK_WAIT_MS;
  try { mkdirSync(dir, { recursive: true }); } catch { /* the open below fails too */ }
  while (fd === null) {
    try { fd = openSync(lock, "wx"); break; } catch (e) {
      if (!e || e.code !== "EEXIST") break;
      try { if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) { unlinkSync(lock); continue; } } catch { continue; }
      if (Date.now() >= until) break;
      nap(2);
    }
  }
  try { return fn(fd !== null); } finally {
    if (fd !== null) { try { closeSync(fd); } catch { /* closed */ } try { unlinkSync(lock); } catch { /* gone */ } }
  }
}
const nonNeg = (v) => (Number.isSafeInteger(v) && v >= 0 ? v : 0);
export function readTrailState(dir = STATE_DIR) {
  let s = {};
  try { s = JSON.parse(readFileSync(paths(dir).state, "utf8")) || {}; } catch { /* fresh */ }
  return { seq: nonNeg(s.seq), count: nonNeg(s.count), bytes: nonNeg(s.bytes), oldest: nonNeg(s.oldest), dropped: nonNeg(s.dropped), lease: nonNeg(s.lease), retryAt: nonNeg(s.retryAt), rejects: nonNeg(s.rejects) };
}
function writeState(dir, st) {
  const p = paths(dir).state;
  try { writeFileSync(p, JSON.stringify(st), { mode: 0o600 }); } catch { /* the next call recounts */ }
}
// The queue's records, oldest first; malformed lines are counted, never returned.
function readQueue(dir) {
  let raw = "";
  try { raw = readFileSync(paths(dir).queue, "utf8"); } catch { return { records: [], bad: 0 }; }
  const records = [];
  let bad = 0;
  for (const l of raw.split("\n")) {
    if (!l) continue;
    try { const r = JSON.parse(l); if (r && typeof r === "object" && !Array.isArray(r) && Number.isSafeInteger(r.seq)) records.push(r); else bad++; } catch { bad++; }
  }
  return { records, bad };
}
function writeQueue(dir, records) {
  const { queue } = paths(dir);
  const body = records.map((r) => JSON.stringify(r) + "\n").join("");
  const tmp = `${queue}.${process.pid}.tmp`;
  writeFileSync(tmp, body, { mode: 0o600 });
  renameSync(tmp, queue);
  return Buffer.byteLength(body);
}
const tsMs = (r) => { const t = Date.parse(r && r.ts); return Number.isFinite(t) ? t : 0; };
// The file is the truth: when its size is not what the state says (deleted, edited, a torn write), the
// count, bytes and oldest are taken from the file again.
function resync(dir, st, size) {
  if (size === st.bytes) return;
  const q = readQueue(dir);
  st.count = q.records.length;
  st.bytes = size;
  st.oldest = q.records.length ? tsMs(q.records[0]) : 0;
}
const queueSize = (dir) => { try { return statSync(paths(dir).queue).size; } catch { return 0; } };
// A lease or retry time in the future beyond what this module ever writes is not one it wrote: ignored.
const leaseHeld = (st, now) => st.lease > 0 && st.lease <= now && now - st.lease < FLUSH_LEASE_MS;
const retryWaits = (st, now) => st.retryAt > now && st.retryAt - now <= BACKOFF_CAP_MS;
function dueAndClaim(st, now, force) {
  if (!st.count || leaseHeld(st, now) || retryWaits(st, now)) return false;
  if (!force && st.count < FLUSH_AT_RECORDS && !(st.oldest && now - st.oldest >= FLUSH_AT_AGE_MS)) return false;
  st.lease = now;
  return true;
}

// Queues one record. → { queued, seq, count, dropped, trimmed, flushDue }. flushDue: this call took the
// flush lease and should spawn the worker. Never throws.
export function enqueueActionRecord(record, { dir = STATE_DIR, now = Date.now() } = {}) {
  try {
    return withLock(dir, () => {
      const st = readTrailState(dir);
      resync(dir, st, queueSize(dir));
      const rec = { ...record, seq: st.seq + 1 };
      const line = JSON.stringify(rec) + "\n";
      const len = Buffer.byteLength(line);
      let trimmed = 0;
      if (st.count + 1 > MAX_RECORDS || st.bytes + len > MAX_BYTES) {
        const q = readQueue(dir);
        const keepN = Math.floor(MAX_RECORDS * TRIM_TO), keepB = Math.floor(MAX_BYTES * TRIM_TO);
        let i = Math.max(0, q.records.length - keepN), bytes = q.records.slice(i).reduce((n, r) => n + Buffer.byteLength(JSON.stringify(r)) + 1, 0);
        while (i < q.records.length && bytes > keepB) bytes -= Buffer.byteLength(JSON.stringify(q.records[i++])) + 1;
        const kept = q.records.slice(i);
        trimmed = i + q.bad;
        st.bytes = writeQueue(dir, kept);
        st.count = kept.length;
        st.oldest = kept.length ? tsMs(kept[0]) : 0;
        st.dropped += trimmed;
      }
      appendFileSync(paths(dir).queue, line, { mode: 0o600 });
      st.seq = rec.seq;
      if (!st.count) st.oldest = now;
      st.count++;
      st.bytes += len;
      const flushDue = dueAndClaim(st, now, false);
      writeState(dir, st);
      return { queued: true, seq: rec.seq, count: st.count, dropped: st.dropped, trimmed, flushDue };
    });
  } catch { return { queued: false, flushDue: false }; }
}

// Takes the flush lease when something is queued and nothing is in flight or backing off. force: ignore
// the size / age thresholds (session end). → true when the caller should spawn the worker.
export function claimFlush({ dir = STATE_DIR, now = Date.now(), force = false } = {}) {
  try {
    return withLock(dir, (held) => {
      if (!held) return false;
      const st = readTrailState(dir);
      resync(dir, st, queueSize(dir));
      const due = dueAndClaim(st, now, force);
      if (due) writeState(dir, st);
      return due;
    });
  } catch { return false; }
}

// The detached worker's body: posts the queue in batches of BATCH_MAX until it is empty or the console
// does not take a batch. A batch leaves the queue only on a 2xx. Any other answer (the console answers
// 404 / 501 until its side ships) or no answer keeps the records and sets retryAt with the console
// back-off's own schedule (1, 2, 4 minutes, capped at 5), so a console that is not ready is asked again
// at most that often. While the hook's console back-off is active the worker sends nothing. It never
// fetches policy and never writes the hook's back-off file.
// Records older than MAX_AGE_MS leave the queue before each batch is read, counted in `dropped` and in
// out.droppedAged.
export async function flushActionTrail({ config, dir = STATE_DIR, fetchImpl = globalThis.fetch, now = () => Date.now(), backoff = readConsoleBackoff } = {}) {
  const out = { posted: 0, batches: 0, status: "empty", httpStatus: 0, droppedAged: 0 };
  const token = config && typeof config.installToken === "string" ? config.installToken.trim() : "";
  try {
    if (!token || !config.serverUrl) { out.status = "unenrolled"; return out; }
    if (backoff().active) {
      out.status = "console-backoff";
      withLock(dir, (held) => { if (!held) return; const st = readTrailState(dir); st.retryAt = now() + BACKOFF_BASE_MS; writeState(dir, st); });
      return out;
    }
    for (let b = 0; b < MAX_BATCHES_PER_RUN; b++) {
      const batch = withLock(dir, (held) => {
        if (!held) return null;
        const q = readQueue(dir);
        const cutoff = now() - MAX_AGE_MS;
        const kept = q.records.filter((r) => { const t = Date.parse(r.ts); return !(Number.isFinite(t) && t < cutoff); });
        const aged = q.records.length - kept.length;
        if (aged) {
          const st = readTrailState(dir);
          st.bytes = writeQueue(dir, kept);
          st.count = kept.length;
          st.oldest = kept.length ? tsMs(kept[0]) : 0;
          st.dropped += aged + q.bad;
          writeState(dir, st);
          out.droppedAged += aged;
        }
        return kept.slice(0, BATCH_MAX);
      });
      if (!batch || !batch.length) { if (!out.posted) out.status = batch ? "empty" : "locked"; break; }
      let status = 0;
      try {
        const r = await fetchImpl(`${config.serverUrl}/api/actions`, { method: "POST", headers: { "Content-Type": "application/json", "X-Install-Token": token }, body: JSON.stringify({ v: 1, records: batch }), signal: AbortSignal.timeout(POST_TIMEOUT_MS) });
        status = r.status;
      } catch { status = 0; }
      out.httpStatus = status;
      const ok = status >= 200 && status < 300;
      const sent = new Set(batch.map((r) => r.seq));
      withLock(dir, (held) => {
        if (!held) return;
        const st = readTrailState(dir);
        if (ok) {
          const q = readQueue(dir);
          const kept = q.records.filter((r) => !sent.has(r.seq));
          st.dropped += q.bad;
          st.bytes = writeQueue(dir, kept);
          st.count = kept.length;
          st.oldest = kept.length ? tsMs(kept[0]) : 0;
          st.rejects = 0;
          st.retryAt = 0;
        } else {
          st.rejects = Math.min(32, st.rejects + 1);
          st.retryAt = now() + backoffDelay(st.rejects);
        }
        writeState(dir, st);
      });
      if (!ok) { out.status = status ? "rejected" : "unreachable"; break; }
      out.posted += batch.length;
      out.batches++;
      out.status = "posted";
    }
  } catch { out.status = "error"; }
  finally {
    try { withLock(dir, (held) => { if (!held) return; const st = readTrailState(dir); st.lease = 0; writeState(dir, st); }); } catch { /* the lease runs out */ }
  }
  return out;
}
