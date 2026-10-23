// Intent alignment in the model proxy: does a tool call the model returns fit what the person asked for?
// The per-session state and the judgement are data/intent-server.mjs (createIntentStore, over the lexical
// logic in data/intent-alignment.js, the hook's own); this file supplies what only the proxy knows — the
// session a request belongs to, the person's turns in it, and the proxy's report / enforce behaviour.
//
// SESSION. The first of, per request:
//   1. X-MoorAI-Session-Id                an application names its session explicitly (≤ 256 characters);
//   2. X-Claude-Code-Session-Id           Claude Code's own session id (the id its hooks get);
//   3. the incoming W3C traceparent's trace-id, when the request carries a valid one (trace-w3c.mjs
//                                         source "incoming"): one agent run under one trace is one task;
//   4. the conversation itself: a keyed hash of its first user turn. Every request re-sends the whole
//                                         conversation, so its first turn names it on every turn;
//   5. none of these (no header, no trace, no user turn): the one session "none", where nothing is ever
//                                         captured, so a risky call there is judged "task-unknown".
// The explicit names win over the trace because a trace can span several conversations (a workflow trace
// around many agent runs), which would merge their tasks. The id goes to the store with its source as a
// prefix (hdr: / cc: / trace: / conv:); the store keeps only its keyed hash.
//
// TASK. From each request's real user turns (user-turns.mjs; never a system prompt, tool result, function
// response or document, and never a harness block such as Claude Code's <system-reminder> with CLAUDE.md and
// memory): the first turn, the task, and the latest turn — but only on a session's first captured request. Once
// a session has a captured task, a later request adds only its latest user turn: every request re-sends the
// conversation, and its first turn is the client's to rewrite (or, after compaction, a summary), so it is never
// re-learned. The proxy keeps which sessions it captured (keyed hashes of the ids, at most STORE_LIMITS.maxSessions, for
// STORE_LIMITS.ttlMs); a session the store evicted while the proxy still holds it is restored from its latest
// turn only, which can only make a call look less aligned. Two conditions, both or nothing:
//   * the request declares tools (user-turns.mjs carriesTools). A tool-less request is a side request
//     (WebFetch's summariser, whose user turn is the fetched page; compaction; a title) and adds nothing;
//   * the provider accepted it: the turns are captured when its 2xx response begins (commit), before any tool
//     call in that response is judged. A request the provider rejects adds nothing.
// The store holds feature hashes only; a turn's text is in memory for the call.
//
// WHOSE "USER" TURN. In an agent-to-agent call (a sub-agent: Claude Code's Task / Agent tool) the first user
// turn is the parent model's prompt, not the person's; this proxy cannot tell the two apart, so it judges the
// sub-agent's calls against what the parent model wrote. For a task that is the person's by construction, name
// the session (X-MoorAI-Session-Id) and set its task over the explicit channel — moorai-serve's POST /v1/task,
// or the Agent SDK's capture — rather than relying on the turns this proxy sees.
//
// COMPACTION. When Claude Code compacts a conversation, the model-written summary of the earlier turns becomes the
// first user turn ("This session is being continued from a previous conversation that ran out of context. …").
// It repeats whatever those turns quoted, so a turn that opens with that sentence is never captured
// (user-turns.mjs isCompactionSummary), and a session captured before compaction keeps its task and adds only
// the latest turn. A session the proxy first sees after compaction starts from the person's next turn. Another
// harness's own summary wording is not recognised and counts as a person's turn.
//
// A BODY THAT CANNOT BE PARSED (a gzip-encoded request, a leading byte-order mark): no turns, so nothing is
// captured, and the session is the header's or the trace's, else "none" — a risky call is still judged, and in
// a session with no task it is task-unknown.
//
// NO TASK. The store answers class "task-unknown" (aligned: false) for a risky call in a session with no live
// captured task: never captured (a request with no real user turn), evicted or expired. It is handled like
// any misaligned call: an alert, and in --mode enforce the ask or the block.
//
// OWNER. The store's optional owner principal (so one caller cannot evict another's sessions) is not passed:
// every client of one proxy holds the same token, so the proxy has no per-client principal to give. One
// consequence: X-MoorAI-Session-Id is the client's to choose, so a client of this proxy that names another
// client's session id adds its own turns to that session's task.
//
// JUDGEMENT. Each tool call the model returns, on every reading of it that maps to the hook's tool vocabulary
// (check.mjs: as sent, a `cmd` alias, a dispatcher's inner tool …; the strictest verdict wins), after
// the proxy's own verdict on it and not when that verdict is a deny. intentModeFromPolicy(policy):
//   off     nothing;
//   report  (default) the first misaligned call per target raises one content-free alert;
//   ask     as report, and in --mode enforce the call is an ask, settled by server mode's headless rule
//           (deny unless --headless-ask allow-with-report) exactly as a functionToolActions ask is;
//   block   as report, and in --mode enforce the call is denied: the proxy's refusal (or the replacement
//           text with --denied-tool-call replace).
// In --mode report nothing is withheld; an ask or block outcome is stamped enforcement LIMITED (report.mjs).
//
// THE ALERT. The hook's own category and reason code: category "Action outside the stated task" (threatId 64,
// riskLevel Medium, stage "behavior"), reasonCode INTENT_MISMATCH (cli/provenance.mjs), tool
// "model-proxy:<name>", the class (egress | credentials | destructive | mcp-write | moorai-control |
// task-unknown) and the mode, and
// contentHash = the tenant-keyed hash of the class and the store's keyed target hash. Never a prompt, a
// path, a host or an argument.
//
// THE KEY. One HMAC key per process for the store and the conversation hash: read from --intent-key-file
// (64 hex characters, in a file owned by root and not group- or world-writable, readRootOwned; on Windows a
// protected file) so several proxy replicas hash alike, else 32 random bytes at start. It never leaves the
// process. A restart with a random key forgets every session, which costs nothing here: the next request
// re-sends the conversation and its first turn is captured again.
import { createHmac, randomBytes } from "node:crypto";
import { REASON } from "../cli/provenance.mjs";
import { settleHeadlessAsk } from "../cli/server-mode.mjs";
import { readRootOwned } from "../cli/hook-core.mjs";
import { CLASS_TEXT as HOOK_CLASS_TEXT } from "../cli/intent-alignment.mjs";
import { userTurns, carriesTools } from "./user-turns.mjs";

export const SESSION_ID_HEADER = "x-moorai-session-id";
export const CLAUDE_SESSION_HEADER = "x-claude-code-session-id";
export const MAX_SESSION_ID = 256;
export const NO_SESSION = "none";
const CLASS_TEXT = { ...HOOK_CLASS_TEXT, "task-unknown": "no request from you was seen in this session" };
export const STORE_LIMITS = Object.freeze({ maxSessions: 1024, ttlMs: 24 * 3600 * 1000, maxFeatures: 512 });
export const CATEGORY = "Action outside the stated task";

// { key: Buffer, source: "option" | "file" | "random" }. A key file that is missing, writable by others or
// not 64 hex characters falls back to a random key, said once on stderr.
export function loadIntentKey({ key, keyFile, read = readRootOwned, warn = (m) => process.stderr.write(m) } = {}) {
  if (key) return { key: Buffer.isBuffer(key) ? key : Buffer.from(String(key)), source: "option" };
  if (keyFile) {
    const t = String(read(keyFile) || "").trim();
    if (/^[0-9a-f]{64}$/i.test(t)) return { key: Buffer.from(t, "hex"), source: "file" };
    try { warn("moorai-model-proxy: --intent-key-file is missing, not root-owned and protected, or not 64 hex characters; using a random per-process key\n"); } catch { /* a warning */ }
  }
  return { key: randomBytes(32), source: "random" };
}

const header = (headers, name) => { const v = headers && headers[name]; return typeof v === "string" && v && v.length <= MAX_SESSION_ID ? v : null; };

// The session id for a request (see SESSION above); NO_SESSION when nothing names one.
export function sessionOf({ headers, trace, turns, hmac }) {
  const explicit = header(headers, SESSION_ID_HEADER);
  if (explicit) return `hdr:${explicit}`;
  const cc = header(headers, CLAUDE_SESSION_HEADER);
  if (cc) return `cc:${cc}`;
  if (trace && trace.source === "incoming" && trace.traceId) return `trace:${trace.traceId}`;
  return turns.length ? `conv:${hmac(`conv\0${turns[0]}`)}` : NO_SESSION;
}

// lib: { createIntentStore, intentModeFromPolicy } (data/intent-server.mjs, or a test double). A store that
// cannot be created leaves intent alignment off for this process, said once on stderr; a policy whose mode
// cannot be read is "off".
export function createIntent({ lib, key, rt, enforce, now, warn = (m) => process.stderr.write(m) }) {
  let store = null;
  try { store = lib.createIntentStore({ key, ...STORE_LIMITS, ...(now ? { now } : {}) }); } catch {
    try { warn("moorai-model-proxy: intent alignment is unavailable (data/intent-server.mjs did not start); tool calls are not judged against the task\n"); } catch { /* a warning */ }
  }
  const hmac = (s) => createHmac("sha256", key).update(s, "utf8").digest("base64url");
  // The sessions that have a captured task (TASK above): session id → when last captured, LRU, bounded.
  const clock = typeof now === "function" ? now : Date.now;
  const known = new Map();
  const captured = (id) => { const sid = hmac(`known\0${id}`), t = known.get(sid); if (t === undefined) return false; if (clock() - t >= STORE_LIMITS.ttlMs) { known.delete(sid); return false; } return true; };
  const remember = (id) => { const sid = hmac(`known\0${id}`); known.delete(sid); known.set(sid, clock()); while (known.size > STORE_LIMITS.maxSessions) known.delete(known.keys().next().value); };
  const modeOf = (policy) => { try { const m = lib.intentModeFromPolicy(policy); return ["off", "report", "ask", "block"].includes(m) ? m : "off"; } catch { return "off"; } };

  // Per request, after the body is read (json null when it could not be parsed): the context the judge needs,
  // or null. The turns are held until commit(ctx).
  function begin(kind, json, headers, trace, policy) {
    if (!store) return null;
    const mode = modeOf(policy);
    if (mode === "off") return null;
    const turns = json ? userTurns(kind, json) : [];
    const sessionId = sessionOf({ headers, trace, turns, hmac });
    const firstTurns = captured(sessionId) ? [] : [turns[0]];
    const pending = carriesTools(kind, json) ? [...new Set([...firstTurns, turns[turns.length - 1]])].filter(Boolean) : [];
    return { sessionId, mode, pending };
  }
  // The provider answered 2xx: capture the task. Once per request.
  function commit(ctx) {
    if (!ctx || !store) return;
    const turns = ctx.pending;
    ctx.pending = [];
    for (const t of turns) {
      try { store.captureTask(ctx.sessionId, t); } catch { /* not captured: the store answers task-unknown */ }
    }
    if (turns.length) remember(ctx.sessionId);
  }

  // check.mjs calls this for a mapped tool call whose verdict is not a deny. Returns the verdict that replaces
  // it, or null to keep it.
  async function judge(ctx, tool, input, findings, name, verdict) {
    if (!ctx || !store) return null;
    let r;
    try { r = store.judge(ctx.sessionId, tool, input, findings || []); } catch { return null; }
    if (!r || r.aligned) return null;
    const s = await rt.ready();
    const label = String(name || tool).replace(/[^A-Za-z0-9_.:\-]/g, "_").slice(0, 64);
    const cls = String(r.class || "unknown").replace(/[^a-z0-9\-]/g, "_").slice(0, 32);
    const why = `action outside the stated task — ${CLASS_TEXT[cls] || cls}`;
    const prov = { prov: { policyId: s.policyId, policySource: s.source, event: "PreToolUse" } };
    if (r.firstForTarget) {
      rt.reporter.post({
        threatId: 64, category: CATEGORY, riskLevel: "Medium", stage: "behavior", tool: `model-proxy:${label}`,
        decision: ctx.mode === "block" ? "deny" : ctx.mode === "ask" ? "ask" : "notify", reasonCode: REASON.INTENT_MISMATCH,
        contentHash: rt.hash(`intent:${cls}:${String(r.targetHash || "")}`), intent: { class: cls, mode: ctx.mode }
      }, prov);
    }
    if (!enforce || ctx.mode === "report") return null;
    if (ctx.mode === "block") return { decision: "deny", reasons: [why] };
    if (verdict && verdict.decision === "ask") return { ...verdict, reasons: [...(verdict.reasons || []), why] };
    if (rt.settings.passThrough) return { decision: "ask", reasons: [why] };
    const h = settleHeadlessAsk({ active: true, headless: rt.settings.headless }, s.policy, { decision: "ask", reason: `needs justification ${why}`, tool: label });
    if (h.alert) rt.reporter.post({ ...h.alert, tool: `model-proxy:${label}`, reasonCode: REASON.HEADLESS_ASK, enforcement: h.decision === "deny" ? "STRENGTHENED" : "LIMITED" }, prov);
    return { decision: h.decision, reasons: [h.reason] };
  }

  return { begin, commit, judge, get active() { return store !== null; }, size: () => { try { return store ? store.size() : 0; } catch { return 0; } } };
}
