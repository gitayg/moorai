// The CLIENT's answer to a server's sampling / elicitation request, judged before the server gets it, and a
// per-session sampling budget. Shared by the stdio guard (moorai-mcp-guard.mjs) and the HTTP gateway
// (../mcp-gateway/guard.mjs, ../mcp-gateway/server.mjs). ./sampling-scan.mjs judges the request on its way
// to the client; this module judges what goes back.
//
// THE GAP. A sampling answer is the client model's completion, and an elicitation answer is what the user
// typed. Both go to the MCP server. A server that asked the model to "summarise the conversation" or the
// user for "your API key" receives the answer unchecked.
//
// TWO SHAPES, both from the MCP specification (modelcontextprotocol.io/specification):
//   "response"  2024-11-05 .. 2025-11-25: the client's JSON-RPC response to the server's request; its result
//               is a CreateMessageResult (role, content, model, stopReason) or an ElicitResult (action,
//               content). Recognised by that shape, not by remembering the request's id.
//   "retry"     2026-07-28 (Multi Round-Trip Requests): the client retries the tools/call, resources/read or
//               prompts/get with params.inputResponses, "a map of client responses to the server requests"
//               (schema InputResponseRequestParams). Every value is read; a ListRootsResult (roots) is
//               skipped, any other value is scanned whole.
//
// THE SCAN. The `content` of each sampling and elicitation answer, with the data-loss detectors (secrets,
// personal data, cards and regulated data, source / IP: cli/mcp-outbound.mjs DLP_IDS) on the serialized
// JSON, then cli/mcp-outbound.mjs mergeOutbound on the same value: the values with their line breaks,
// base64 / data: content decoded and scanned, a labelled ZIP / PDF / OLE file's label against labelPolicy
// "send", and the over-sharing signal (#92, policy mcpOversharing). The outbound-argument check, on the
// answer instead of the arguments. #65 (local secret values) is not run on it.
//
// THE DECISION (signed policy only):
//   a finding whose action resolves to block / kill, an over-sharing "block",   refused, in every mode
//   or a labelled file labelPolicy blocks from being sent
//   policy.samplingResponseAction "block"                                        also refused on any finding
//   anything else (the default, "report")                                         forwarded, and reported
// Coach mode never refuses. An answer that could not be judged (the scan threw, no engine) or that holds
// encoded content past the decode caps follows failMode.mcpGateway: closed refuses it; open forwards it, and
// content past the caps is reported once per process and server.
//
// A REFUSAL. "response": the server gets, on the request's id, the JSON-RPC error the 2025-11-25 sampling
// spec lists for a refused sampling request ("User rejected sampling request: `-1`"), for an elicitation
// too; the stdio guard also writes the client a notifications/message from logger "moorai". The HTTP gateway
// cannot: the spec answers a POSTed response with 202 and no body. "retry": the retried request is not sent;
// the client gets an isError tool result (tools/call) or a JSON-RPC error (the others). The 2026-07-28 spec
// expects this: "Servers MUST NOT assume that clients will fulfill the inputRequests or retry the original
// request."
//
// THE BUDGET (SAF-T1112 "budget amplification"). policy.samplingBudget: false | { action, maxRequests,
// maxTokens, windowMin }: the sampling requests a server sends one session, and the maxTokens they state,
// inside a sliding window. action "report" (the default: one alert per limit per session), "block" (every
// sampling request past a limit is refused as ./sampling-scan.mjs refuses one), "off". A session is the
// stdio guard process, or the gateway route and Mcp-Session-Id. Elicitation is not counted.
//
// Content-free: alerts carry threat ids, categories, keyed hashes of matched spans, counts and the
// over-sharing signal names; never a byte of the answer.
import { decideText } from "../cli/hook-core.mjs";
import { mergeOutbound, dlpEngine, oversharingAlertFields, DLP_IDS } from "../cli/mcp-outbound.mjs";
import { outboundUnevaluatedAlert } from "../cli/mcp-outbound-fail.mjs";
import { gatewayFailAlert, gatewayFailReason } from "../cli/mcp-fail.mjs";
import { spanHash } from "../cli/span-hash.mjs";
import { REFUSED_CODE, refusalOf } from "./sampling-scan.mjs";

export const RESPONSE_STAGE = "sampling-response";
export const RETRY_METHODS = Object.freeze(["tools/call", "resources/read", "prompts/get"]);
export const SAMPLING_BUDGET_THREAT = 97;
export const BUDGET_CATEGORY = "MCP: sampling budget exceeded";
export const BUDGET_DEFAULTS = Object.freeze({ action: "report", maxRequests: 30, maxTokens: 100_000, windowMin: 60 });
const BUDGET_ACTIONS = ["report", "block", "off"];
const MAX_SESSIONS = 64, MAX_EVENTS = 10_000;
const isObj = (v) => v != null && typeof v === "object" && !Array.isArray(v);

export function answerKind(v) {
  if (!isObj(v)) return null;
  if (typeof v.role === "string" && "content" in v) return "sampling";
  if (typeof v.action === "string") return "elicitation";
  return Array.isArray(v.roots) ? null : "input";
}

// → { shape: "response" | "retry", answers: [{ kind, value }] } or null.
export function clientAnswersOf(msg) {
  if (!isObj(msg)) return null;
  if (msg.method == null) {
    if (msg.id == null || !isObj(msg.result)) return null;
    const kind = answerKind(msg.result);
    return kind && kind !== "input" ? { shape: "response", answers: [{ kind, value: msg.result }] } : null;
  }
  if (!RETRY_METHODS.includes(msg.method) || !isObj(msg.params) || !isObj(msg.params.inputResponses)) return null;
  const answers = [];
  for (const k of Object.keys(msg.params.inputResponses)) {
    const v = msg.params.inputResponses[k];
    const kind = answerKind(v);
    if (kind) answers.push({ kind, value: v });
  }
  return answers.length ? { shape: "retry", answers } : null;
}

export function responsePolicy(policy) {
  return { action: policy && policy.samplingResponseAction === "block" ? "block" : "report" };
}

// → { findings, refuse, reasons, unevaluated }. `refuse` ignores coach; the caller applies it.
export function judgeClientAnswers(engine, policy, answers, { server = "" } = {}) {
  const pick = [];
  for (const a of answers) {
    const v = a.kind === "input" ? a.value : a.value.content;
    if (v != null) pick.push(v);
  }
  if (!pick.length) return { findings: [], refuse: false, reasons: [], unevaluated: null };
  const args = JSON.stringify(pick);
  const d = decideText(dlpEngine(engine), policy, args, "prompt", { ctx: { egress: true }, only: DLP_IDS });
  mergeOutbound(d, { engine, policy, tool: "sampling", server, args, decide: decideText });
  const reasons = d.decision === "deny" ? d.reasons.filter((r) => !/\(needs sign-off\)$/.test(r)) : [];
  if (responsePolicy(policy).action === "block") for (const f of d.findings) reasons.push(`#${f.threatId} ${f.category}`);
  const uniq = [...new Set(reasons)];
  return { findings: d.findings, refuse: d.decision === "deny" || uniq.length > 0, reasons: uniq, unevaluated: d.unevaluated || null };
}

const kindOf = (found) => (found.answers.some((a) => a.kind === "sampling") ? "sampling" : found.answers.some((a) => a.kind === "elicitation") ? "elicitation" : "input");

// → { toServer, toClient }: what a surface writes in place of the answer.
export function answerRefusal(msg, shape, kind, reason) {
  if (shape === "response") {
    return {
      toServer: { jsonrpc: "2.0", id: msg.id, error: { code: REFUSED_CODE, message: `MoorAI refused to return this ${kind} answer: ${reason}` } },
      toClient: { jsonrpc: "2.0", method: "notifications/message", params: { level: "warning", logger: "moorai", data: `MoorAI did not return a ${kind} answer to this MCP server: ${reason}` } }
    };
  }
  const text = `MoorAI blocked this MCP request: the ${kind} answer it carries was refused: ${reason}`;
  return {
    toServer: null,
    toClient: msg.method === "tools/call"
      ? { jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text }], isError: true } }
      : { jsonrpc: "2.0", id: msg.id, error: { code: -32603, message: text } }
  };
}

// MOORAI_TEST_SAMPLINGRESPONSE_THROW: a test hook that makes judging an answer throw (the fail-mode path).
const ANSWER_THROW = Boolean(process.env.MOORAI_TEST_SAMPLINGRESPONSE_THROW);

// One surface's whole decision on a client answer. deps: { engine, policy, coach, server, toolPrefix,
// identity, post(alert), record(alert), failClosed() → {mode, source} | null, coachNote(what, reason),
// seenOnce(token) }. → null (forward the original) or { toServer, toClient }.
export function gateClientAnswer(msg, found, deps) {
  const kind = kindOf(found);
  const label = found.shape === "retry" ? (msg.method === "tools/call" && typeof msg.params.name === "string" ? msg.params.name : msg.method) : kind;
  const base = { stage: RESPONSE_STAGE, tool: `${deps.toolPrefix}:${label}`, mcpServer: deps.server, samplingKind: kind, samplingShape: found.shape };
  const emit = (a, record = true) => {
    const alert = { ...a, ...base, ts: new Date().toISOString(), ...deps.identity };
    try { deps.post(alert); } catch { /* evidence, not enforcement */ }
    if (record) { try { deps.record(alert); } catch { /* ledger is best-effort */ } }
  };
  const failed = (why) => {
    let fm = null;
    try { fm = deps.failClosed(); } catch { fm = null; }
    if (!fm) return null;
    emit(gatewayFailAlert({ stage: "mcp", why, source: fm.source, tool: label, server: deps.server, toolPrefix: deps.toolPrefix }));
    return answerRefusal(msg, found.shape, kind, gatewayFailReason(why));
  };
  let judged;
  try {
    if (ANSWER_THROW) throw new Error("injected sampling-response fault (test hook)");
    if (!deps.engine) { const e = new Error("no engine"); e.why = "no-engine"; throw e; }
    judged = judgeClientAnswers(deps.engine, deps.policy, found.answers, { server: deps.server });
  } catch (e) {
    return failed((e && e.why) || "error");
  }
  if (judged.unevaluated && !judged.refuse) {
    const ref = failed(judged.unevaluated.why);
    if (ref) return ref;
    let first = true;
    try { first = deps.seenOnce(`sampling-response-unevaluated|${deps.server}`); } catch { first = true; }
    if (first) emit(outboundUnevaluatedAlert(judged.unevaluated, { tool: label, server: deps.server, toolPrefix: deps.toolPrefix }));
  }
  const blocked = judged.refuse && !deps.coach;
  if (judged.refuse && deps.coach) { try { deps.coachNote(`MCP ${kind} answer to ${deps.server}`, judged.reasons.join(", ") || "policy"); } catch { /* a note */ } }
  for (const f of judged.findings) {
    emit({ threatId: f.threatId, category: f.category, riskLevel: blocked ? "Blocked" : f.riskLevel, decision: blocked ? "deny" : "notify", contentHash: spanHash(f.threatId, f.match || ""), ...oversharingAlertFields(f) });
  }
  return blocked ? answerRefusal(msg, found.shape, kind, judged.reasons.join(", ") || "policy") : null;
}

// policy.samplingBudget: false | { action?, maxRequests?, maxTokens?, windowMin? }. Absent → the defaults
// (report). An invalid field keeps its default; a limit of 0 is off.
export function budgetConfig(policy) {
  const v = isObj(policy) ? policy.samplingBudget : undefined;
  if (v === false) return { ...BUDGET_DEFAULTS, action: "off" };
  const out = { ...BUDGET_DEFAULTS };
  if (!isObj(v)) return out;
  if (BUDGET_ACTIONS.includes(v.action)) out.action = v.action;
  for (const k of ["maxRequests", "maxTokens"]) if (Number.isInteger(v[k]) && v[k] >= 0) out[k] = v[k];
  if (Number.isInteger(v.windowMin) && v.windowMin > 0) out.windowMin = v.windowMin;
  return out;
}

const statedTokens = (params) => (Number.isFinite(params.maxTokens) && params.maxTokens > 0 ? Math.floor(params.maxTokens) : 0);

// Per-session sliding-window counts. Holds timestamps, token counts and the session key only.
export function createSamplingBudget() {
  const sessions = new Map();
  return {
    // → { over: ["requests" | "tokens"], requests, tokens, cfg } after adding this message's requests.
    add(key, requests, cfg, now = Date.now()) {
      const k = String(key || "");
      let s = sessions.get(k);
      if (!s) {
        if (sessions.size >= MAX_SESSIONS) sessions.delete(sessions.keys().next().value);
        s = { events: [], said: new Set() };
      } else sessions.delete(k);
      sessions.set(k, s);
      const since = now - cfg.windowMin * 60_000;
      while (s.events.length && s.events[0].t <= since) s.events.shift();
      for (const r of requests) s.events.push({ t: now, tokens: statedTokens(r.params) });
      if (s.events.length > MAX_EVENTS) s.events.splice(0, s.events.length - MAX_EVENTS);
      const count = s.events.length;
      let tokens = 0;
      for (const e of s.events) tokens += e.tokens;
      const over = [];
      if (cfg.maxRequests && count > cfg.maxRequests) over.push("requests");
      if (cfg.maxTokens && tokens > cfg.maxTokens) over.push("tokens");
      const fresh = over.filter((x) => !s.said.has(x));
      for (const x of fresh) s.said.add(x);
      return { over, fresh, requests: count, tokens };
    }
  };
}

// The budget's decision on one server -> client message (found: ./sampling-scan.mjs serverRequestsOf).
// deps: { budget, sessionKey, policy, coach, server, toolPrefix, label, isToolCall, identity, post, record,
// coachNote }. → null (go on to the scan) or { toServer, toClient } (refused).
export function gateSamplingBudget(msg, found, deps) {
  try {
    const sampling = found.requests.filter((r) => r.kind === "sampling");
    if (!sampling.length) return null;
    const cfg = budgetConfig(deps.policy);
    if (cfg.action === "off") return null;
    const r = deps.budget.add(deps.sessionKey, sampling, cfg);
    if (!r.over.length) return null;
    const blocked = cfg.action === "block" && !deps.coach && msg.id != null;
    const reason = `this MCP server's sampling budget is used up (${r.requests} requests, ${r.tokens} tokens stated in ${cfg.windowMin} min; limits ${cfg.maxRequests} and ${cfg.maxTokens})`;
    if (cfg.action === "block" && deps.coach) { try { deps.coachNote(`MCP sampling request from ${deps.server}`, reason); } catch { /* a note */ } }
    for (const kind of blocked ? r.over : r.fresh) {
      const alert = {
        threatId: SAMPLING_BUDGET_THREAT, category: BUDGET_CATEGORY, riskLevel: blocked ? "Blocked" : "Low", decision: blocked ? "deny" : "notify",
        stage: "sampling", tool: `${deps.toolPrefix}:${deps.label || "sampling"}`, mcpServer: deps.server, samplingKind: "sampling", samplingShape: found.shape,
        budgetKind: kind, samplingRequests: r.requests, samplingTokens: r.tokens, budgetLimit: kind === "requests" ? cfg.maxRequests : cfg.maxTokens, windowMin: cfg.windowMin,
        contentHash: `mcp:sampling:budget:${kind}`, ts: new Date().toISOString(), ...deps.identity
      };
      try { deps.post(alert); } catch { /* evidence, not enforcement */ }
      try { deps.record(alert); } catch { /* ledger is best-effort */ }
    }
    return blocked ? refusalOf(msg, found.shape, "sampling", reason, { isToolCall: deps.isToolCall }) : null;
  } catch { return null; }
}
