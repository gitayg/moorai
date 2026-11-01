// Server -> client SAMPLING and ELICITATION requests, judged before the client sees them. Shared by the
// stdio guard (moorai-mcp-guard.mjs) and the HTTP gateway (../mcp-gateway/guard.mjs).
//
// THE GAP. resultOfResponse (./tool-scan.mjs) rejects any message with a `method`, so a server's own
// request to the client — `sampling/createMessage` (run this prompt on your model) or `elicitation/create`
// (ask your user this) — was never scanned. A server can use sampling to put instructions in front of the
// client's model, and `includeContext` to ask the client to send its conversation context back.
//
// TWO SHAPES, both from the MCP specification (modelcontextprotocol.io/specification):
//   "request"         2024-11-05 .. 2025-11-25: a JSON-RPC request from the server, with an id, whose
//                     method is sampling/createMessage or elicitation/create. The client answers it.
//   "input_required"  2026-07-28 (Multi Round-Trip Requests): "Servers MUST send server-to-client requests
//                     (such as roots/list, sampling/createMessage, or elicitation/create) using the MRTR
//                     pattern" — the result of a tools/call, resources/read or prompts/get carries
//                     result.inputRequests, a map of { method, params }, and the client retries the call
//                     with the answers.
//
// THE TEXT scanned: for sampling, systemPrompt, messages (every content block's strings; image and audio
// `data` are skipped, as in the result harvest), request-scoped tools and stopSequences; for elicitation,
// message, url and requestedSchema. Every inputRequests entry is read. The text is bounded like a tool result
// (./tool-scan.mjs CAPS.maxResultBytes / maxResultNodes / maxResultDepth); a request with text past those
// bounds is NOT JUDGED: a finding in the part that was read still refuses it as below, and otherwise it
// follows the gateway fail mode (refused when closed; forwarded and reported, threat id 0, when open).
// The engine and stage are the result stage's: decideInbound at "file", door surface, no masking — a
// request is refused or forwarded whole, never rewritten.
//
// THE DECISION (signed policy only; nothing user-writable is read here):
//   any finding whose action resolves to block / kill      refused, in every mode (the result stage's rule)
//   policy.samplingScanAction "block"                       also refused when a finding carries
//                                                           instructions (prompt-scan INSTRUCTION_THREATS:
//                                                           injection, tool / rules poisoning, invisible
//                                                           text, system-prompt extraction)
//   policy.samplingContextAction "block"                    also refused when includeContext is
//                                                           "thisServer" or "allServers"
//   anything else (the default)                             forwarded, and reported
// includeContext "allServers" (Medium) or "thisServer" (Low) is reported whatever the action: the server
// is asking the client to share context with it (the spec deprecates both values). Coach mode (unenrolled,
// unmanaged) never refuses. A request that could not be judged (the scan failed, no engine, or text past the
// scan bounds) follows the gateway fail mode (cli/mcp-fail.mjs): forwarded when open, refused when closed;
// text past the bounds is also reported when open ("MCP: sampling request not fully evaluated", Medium).
//
// A REFUSAL. "request" shape: the server gets a JSON-RPC error on the request's id, code -1 (the spec's
// "User rejected sampling request"), and the client gets a notifications/message saying MoorAI refused one,
// so the client never holds the request. "input_required" shape: the client gets, on the response's id, an
// isError tool result for a tools/call and a JSON-RPC error for anything else; the server never gets the
// answers it asked for.
//
// Content-free: alerts carry the threat id, category, a keyed hash of the matched span, the request kind
// and the includeContext value — never a byte of the prompt.
import { decideInbound, inboundText } from "../cli/inbound.mjs";
import { threatActionFor } from "../cli/hook-core.mjs";
import { promptBlockers } from "../cli/prompt-scan.mjs";
import { gatewayFailAlert, gatewayFailReason } from "../cli/mcp-fail.mjs";
import { spanHash } from "../cli/span-hash.mjs";
import { BINARY_KEYS, CAPS } from "./tool-scan.mjs";
import { REASON } from "../cli/provenance.mjs";

export const SERVER_REQUEST_KINDS = Object.freeze({ "sampling/createMessage": "sampling", "elicitation/create": "elicitation" });
export const REFUSED_CODE = -1;
export const SAMPLING_STAGE = "sampling";
// The threat id the includeContext alert carries: #91 MCP server asks the client to share its context.
export const CONTEXT_THREAT = 91;

const SAMPLING_FIELDS = ["systemPrompt", "messages", "tools", "stopSequences"];
const ELICIT_FIELDS = ["message", "url", "requestedSchema"];
const isObj = (v) => v != null && typeof v === "object" && !Array.isArray(v);

// → { shape: "request" | "input_required", requests: [{ kind, params }] } or null.
export function serverRequestsOf(msg) {
  if (!isObj(msg)) return null;
  if (msg.method != null) {
    const kind = typeof msg.method === "string" && Object.hasOwn(SERVER_REQUEST_KINDS, msg.method) ? SERVER_REQUEST_KINDS[msg.method] : null;
    if (!kind || msg.id == null) return null;
    return { shape: "request", requests: [{ kind, params: isObj(msg.params) ? msg.params : {} }] };
  }
  const r = msg.result;
  if (!isObj(r) || !isObj(r.inputRequests)) return null;
  const requests = [];
  for (const k of Object.keys(r.inputRequests)) {
    const v = r.inputRequests[k];
    if (isObj(v) && typeof v.method === "string" && Object.hasOwn(SERVER_REQUEST_KINDS, v.method)) requests.push({ kind: SERVER_REQUEST_KINDS[v.method], params: isObj(v.params) ? v.params : {} });
  }
  return requests.length ? { shape: "input_required", requests } : null;
}

function requestParts(requests) {
  const parts = [];
  for (const r of requests || []) {
    const pick = {};
    for (const k of r.kind === "sampling" ? SAMPLING_FIELDS : ELICIT_FIELDS) if (r.params[k] != null) pick[k] = r.params[k];
    parts.push(pick);
  }
  return parts;
}

// The strings a scan reads from the picked fields, in order: object values and array items (stopSequences,
// an enum), `data` / `blob` skipped (image and audio bytes), within the result stage's bounds (bytes, nodes,
// depth). → { text, complete }: complete is false when the walk stopped with something left unread.
export function harvestRequests(requests) {
  const parts = requestParts(requests);
  const out = [];
  let nodes = CAPS.maxResultNodes, bytes = CAPS.maxResultBytes + 1, complete = true;
  const walk = (node, depth) => {
    const arr = Array.isArray(node), keys = arr ? null : Object.keys(node), n = arr ? node.length : keys.length;
    if (!n) return;
    if (depth > CAPS.maxResultDepth || nodes <= 0) { complete = false; return; }
    nodes--;
    for (let i = 0; i < n && complete; i++) {
      const k = arr ? null : keys[i], v = arr ? node[i] : node[k];
      if (typeof v === "string") {
        if (!v || (k !== null && BINARY_KEYS.has(k))) continue;
        if (v.length + 1 > bytes) { out.push(v.slice(0, bytes - 1)); complete = false; return; }
        bytes -= v.length + 1;
        out.push(v);
      } else if (v && typeof v === "object") walk(v, depth + 1);
    }
  };
  if (parts.length) walk(parts, 0);
  return { text: out.length ? inboundText(out.join("\n")) : "", complete };
}

export function serverRequestText(requests) {
  return harvestRequests(requests).text;
}

// The widest includeContext any sampling request asks for: "allServers", "thisServer" or null.
export function contextAsked(requests) {
  let out = null;
  for (const r of requests || []) {
    if (r.kind !== "sampling") continue;
    const c = r.params.includeContext;
    if (c === "allServers") return "allServers";
    if (c === "thisServer") out = "thisServer";
  }
  return out;
}

export function samplingPolicy(policy) {
  return {
    action: policy && policy.samplingScanAction === "block" ? "block" : "report",
    context: policy && policy.samplingContextAction === "block" ? "block" : "report"
  };
}

// → { findings, context, refuse, contextRefused, reasons, complete }. `refuse` ignores coach; the caller
// applies it. complete: false when text past the scan bounds was not read.
export function judgeServerRequests(engine, policy, requests) {
  const { text, complete } = harvestRequests(requests);
  const context = contextAsked(requests);
  const pol = samplingPolicy(policy);
  const d = text ? decideInbound(engine, policy, text, { surface: "door", stage: "file", mask: false }) : { decision: "allow", reasons: [], findings: [] };
  const reasons = [];
  if (d.decision === "deny") reasons.push(...d.reasons.filter((r) => !/\(needs sign-off\)$/.test(r)));
  if (pol.action === "block") for (const f of promptBlockers(d.findings, (id) => threatActionFor(policy, id))) reasons.push(`#${f.threatId} ${f.category}`);
  const contextRefused = Boolean(context && pol.context === "block");
  if (contextRefused) reasons.push(`includeContext "${context}"`);
  const uniq = [...new Set(reasons)];
  return { findings: d.findings, context, refuse: d.decision === "deny" || uniq.length > 0, contextRefused, reasons: uniq, complete };
}

// The content-free alerts for one judged message. Findings on an "input_required" result that is
// forwarded are left to the result stage, which scans the same result and reports them there.
export function serverRequestAlerts({ judged, blocked, shape, kind, label, toolPrefix, server, ts = new Date().toISOString() }) {
  const out = [];
  const tool = `${toolPrefix}:${label || kind}`;
  const base = { stage: SAMPLING_STAGE, tool, mcpServer: server, samplingKind: kind, samplingShape: shape, ts };
  if (shape === "request" || blocked) {
    for (const f of judged.findings) {
      out.push({ threatId: f.threatId, category: f.category, riskLevel: blocked ? "Blocked" : f.riskLevel, decision: blocked ? "deny" : "notify", ...base, contentHash: spanHash(f.threatId, f.match || "") });
    }
  }
  if (judged.context) {
    const refused = blocked && judged.contextRefused;
    out.push({
      threatId: CONTEXT_THREAT, category: `MCP: sampling request asks for ${judged.context} context`,
      riskLevel: refused ? "Blocked" : judged.context === "allServers" ? "Medium" : "Low",
      decision: refused ? "deny" : "notify", includeContext: judged.context, ...base, contentHash: `mcp:sampling:context:${judged.context}`
    });
  }
  return out;
}

export function refusalNotice(kind, reason) {
  return { jsonrpc: "2.0", method: "notifications/message", params: { level: "warning", logger: "moorai", data: `MoorAI refused a ${kind} request from this MCP server: ${reason}` } };
}

// → { toServer, toClient }: what a surface writes in place of the message.
export function refusalOf(msg, shape, kind, reason, { isToolCall = false } = {}) {
  if (shape === "request") {
    return { toServer: { jsonrpc: "2.0", id: msg.id, error: { code: REFUSED_CODE, message: `MoorAI refused this ${kind} request: ${reason}` } }, toClient: refusalNotice(kind, reason) };
  }
  const text = `MoorAI blocked this MCP ${kind} request: ${reason}`;
  return {
    toServer: null,
    toClient: isToolCall
      ? { jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text }], isError: true } }
      : { jsonrpc: "2.0", id: msg.id, error: { code: -32603, message: text } }
  };
}

// MOORAI_TEST_SAMPLINGSCAN_THROW: a test hook that makes judging a server request throw (the fail-mode path).
const SCAN_THROW = Boolean(process.env.MOORAI_TEST_SAMPLINGSCAN_THROW);

// One surface's whole decision. deps: { engine, policy, coach, server, toolPrefix, label, isToolCall,
// identity, post(alert), record(alert), failClosed() → {mode, source} | null, coachNote(what, reason) }.
// → null (forward the original) or { toServer, toClient }.
export function gateServerRequest(msg, found, deps) {
  const kind = found.requests.some((r) => r.kind === "sampling") ? "sampling" : "elicitation";
  const label = deps.label || kind;
  let judged;
  try {
    if (SCAN_THROW) throw new Error("injected sampling-scan fault (test hook)");
    if (!deps.engine) { const e = new Error("no engine"); e.why = "no-engine"; throw e; }
    judged = judgeServerRequests(deps.engine, deps.policy, found.requests);
  } catch (e) {
    const why = (e && e.why) || "error";
    let fm = null;
    try { fm = deps.failClosed(); } catch { fm = null; }
    if (!fm || msg.id == null) return null;
    try { deps.post({ ...gatewayFailAlert({ stage: "result", why, source: fm.source, tool: label, server: deps.server, toolPrefix: deps.toolPrefix }), stage: SAMPLING_STAGE, samplingKind: kind, samplingShape: found.shape, ts: new Date().toISOString(), ...deps.identity }); } catch { /* evidence, not enforcement */ }
    return refusalOf(msg, found.shape, kind, gatewayFailReason(why), { isToolCall: deps.isToolCall });
  }
  // Text past the scan bounds was not read: unless what was read already refuses it, the fail mode decides.
  if (!judged.complete && !judged.refuse) {
    let fm = null;
    try { fm = deps.failClosed(); } catch { fm = null; }
    const refused = Boolean(fm) && msg.id != null;
    const a = refused
      ? { ...gatewayFailAlert({ stage: "result", why: "size", source: fm.source, tool: label, server: deps.server, toolPrefix: deps.toolPrefix }), stage: SAMPLING_STAGE }
      : { threatId: 0, category: `MCP: ${kind} request not fully evaluated`, riskLevel: "Medium", stage: SAMPLING_STAGE, tool: `${deps.toolPrefix}:${label}`, decision: "notify", basisCode: REASON.UNEVALUATED_SIZE_CAP, failMode: "open", failWhy: "size", mcpServer: deps.server, contentHash: `mcp:${kind}:unevaluated:size` };
    const alert = { ...a, samplingKind: kind, samplingShape: found.shape, ts: new Date().toISOString(), ...deps.identity };
    try { deps.post(alert); } catch { /* evidence, not enforcement */ }
    try { deps.record(alert); } catch { /* ledger is best-effort */ }
    if (refused) return refusalOf(msg, found.shape, kind, gatewayFailReason("size"), { isToolCall: deps.isToolCall });
  }
  const blocked = judged.refuse && !deps.coach && msg.id != null;
  if (judged.refuse && deps.coach) { try { deps.coachNote(`MCP ${kind} request from ${deps.server}`, judged.reasons.join(", ") || "policy"); } catch { /* a note */ } }
  for (const a of serverRequestAlerts({ judged, blocked, shape: found.shape, kind, label, toolPrefix: deps.toolPrefix, server: deps.server })) {
    const alert = { ...a, ...deps.identity };
    try { deps.post(alert); } catch { /* evidence, not enforcement */ }
    try { deps.record(alert); } catch { /* ledger is best-effort */ }
  }
  return blocked ? refusalOf(msg, found.shape, kind, judged.reasons.join(", ") || "policy", { isToolCall: deps.isToolCall }) : null;
}
