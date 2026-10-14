// W3C Trace Context (www.w3.org/TR/trace-context/) for the requests MoorAI mediates: the model proxy →
// provider, the HTTP MCP gateway → upstream MCP server, and (as params._meta) the MCP stdio guard → its
// server. The W3C rules themselves (parsing traceparent, merging tracestate) live in ONE place,
// cli/trace-context.mjs, which the hook and the egress proxy use too; this file applies them to one request.
//
// One span per mediated request (cli/trace-context.mjs continueOrStart):
//   * a valid incoming traceparent CONTINUES that trace: its trace-id is kept, its parent-id becomes this
//     span's parentSpanId, and a new span id is the parent-id sent on. Its sampled flag is kept. A version
//     above 00 is read by the 00 layout (W3C 3.2.4) and sent on as version 00.
//   * otherwise, when the surface knows the agent session, the trace-id is traceIdFor(tenant, session) —
//     the id every MoorAI surface derives for that session (a keyed hash, never the session id itself);
//   * otherwise a new random trace. A new trace is sent sampled (01): MoorAI records the action.
//
// tracestate, merged per W3C (cli/trace-context.mjs mergeTracestate): the moorai entry
// ("moorai=a:<agentName>") goes first (left), an earlier moorai entry is removed, the other entries keep
// their order, at most 32. An incoming tracestate that is not a valid W3C list is not sent on, and a
// repeated key keeps its first entry. With no valid traceparent the incoming tracestate is not parsed and
// is not sent on ("If the vendor failed to parse traceparent, it MUST NOT attempt to parse tracestate").
//
// Content-free: a record carries traceId, spanId and parentSpanId (hex) only; no header value is logged,
// stored or reported, the incoming traceparent and tracestate included.
import { traceIdFor, continueOrStart } from "../cli/trace-context.mjs";

export { parseTraceparent, mergeTracestate } from "../cli/trace-context.mjs";
// A session key (an agent's session id as it states it) longer than this is not a session id.
export const MAX_SESSION_KEY = 256;

// tenantKey: the install token (the per-tenant secret the console mints, the key of every MoorAI keyed
// hash). agentName: this surface's agentName (cli/agent-names.mjs), for the tracestate entry; none → no
// moorai entry.
export function createTracer({ tenantKey = "", agentName } = {}) {
  const sessionTrace = (sessionKey) => (typeof sessionKey === "string" && sessionKey && sessionKey.length <= MAX_SESSION_KEY ? traceIdFor({ tenantKey: String(tenantKey || ""), sessionKey }) : null);
  // → { traceId, spanId, parentSpanId?, sampled, source: "incoming"|"session"|"new", traceparent, tracestate }
  // (tracestate "" when there is none to send).
  return function start({ traceparent, tracestate, sessionKey } = {}) {
    const session = sessionTrace(sessionKey);
    const t = continueOrStart({ traceparent, tracestate, traceId: session, agentName });
    return { ...t, source: t.parentSpanId ? "incoming" : session ? "session" : "new", tracestate: t.tracestate || "" };
  };
}

// The record fields of a span: content-free hex only.
export const traceFields = (t) => (t && t.traceId ? { traceId: t.traceId, spanId: t.spanId, ...(t.parentSpanId ? { parentSpanId: t.parentSpanId } : {}) } : {});

// Outbound HTTP headers (keys lower-case, as Node's): traceparent replaced, tracestate set or removed.
export function applyTraceHeaders(h, t) {
  if (!t) return h;
  h.traceparent = t.traceparent;
  if (t.tracestate) h.tracestate = t.tracestate; else delete h.tracestate;
  return h;
}

// A request's model string as a record field: at most 64 characters of [A-Za-z0-9._:/@-], else none.
export const MODEL_RE = /^[A-Za-z0-9._:/@-]{1,64}$/;
export const cleanModel = (v) => (typeof v === "string" && MODEL_RE.test(v) ? v : undefined);
export const PROVIDERS = Object.freeze(["anthropic", "openai", "google", "ollama", "other"]);
