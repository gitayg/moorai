// W3C Trace Context for MoorAI: one trace per agent session, so a SIEM or APM can join an agent action, the
// model call, the MCP call and the downstream API it led to. Content-free: only hex ids and an agent name
// from the console's vocabulary ever leave.
//
//   traceIdFor({ tenantKey, sessionKey })  32 hex, deterministic: HMAC-SHA-256 under the tenant key that
//                                           cli/content-hash.mjs uses (deriveKey of the install token),
//                                           over a trace-only label and the agent's own session id. Every
//                                           surface that holds the install token and sees the session id
//                                           (the hook's session_id, Claude Code's x-claude-code-session-id
//                                           request header, CLAUDE_CODE_SESSION_ID in a stdio MCP server's
//                                           environment) derives the same id. The raw session id is never
//                                           in it and cannot be recovered from it without the tenant key.
//                                           tenantKey: the install token (string) or the derived key
//                                           (Buffer); both give the same id. No key or no session id: null,
//                                           and the caller starts a random trace (newTraceId).
//   newTraceId() / newSpanId()              random, never all zeros.
//   parseTraceparent(header)                W3C → { traceId, parentSpanId, flags, sampled } (flags a
//                                           number), or null. Version 00 is exactly the 00 layout; a higher
//                                           version (not ff) is read by the 00 layout (W3C 3.2.4: at least
//                                           55 characters, the flags followed by the end or a dash).
//   formatTraceparent({ traceId, spanId, sampled }) → "00-<traceId>-<spanId>-01|00", or null for a bad id.
//   tracestateMoorai({ agentName })         "moorai=a:<agentName>", agentName from cli/agent-names.mjs
//                                           only; null otherwise.
//   mergeTracestate(incoming, entry)        W3C mutation: the entry's key moves to the front, the other
//                                           members keep their order, at most 32 members. An incoming
//                                           header that is not a valid W3C list (a member off the grammar,
//                                           or more than 32 members) is discarded whole; a repeated key
//                                           keeps its first entry. This is the one implementation: the
//                                           model proxy, the HTTP MCP gateway and the stdio guard use it
//                                           through model-proxy/trace-w3c.mjs.
//   continueOrStart({ traceparent, tracestate, traceId, sampled, agentName })
//                                           one outbound hop: continues a valid incoming traceparent (its
//                                           traceId kept, parentSpanId = its span), else uses traceId (from
//                                           traceIdFor), else a random trace. → { traceId, spanId,
//                                           parentSpanId?, sampled, traceparent, tracestate? }.
import { createHmac, randomBytes } from "node:crypto";
import { deriveKey } from "./content-hash.mjs";
import { agentNameOf } from "./agent-names.mjs";

export const TRACE_LABEL = "moorai/trace-id/v1";
export const TRACESTATE_MAX = 32;
export const TRACE_ID_RE = /^[0-9a-f]{32}$/;
export const SPAN_ID_RE = /^[0-9a-f]{16}$/;
const ZERO = /^0+$/;
export const validTraceId = (v) => typeof v === "string" && TRACE_ID_RE.test(v) && !ZERO.test(v);
export const validSpanId = (v) => typeof v === "string" && SPAN_ID_RE.test(v) && !ZERO.test(v);

function keyOf(tenantKey) {
  if (tenantKey instanceof Uint8Array) return tenantKey.length ? tenantKey : null;
  if (typeof tenantKey === "string" && tenantKey) return deriveKey(tenantKey);
  return null;
}

export function traceIdFor({ tenantKey, sessionKey } = {}) {
  const key = keyOf(tenantKey);
  if (!key || typeof sessionKey !== "string" || !sessionKey) return null;
  const h = createHmac("sha256", key).update(`${TRACE_LABEL}\n${sessionKey}`, "utf8").digest("hex").slice(0, 32);
  return ZERO.test(h) ? `${h.slice(0, 31)}1` : h;
}

function randomHex(bytes) {
  for (;;) { const h = randomBytes(bytes).toString("hex"); if (!ZERO.test(h)) return h; }
}
export const newTraceId = () => randomHex(16);
export const newSpanId = () => randomHex(8);

// W3C 3.2.4: version 00 is exactly version-format; "If a higher version is detected, the implementation
// SHOULD try to parse it": under 55 characters restarts the trace, and the 2 flag characters must be "either
// the end of the string or a dash". Version ff is invalid. Optional whitespace (RFC 7230 OWS: spaces and
// tabs) around the value is ignored.
const TRACEPARENT_RE = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(?:$|-)/;
const OWS_EDGES = /^[ \t]+|[ \t]+$/g;
export function parseTraceparent(header) {
  if (typeof header !== "string") return null;
  const h = header.replace(OWS_EDGES, "");
  const m = TRACEPARENT_RE.exec(h);
  if (!m) return null;
  const [, version, traceId, parentSpanId, f] = m;
  if (version === "ff" || (version === "00" && h.length !== 55) || ZERO.test(traceId) || ZERO.test(parentSpanId)) return null;
  const flags = parseInt(f, 16);
  return { traceId, parentSpanId, flags, sampled: (flags & 1) === 1 };
}

export function formatTraceparent({ traceId, spanId, sampled = true } = {}) {
  if (!validTraceId(traceId) || !validSpanId(spanId)) return null;
  return `00-${traceId}-${spanId}-${sampled ? "01" : "00"}`;
}

export function tracestateMoorai({ agentName } = {}) {
  const n = agentNameOf(agentName);
  return n ? `moorai=a:${n}` : null;
}

// W3C tracestate (3.3.1): a list of at most 32 list-members separated by commas; spaces and tabs around a
// member are ignored, and empty or whitespace-only members are allowed. A member is key "=" value: a key is
// a simple key (a lowercase letter, then up to 255 of [a-z0-9_*/-]) or tenant@system (a lowercase letter or
// digit, then up to 240 of them; "@"; a lowercase letter, then up to 13); a value is 1 to 256 printable
// ASCII characters, no "," or "=", not ending in a space.
const TS_KEY_RE = /^(?:[a-z][a-z0-9_\-*/]{0,255}|[a-z0-9][a-z0-9_\-*/]{0,240}@[a-z][a-z0-9_\-*/]{0,13})$/;
const TS_VALUE_RE = /^[\x20-\x2b\x2d-\x3c\x3e-\x7e]{0,255}[\x21-\x2b\x2d-\x3c\x3e-\x7e]$/;
const memberKey = (m) => m.slice(0, m.indexOf("="));
// The members of a header (repeated headers are one list, RFC 7230 3.2.2), or [] when it is not a valid list:
// "If the tracestate header cannot be parsed the vendor MAY discard the entire header" (4.3). One entry per key
// (3.3.1.4): a repeated key keeps its first, left-most entry, the most recent position.
function members(header) {
  const raw = Array.isArray(header) ? header.join(",") : typeof header === "string" ? header : "";
  const out = [], seen = new Set();
  let n = 0;
  for (const part of raw.split(",")) {
    const m = part.replace(OWS_EDGES, "");
    if (!m) continue;
    if (++n > TRACESTATE_MAX) return [];
    const eq = m.indexOf("=");
    if (eq <= 0 || !TS_KEY_RE.test(m.slice(0, eq)) || !TS_VALUE_RE.test(m.slice(eq + 1))) return [];
    const k = m.slice(0, eq);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(m);
  }
  return out;
}
// Ours added to the front (3.5: "The new key/value pair SHOULD be added to the beginning of the list"), our
// earlier entry removed. Over 32 (3.3.1.5): whole entries go, those over 128 characters first, then from the
// end; ours is never the one dropped. → the merged header, or null when nothing is left.
export function mergeTracestate(incoming, entry) {
  const own = typeof entry === "string" ? members(entry)[0] : undefined;
  const ownKey = own ? memberKey(own) : null;
  const list = [...(own ? [own] : []), ...members(incoming).filter((m) => memberKey(m) !== ownKey)];
  while (list.length > TRACESTATE_MAX) {
    let i = list.length - 1;
    for (let j = i; j >= (own ? 1 : 0); j--) if (list[j].length > 128) { i = j; break; }
    list.splice(i, 1);
  }
  return list.length ? list.join(",") : null;
}

export function continueOrStart({ traceparent, tracestate, traceId, sampled = true, agentName } = {}) {
  const inc = parseTraceparent(Array.isArray(traceparent) ? undefined : traceparent);
  const spanId = newSpanId();
  const entry = tracestateMoorai({ agentName });
  if (inc) {
    const ts = mergeTracestate(tracestate, entry);
    return { traceId: inc.traceId, spanId, parentSpanId: inc.parentSpanId, sampled: inc.sampled, traceparent: formatTraceparent({ traceId: inc.traceId, spanId, sampled: inc.sampled }), ...(ts ? { tracestate: ts } : {}) };
  }
  const t = validTraceId(traceId) ? traceId : newTraceId();
  return { traceId: t, spanId, sampled: !!sampled, traceparent: formatTraceparent({ traceId: t, spanId, sampled }), ...(entry ? { tracestate: entry } : {}) };
}
