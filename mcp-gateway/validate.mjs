// Staged JSON-RPC / MCP validation for the gateway (CONTRACT C5, SCHEMA_INVALID). Pure: a message (or a
// raw body) in, the FIRST failing stage out — { stage, path } — or null. A path is a JSON path built only
// from the schema's own field names and array indices, never from a key or value the peer sent, so a
// finding is content-free by construction.
//
// Stages, in order (C5 schemaStage):
//   json            the body is UTF-8 and parses as JSON ("JSON-RPC messages MUST be UTF-8 encoded",
//                   MCP 2025-06-18 transports)
//   jsonrpc         the JSON-RPC 2.0 envelope: an object, `jsonrpc` "MUST be exactly "2.0"", `method` "A
//                   String", a batch is a non-empty array (jsonrpc.org/specification)
//   structure       MCP's tightening of the envelope: request ids are "a string or integer ID" that "MUST
//                   NOT be null", notifications "MUST NOT include an ID", params is an object, a response
//                   sets "Either a result or an error … MUST NOT set both", error code an integer
//                   (MCP 2025-06-18 and 2026-07-28 basic)
//   method          the method is one this gateway knows (either era, plus the tasks extension) — or, when
//                   the operator configured an allow-list, one on it
//   protocolVersion an `initialize` protocolVersion, the MCP-Protocol-Version header and the 2026-07-28
//                   `_meta` "io.modelcontextprotocol/protocolVersion" are YYYY-MM-DD strings and the header
//                   agrees with `_meta`
//   schema          per-method params / result shape for initialize, tools/list and tools/call
//
// Deliberately lenient where the two spec eras the gateway carries differ, so valid traffic from either
// passes: no field is required that one era lacks (`resultType` is 2026-07-28-only, `content` may be
// absent on an MRTR "input_required" or a tasks-extension result), an unknown but well-formed protocol
// version is accepted (the gateway is not the server), and inputSchema may be an object or a boolean
// (2026-07-28 allows "any JSON Schema 2020-12").

export const STAGES = Object.freeze(["json", "jsonrpc", "structure", "method", "protocolVersion", "schema"]);
const PV_META = "io.modelcontextprotocol/protocolVersion";
const PV_RE = /^\d{4}-\d{2}-\d{2}$/;
const METHOD_RE = /^[A-Za-z0-9_.:/$-]{1,256}$/;

// Client → server requests across 2024-11-05 … 2026-07-28 and the io.modelcontextprotocol/tasks extension.
export const KNOWN_CLIENT_METHODS = new Set([
  "initialize", "ping", "server/discover", "subscriptions/listen",
  "tools/list", "tools/call",
  "resources/list", "resources/templates/list", "resources/read", "resources/subscribe", "resources/unsubscribe",
  "prompts/list", "prompts/get", "completion/complete", "logging/setLevel",
  "tasks/get", "tasks/update", "tasks/result", "tasks/list", "tasks/cancel"
]);
// Every notification lives under notifications/ in every revision.
const isNotificationMethod = (m) => m.startsWith("notifications/");

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isId = (v) => typeof v === "string" || (typeof v === "number" && Number.isInteger(v));
const fail = (stage, path) => ({ stage, path });

// Raw bytes → { value } or { error } at the json stage. Strict UTF-8 (a lenient decode would let the
// gateway and the upstream read different text) and no BOM (JSON.parse rejects it; some parsers do not).
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
export function parseBody(buf) {
  let text;
  try { text = UTF8.decode(buf); } catch { return { error: fail("json", "$") }; }
  try { return { value: JSON.parse(text) }; } catch { return { error: fail("json", "$") }; }
}

function metaPv(p, path) {
  if (!isObj(p) || p._meta === undefined) return null;
  if (!isObj(p._meta)) return fail("structure", `${path}.params._meta`);
  const v = p._meta[PV_META];
  if (v !== undefined && (typeof v !== "string" || !PV_RE.test(v))) return fail("protocolVersion", `${path}.params._meta["${PV_META}"]`);
  return null;
}

function clientParams(m, path) {
  const p = m.params;
  if (m.method === "initialize") {
    if (!isObj(p)) return fail("schema", `${path}.params`);
    if (typeof p.protocolVersion !== "string") return fail("schema", `${path}.params.protocolVersion`);
    if (!PV_RE.test(p.protocolVersion)) return fail("protocolVersion", `${path}.params.protocolVersion`);
    if (!isObj(p.capabilities)) return fail("schema", `${path}.params.capabilities`);
    if (!isObj(p.clientInfo)) return fail("schema", `${path}.params.clientInfo`);
    if (typeof p.clientInfo.name !== "string") return fail("schema", `${path}.params.clientInfo.name`);
    if (p.clientInfo.version !== undefined && typeof p.clientInfo.version !== "string") return fail("schema", `${path}.params.clientInfo.version`);
  } else if (m.method === "tools/call") {
    if (!isObj(p)) return fail("schema", `${path}.params`);
    if (typeof p.name !== "string" || !p.name) return fail("schema", `${path}.params.name`);
    if (p.arguments !== undefined && p.arguments !== null && !isObj(p.arguments)) return fail("schema", `${path}.params.arguments`);
  } else if (m.method === "tools/list") {
    if (isObj(p) && p.cursor !== undefined && typeof p.cursor !== "string") return fail("schema", `${path}.params.cursor`);
  }
  return null;
}

// The envelope checks shared by both directions. → { kind: "request"|"notification"|"response", fail? }
function envelope(m, path) {
  if (!isObj(m)) return { fail: fail("jsonrpc", path) };
  if (m.jsonrpc !== "2.0") return { fail: fail("jsonrpc", `${path}.jsonrpc`) };
  if (m.method !== undefined) {
    if (typeof m.method !== "string") return { fail: fail("jsonrpc", `${path}.method`) };
    if (!METHOD_RE.test(m.method) || m.method.startsWith("rpc.")) return { fail: fail("structure", `${path}.method`) };
    if (m.params !== undefined && !isObj(m.params)) return { fail: fail("structure", `${path}.params`) };
    if ("id" in m) {
      if (!isId(m.id)) return { fail: fail("structure", `${path}.id`) };
      if (isNotificationMethod(m.method)) return { fail: fail("structure", `${path}.id`) };
      return { kind: "request" };
    }
    return { kind: "notification" };
  }
  const hasR = "result" in m, hasE = "error" in m;
  if (hasR === hasE) return { fail: fail("structure", path) };
  if (hasR) {
    if (!isId(m.id)) return { fail: fail("structure", `${path}.id`) };
    if (!isObj(m.result)) return { fail: fail("structure", `${path}.result`) };
  } else {
    if (m.id !== undefined && m.id !== null && !isId(m.id)) return { fail: fail("structure", `${path}.id`) };
    if (!isObj(m.error)) return { fail: fail("structure", `${path}.error`) };
    if (!Number.isInteger(m.error.code)) return { fail: fail("structure", `${path}.error.code`) };
    if (typeof m.error.message !== "string") return { fail: fail("structure", `${path}.error.message`) };
  }
  return { kind: "response" };
}

// One client → server message. opts.allowedMethods: a Set; when given, a request method outside it fails
// the method stage. Without it, an unknown request method is NOT a failure; it comes back as
// { unknownMethod: true } so the caller can report it (new revisions and extensions add methods).
export function validateClientMessage(m, { path = "$", allowedMethods = null, headerPv = undefined } = {}) {
  const e = envelope(m, path);
  if (e.fail) return e.fail;
  if (e.kind === "request" || e.kind === "notification") {
    if (e.kind === "request") {
      if (allowedMethods && !allowedMethods.has(m.method)) return fail("method", `${path}.method`);
    } else if (!isNotificationMethod(m.method)) {
      if (KNOWN_CLIENT_METHODS.has(m.method)) return fail("structure", `${path}.id`); // a request sent without its id
      if (allowedMethods && !allowedMethods.has(m.method)) return fail("method", `${path}.method`);
    }
    const pv = metaPv(m.params, path);
    if (pv) return pv;
    if (headerPv !== undefined && isObj(m.params) && isObj(m.params._meta) && m.params._meta[PV_META] !== undefined && m.params._meta[PV_META] !== headerPv) {
      return { ...fail("protocolVersion", `${path}.params._meta["${PV_META}"]`), headerMismatch: true };
    }
    const sp = clientParams(m, path);
    if (sp) return sp;
    if (e.kind === "request" && !KNOWN_CLIENT_METHODS.has(m.method)) return { unknownMethod: true };
  }
  return null;
}

// The MCP-Protocol-Version request header: absent is fine (older clients, "the server SHOULD assume
// protocol version 2025-03-26"); present must be a version string.
export function validateHeaderPv(v) {
  if (v === undefined) return null;
  return typeof v === "string" && PV_RE.test(v) ? null : fail("protocolVersion", "$");
}

// A whole client body (already parsed). A batch must be a non-empty array; the first failing element
// decides. → null | { stage, path, index?, headerMismatch? } | { unknownMethods: [...] }
export function validateClientBody(parsed, opts = {}) {
  if (Array.isArray(parsed)) {
    if (!parsed.length) return fail("jsonrpc", "$");
    const unknown = [];
    for (let i = 0; i < parsed.length; i++) {
      const r = validateClientMessage(parsed[i], { ...opts, path: `$[${i}]` });
      if (r && r.stage) return { ...r, index: i };
      if (r && r.unknownMethod) unknown.push(parsed[i].method);
    }
    return unknown.length ? { unknownMethods: unknown } : null;
  }
  const r = validateClientMessage(parsed, opts);
  if (r && r.unknownMethod) return { unknownMethods: [parsed.method] };
  return r;
}

function serverResult(method, r, path) {
  const rp = `${path}.result`;
  if (r.resultType !== undefined && typeof r.resultType !== "string") return fail("schema", `${rp}.resultType`);
  if (method === "initialize") {
    if (typeof r.protocolVersion !== "string") return fail("schema", `${rp}.protocolVersion`);
    if (!PV_RE.test(r.protocolVersion)) return fail("protocolVersion", `${rp}.protocolVersion`);
    if (!isObj(r.capabilities)) return fail("schema", `${rp}.capabilities`);
    if (!isObj(r.serverInfo)) return fail("schema", `${rp}.serverInfo`);
    if (typeof r.serverInfo.name !== "string") return fail("schema", `${rp}.serverInfo.name`);
  } else if (method === "tools/list") {
    if (r.resultType === "input_required") return null;
    if (!Array.isArray(r.tools)) return fail("schema", `${rp}.tools`);
    for (let i = 0; i < r.tools.length; i++) {
      const t = r.tools[i];
      if (!isObj(t)) return fail("schema", `${rp}.tools[${i}]`);
      if (typeof t.name !== "string") return fail("schema", `${rp}.tools[${i}].name`);
      if (t.inputSchema !== undefined && !isObj(t.inputSchema) && typeof t.inputSchema !== "boolean") return fail("schema", `${rp}.tools[${i}].inputSchema`);
    }
    if (r.nextCursor !== undefined && r.nextCursor !== null && typeof r.nextCursor !== "string") return fail("schema", `${rp}.nextCursor`);
  } else if (method === "tools/call") {
    if (r.content !== undefined) {
      if (!Array.isArray(r.content)) return fail("schema", `${rp}.content`);
      for (let i = 0; i < r.content.length; i++) {
        const c = r.content[i];
        if (!isObj(c)) return fail("schema", `${rp}.content[${i}]`);
        if (typeof c.type !== "string") return fail("schema", `${rp}.content[${i}].type`);
      }
    }
    if (r.isError !== undefined && typeof r.isError !== "boolean") return fail("schema", `${rp}.isError`);
  }
  return null;
}

// One server → client message. methodOf(id) → the method of the client request it answers ("" unknown).
export function validateServerMessage(m, { path = "$", methodOf = () => "" } = {}) {
  const e = envelope(m, path);
  if (e.fail) return e.fail;
  if (e.kind === "response" && "result" in m) return serverResult(methodOf(m.id), m.result, path);
  return null;
}
