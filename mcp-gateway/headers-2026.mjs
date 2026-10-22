// MCP 2026-07-28 request metadata headers the gateway validates against the body it gates (Streamable HTTP,
// "Request Metadata"). Quoted from the revision:
//   * "Every POST request to the MCP endpoint MUST include an MCP-Protocol-Version header."; standard
//     headers Mcp-Method ("All requests") and Mcp-Name (tools/call, resources/read, prompts/get) "are
//     REQUIRED for compliance"; Server Validation failures include "A required standard header
//     (MCP-Protocol-Version, Mcp-Method, Mcp-Name) is missing", answered "400 Bad Request" with "-32020"
//     HeaderMismatch. (A mismatched value is checked in server.mjs headerMismatch.)
//   * Custom Headers from Tool Parameters: a tool parameter annotated `x-mcp-header: "<Name>"` in the
//     tool's inputSchema is mirrored as `Mcp-Param-<Name>`. "Any server that processes the message body MUST
//     validate that encoded header values, after decoding if Base64-encoded, match the corresponding values
//     in the request body"; "Client omits header but value is in body — Server MUST reject the request";
//     "Intermediate servers that do not recognize an Mcp-Param-{Name} header MUST forward it and otherwise
//     ignore it"; integers "SHOULD" compare numerically ("42.0 and 42 are considered equal").
//   * Annotation constraints: not empty; "1*tchar" (RFC 9110 field-name token); "case-insensitively
//     unique"; "only be applied to parameters with primitive types (integer, string, boolean). Parameters
//     with type number are not permitted"; "statically reachable from the schema root ... solely of
//     properties keys". "An x-mcp-header annotation anywhere else makes the annotation — and thus the tool
//     definition — invalid."
// The gateway learns the annotations from the tools/list results it judges (per route); a tool it has not
// seen listed has no recognized Mcp-Param header, so its headers are forwarded and ignored. Only requests of
// the 2026-07-28 era (or later: the MCP-Protocol-Version header or the body's _meta protocol version at or
// after 2026-07-28) are checked; earlier eras have no such headers.
export const MODERN_PV = "2026-07-28";
const PV_META = "io.modelcontextprotocol/protocolVersion";
const NAME_METHODS = new Set(["tools/call", "resources/read", "prompts/get"]);
const TCHAR = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const PV_RE = /^\d{4}-\d{2}-\d{2}$/;
const MAX_TOOLS = 4096;
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// The Base64 sentinel `=?base64?…?=` decoded (UTF-8), the value as sent otherwise, null when malformed.
export function decodeHeaderValue(v) {
  const s = String(v);
  const m = /^=\?base64\?(.*)\?=$/.exec(s);
  if (!m) return s;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(m[1]) || m[1].length % 4) return null;
  try { return Buffer.from(m[1], "base64").toString("utf8"); } catch { return null; }
}

// Is this request of the 2026-07-28 era or later?
export function isModern(req, m) {
  const h = req.headers["mcp-protocol-version"];
  const b = isObj(m) && isObj(m.params) && isObj(m.params._meta) ? m.params._meta[PV_META] : undefined;
  return [h, b].some((v) => typeof v === "string" && PV_RE.test(v) && v >= MODERN_PV);
}

// A 2026-era request missing a required standard header → the reason, else null. `server/discover` is
// exempt: it is the version probe ("Clients MAY call it before any other request for up-front version
// selection, or use it as a backward-compatibility probe"), carries no tool, and the upstream answers it
// with the versions it supports; refusing a probe that omits a header would only break version selection.
export function missingStandardHeader(req, m) {
  if (!isObj(m) || typeof m.method !== "string" || m.id === undefined || m.method === "server/discover" || !isModern(req, m)) return null;
  if (req.headers["mcp-protocol-version"] === undefined) return "required MCP-Protocol-Version header is missing";
  if (req.headers["mcp-method"] === undefined) return "required Mcp-Method header is missing";
  if (NAME_METHODS.has(m.method) && req.headers["mcp-name"] === undefined) return "required Mcp-Name header is missing";
  return null;
}

// One inputSchema → [{ name (lower case), header (as written), path, type }] or null when an annotation
// makes the tool definition invalid.
export function paramAnnotations(schema) {
  if (!isObj(schema)) return [];
  const out = [];
  let reachable = 0, total = 0, bad = false;
  const countAll = (v, d) => {
    if (d > 64 || v === null || typeof v !== "object") return;
    if (Array.isArray(v)) { for (const x of v) countAll(x, d + 1); return; }
    for (const [k, x] of Object.entries(v)) { if (k === "x-mcp-header") total++; countAll(x, d + 1); }
  };
  countAll(schema, 0);
  const walk = (node, path, d) => {
    if (d > 32 || !isObj(node) || !isObj(node.properties)) return;
    for (const [k, sub] of Object.entries(node.properties)) {
      if (!isObj(sub)) continue;
      if (Object.hasOwn(sub, "x-mcp-header")) {
        reachable++;
        const h = sub["x-mcp-header"];
        if (typeof h !== "string" || !TCHAR.test(h) || !["string", "integer", "boolean"].includes(sub.type)) bad = true;
        else out.push({ name: h.toLowerCase(), header: h, path: [...path, k], type: sub.type });
      }
      walk(sub, [...path, k], d + 1);
    }
  };
  walk(schema, [], 0);
  if (bad || reachable !== total || new Set(out.map((a) => a.name)).size !== out.length) return null;
  return out;
}

function valueAt(args, path) {
  let v = args;
  for (const k of path) { if (!isObj(v) || !Object.hasOwn(v, k)) return undefined; v = v[k]; }
  return v;
}
function sameValue(decoded, v) {
  if (typeof v === "boolean") return decoded === (v ? "true" : "false");
  if (typeof v === "number") return Number.isInteger(v) && /^-?\d+(?:\.0+)?$/.test(decoded) && Number(decoded) === v;
  if (typeof v === "string") return decoded === v;
  return false;
}

// The per-route registry: learn(tools) from judged tools/list results; check(req, m) → reason | null.
export function createParamHeaders({ onInvalid = () => {} } = {}) {
  const byTool = new Map();
  return {
    learn(tools) {
      for (const t of Array.isArray(tools) ? tools : []) {
        if (!isObj(t) || typeof t.name !== "string") continue;
        const a = paramAnnotations(t.inputSchema);
        if (a === null) { byTool.delete(t.name); onInvalid(t.name); continue; }
        if (!byTool.has(t.name) && byTool.size >= MAX_TOOLS) continue;
        if (a.length) byTool.set(t.name, a); else byTool.delete(t.name);
      }
    },
    check(req, m) {
      if (!isObj(m) || m.method !== "tools/call" || !isObj(m.params) || !isModern(req, m)) return null;
      const ann = byTool.get(m.params.name);
      if (!ann) return null;
      const args = isObj(m.params.arguments) ? m.params.arguments : {};
      for (const a of ann) {
        const raw = req.headers[`mcp-param-${a.name}`];
        const v = valueAt(args, a.path);
        const label = `Mcp-Param-${a.header}`;
        if (v === undefined || v === null) { if (raw !== undefined) return `${label} header has no value in the body`; continue; }
        if (raw === undefined) return `required ${label} header is missing`;
        const decoded = typeof raw === "string" ? decodeHeaderValue(raw) : null;
        if (decoded === null) return `${label} header is not a valid value`;
        if (!sameValue(decoded, v)) return `${label} header does not match the body`;
      }
      return null;
    },
    size: () => byTool.size
  };
}
