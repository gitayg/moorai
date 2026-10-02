// The HTTP half of the gateway: a reverse proxy for the MCP Streamable HTTP transport.
//
// Both eras of the transport pass through it unchanged in shape:
//   * 2026-07-28: every message is its own POST; per-request metadata headers (MCP-Protocol-Version,
//     Mcp-Method, Mcp-Name, Mcp-Param-*); no sessions, no GET stream, no resumption.
//   * 2025-03-26 .. 2025-11-25: Mcp-Session-Id on the initialize response and every later request,
//     DELETE to end a session, GET for a server-initiated SSE stream, Last-Event-ID resumption.
// Every end-to-end header goes upstream as the client sent it (Authorization included, never logged);
// every response header comes back (Mcp-Session-Id, WWW-Authenticate included). Only POST bodies are
// gated, and only responses are scanned — the JSON body, or each SSE event before it is forwarded.
import http from "node:http";
import https from "node:https";
import { createHash, timingSafeEqual } from "node:crypto";
import { CAPS } from "../mcp-proxy/tool-scan.mjs";
import { isLoopbackHost, TOKEN_HEADER } from "./config.mjs";
import { createGuard, blockedCall } from "./guard.mjs";
import { createSseFramer, sseEvent } from "./sse.mjs";
import { reportOnce } from "./report.mjs";

export const MAX_REQUEST_BYTES = 16 * 1048576;
const HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding", TOKEN_HEADER]);
const RESP_HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-connection", "transfer-encoding", "trailer", "upgrade", "content-length"]);
const AGENTS = { "http:": new http.Agent({ keepAlive: true }), "https:": new https.Agent({ keepAlive: true }) };

function digest(s) { return createHash("sha256").update(String(s)).digest(); }
function tokenOk(given, want) { return typeof given === "string" && timingSafeEqual(digest(given), digest(want)); }

function decodeSentinel(v) {
  const m = /^=\?base64\?(.*)\?=$/.exec(String(v));
  if (!m) return String(v);
  try { return Buffer.from(m[1], "base64").toString("utf8"); } catch { return null; }
}

function sendJson(res, status, obj, extra = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), ...extra });
  res.end(body);
}
const rpcError = (id, code, message) => ({ jsonrpc: "2.0", id: id == null ? null : id, error: { code, message } });

// The request's mirrored metadata headers against its body (2026-07-28 "Server Validation"). An
// intermediary that gates on the body must not let a different name ride in the header, because the
// next hop may route on the header. Only checked when the header is present (older clients send none).
function headerMismatch(req, m) {
  if (!m || typeof m !== "object" || typeof m.method !== "string") return null;
  const hm = req.headers["mcp-method"];
  if (hm != null && hm !== m.method) return "Mcp-Method header does not match the body";
  const hn = req.headers["mcp-name"];
  if (hn != null && ["tools/call", "resources/read", "prompts/get"].includes(m.method)) {
    const p = m.params || {};
    const want = m.method === "resources/read" ? p.uri : p.name;
    if (decodeSentinel(hn) !== want) return "Mcp-Name header does not match the body";
  }
  return null;
}

function originOk(origin, allow) {
  if (origin == null) return true;
  if (allow.includes(origin)) return true;
  try { const u = new URL(origin); return (u.protocol === "http:" || u.protocol === "https:") && isLoopbackHost(u.hostname); } catch { return false; }
}

function hostOk(hostHeader) {
  if (!hostHeader) return false;
  try { return isLoopbackHost(new URL(`http://${hostHeader}`).hostname); } catch { return false; }
}

function upstreamUrl(route, reqUrl) {
  const u = new URL(route.url);
  const q = new URL(reqUrl, "http://x").searchParams;
  for (const [k, v] of q) u.searchParams.append(k, v);
  return u;
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    req.on("data", (c) => {
      n += c.length;
      if (n > limit) { reject(Object.assign(new Error("too large"), { tooLarge: true })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export function createGatewayServer(cfg) {
  const routes = new Map(cfg.routes.map((r) => [r.path, { route: r, guard: createGuard(r) }]));

  async function handle(req, res) {
    // DNS rebinding: a loopback-only gateway answers only to loopback Host names and loopback / listed
    // browser Origins (spec: "Servers MUST validate the Origin header").
    if (!cfg.allowRemote && !hostOk(req.headers.host)) return sendJson(res, 403, rpcError(null, -32600, "Forbidden: Host is not loopback"));
    if (!originOk(req.headers.origin, cfg.allowOrigins)) return sendJson(res, 403, rpcError(null, -32600, "Forbidden: Origin not allowed"));
    if (cfg.token && !tokenOk(req.headers[TOKEN_HEADER], cfg.token)) return sendJson(res, 401, rpcError(null, -32600, "Unauthorized: missing or wrong X-MoorAI-Gateway-Token"));

    const path = new URL(req.url, "http://x").pathname.replace(/\/+$/, "") || "/";
    const entry = routes.get(path);
    if (!entry) return sendJson(res, 404, rpcError(null, -32601, "No MCP route at this path"));
    const { route, guard } = entry;

    let body;
    try { body = await readBody(req, MAX_REQUEST_BYTES); }
    catch (e) { if (e.tooLarge) return sendJson(res, 413, rpcError(null, -32600, "Request too large for the gateway to inspect")); return; }

    // ---- the CALL side: gate every tools/call in the body ----
    const idTool = new Map();
    if (req.method === "POST" && body.length) {
      let parsed = null;
      try { parsed = JSON.parse(body.toString("utf8")); } catch { /* not JSON: forwarded, the upstream decides */ }
      if (parsed && typeof parsed === "object") {
        const msgs = Array.isArray(parsed) ? parsed : [parsed];
        if (!Array.isArray(parsed)) {
          const mm = headerMismatch(req, parsed);
          if (mm) return sendJson(res, 400, rpcError(parsed.id, -32020, `Header mismatch: ${mm}`));
        }
        const blocked = new Map();
        for (const m of msgs) {
          if (!m || typeof m !== "object") continue;
          if (m.result && Array.isArray(m.result.roots)) { try { guard.rememberRoots(m.result.roots); } catch { /* roots are a hint */ } }
          if (m.method !== "tools/call" || !m.params || typeof m.params !== "object") continue;
          if (m.id != null) idTool.set(String(m.id), String(m.params.name || "mcp"));
          try {
            const d = await guard.gateCall(m);
            if (d.block) blocked.set(m, d.block);
          } catch { /* governance, not a sandbox: a failing check forwards */ }
        }
        if (blocked.size) {
          if (!Array.isArray(parsed)) return sendJson(res, 200, blockedCall(parsed.id, blocked.get(parsed)));
          // A batch (2025-03-26 only) is refused whole: forwarding part of it would answer some ids and
          // not others, and the gate has already said no to one of them.
          const out = msgs.filter((m) => m && m.id != null).map((m) => blockedCall(m.id, blocked.get(m) || "another call in the same batch was blocked"));
          return out.length ? sendJson(res, 200, out) : (res.writeHead(202), res.end());
        }
      }
    }

    // ---- forward ----
    const target = upstreamUrl(route, req.url);
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k)) headers[k] = v;
    headers["accept-encoding"] = "identity"; // a compressed body could not be scanned
    if (body.length || req.method === "POST") headers["content-length"] = String(body.length);
    const lib = target.protocol === "https:" ? https : http;
    const up = lib.request(target, { method: req.method, headers, agent: AGENTS[target.protocol] });
    res.on("close", () => { if (!res.writableFinished) up.destroy(); }); // client went away = cancellation
    up.on("error", () => {
      if (!res.headersSent) sendJson(res, 502, rpcError(null, -32603, "Upstream MCP server unreachable"));
      else res.destroy();
    });
    up.on("response", (ur) => onUpstream(ur, res, guard, idTool));
    up.end(body);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch(() => { if (!res.headersSent) sendJson(res, 500, rpcError(null, -32603, "Gateway error")); else res.destroy(); });
  });
  server.guards = [...routes.values()].map((e) => e.guard);
  return server;
}

function respHeaders(ur) {
  const h = {};
  for (const [k, v] of Object.entries(ur.headers)) if (!RESP_HOP.has(k)) h[k] = v;
  return h;
}

function onUpstream(ur, res, guard, idTool) {
  const ctype = String(ur.headers["content-type"] || "").toLowerCase();
  const enc = String(ur.headers["content-encoding"] || "identity").toLowerCase();
  const toolOf = (id) => (id != null && idTool.get(String(id))) || "mcp";
  const passthrough = () => { res.writeHead(ur.statusCode, ur.statusMessage, { ...respHeaders(ur), ...(ur.headers["content-length"] ? { "content-length": ur.headers["content-length"] } : {}) }); ur.pipe(res); };

  if (enc !== "identity" && (ctype.includes("json") || ctype.includes("event-stream"))) {
    reportOnce("MCP gateway: compressed upstream response forwarded unscanned", `gateway:unscanned:encoding:${enc}`, "Info");
    return passthrough();
  }
  if (ctype.startsWith("text/event-stream")) return onSse(ur, res, guard, toolOf);
  if (ctype.startsWith("application/json")) return onJson(ur, res, guard, toolOf);
  return passthrough();
}

// A JSON response: buffered (at most CAPS.maxLineBytes, as the proxy bounds a line), scanned, then
// forwarded byte-for-byte unless a message in it was replaced. Over the cap it streams through unscanned.
function onJson(ur, res, guard, toolOf) {
  const chunks = [];
  let n = 0;
  let streaming = false;
  ur.on("data", (c) => {
    if (streaming) return;
    n += c.length;
    chunks.push(c);
    if (n > CAPS.maxLineBytes) {
      streaming = true;
      reportOnce("MCP gateway: oversized response forwarded unscanned", "gateway:unscanned:size", "Info");
      res.writeHead(ur.statusCode, ur.statusMessage, respHeaders(ur));
      res.write(Buffer.concat(chunks));
      ur.pipe(res);
    }
  });
  ur.on("end", async () => {
    if (streaming) return;
    const raw = Buffer.concat(chunks);
    let out = raw;
    try {
      const parsed = JSON.parse(raw.toString("utf8"));
      if (Array.isArray(parsed)) {
        let changed = false;
        const next = [];
        for (const m of parsed) { const r = await guard.gateResult(m, toolOf(m && m.id)); if (r) changed = true; next.push(r || m); }
        if (changed) out = Buffer.from(JSON.stringify(next));
      } else {
        const r = await guard.gateResult(parsed, toolOf(parsed && parsed.id));
        if (r) out = Buffer.from(JSON.stringify(r));
      }
    } catch { /* unparseable or a failed scan: the original goes */ }
    if (res.destroyed) return;
    res.writeHead(ur.statusCode, ur.statusMessage, { ...respHeaders(ur), "content-length": out.length });
    res.end(out);
  });
  ur.on("error", () => res.destroy());
}

// An SSE response: each event is framed, scanned and forwarded in order before the next one goes.
// Notifications and comments pass as written; a result event that policy blocks is replaced by an
// event carrying the tool error (same id: line). Upstream is paused while the client is slow.
function onSse(ur, res, guard, toolOf) {
  res.writeHead(ur.statusCode, ur.statusMessage, { ...respHeaders(ur), "x-accel-buffering": "no" });
  if (res.flushHeaders) res.flushHeaders();
  let queue = Promise.resolve();
  let depth = 0;
  let paused = false;
  const write = (text) => new Promise((resolve) => {
    if (res.destroyed) return resolve();
    if (res.write(text)) resolve(); else res.once("drain", resolve);
  });
  const enqueue = (fn) => {
    depth++;
    if (depth > 64 && !paused) { paused = true; ur.pause(); }
    queue = queue.then(fn, fn).catch(() => {}).finally(() => {
      depth--;
      if (paused && depth < 16) { paused = false; ur.resume(); }
    });
  };
  const framer = createSseFramer({
    maxEventBytes: CAPS.maxLineBytes,
    onRaw: (text) => enqueue(() => write(text)),
    onEvent: (ev) => enqueue(async () => {
      let rep = null;
      if (ev.data != null && ev.data.indexOf("\"result\"") >= 0) {
        try { const m = JSON.parse(ev.data); rep = await guard.gateResult(m, toolOf(m && m.id)); } catch { rep = null; }
      }
      await write(rep ? sseEvent(rep, ev.id) : ev.raw);
    })
  });
  ur.on("data", (c) => { try { framer.push(c); } catch { enqueue(() => write(c.toString("utf8"))); } });
  ur.on("end", () => { try { framer.end(); } catch { /* nothing left to frame */ } enqueue(async () => { res.end(); }); });
  ur.on("error", () => res.destroy());
}
