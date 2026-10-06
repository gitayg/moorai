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
import { isLoopbackHost, TOKEN_HEADER, DEFAULT_MAX_RESPONSE_BYTES } from "./config.mjs";
import { createGuard, blockedCall } from "./guard.mjs";
import { createSseFramer, sseEvent } from "./sse.mjs";
import { reportOnce, alertSchema, alertTooLarge, alertCooldown } from "./report.mjs";
import { parseBody, validateClientBody, validateHeaderPv, validateServerMessage } from "./validate.mjs";
import { createCooldown } from "./cooldown.mjs";
import { countCall } from "./usage.mjs";

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
const isId = (v) => typeof v === "string" || (typeof v === "number" && Number.isInteger(v));
const TOOL_NAME_RE = /^[A-Za-z0-9_.:\/-]{1,128}$/;
// A refused RESULT: the proxy's shape (an MCP tool result with isError), as guard.gateResult builds it.
const blockedResult = (id, reason) => ({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `MoorAI blocked this MCP tool result: ${reason}` }], isError: true } });

// ---- C5: refusing an invalid client message ----
// JSON-RPC codes per stage (jsonrpc.org/specification: -32700 "Parse error", -32600 "Invalid Request",
// -32601 "Method not found", -32602 "Invalid params"). A tools/call with a usable id gets the gateway's
// refusal shape (an isError tool result, HTTP 200); any other request with a usable id a JSON-RPC error
// (HTTP 200, as a request's answer is "a single JSON object"); a body with no usable id — unparseable, a
// notification, a response — HTTP 400 with an id-less error, as the transport says for input the server
// "cannot accept" ("MUST return an HTTP error status code (e.g., 400 Bad Request)"). A bad
// MCP-Protocol-Version header is 400 ("MUST respond with 400 Bad Request"); a header that disagrees with
// the body's _meta is 400 / -32020 HeaderMismatch, as the existing Mcp-Name check answers.
const STAGE_CODE = { json: -32700, jsonrpc: -32600, structure: -32600, method: -32601, protocolVersion: -32602, schema: -32602 };
function refuseInvalid(res, parsed, bad) {
  const why = `this MCP message failed validation (${bad.stage} at ${bad.path})`;
  if (bad.headerMismatch) return sendJson(res, 400, rpcError(parsed && isId(parsed.id) ? parsed.id : null, -32020, "Header mismatch: MCP-Protocol-Version header does not match the body"));
  if (bad.header) return sendJson(res, 400, rpcError(null, -32602, `Invalid MCP-Protocol-Version header (${why})`));
  const code = STAGE_CODE[bad.stage] || -32600;
  const answer = (m, own) => {
    if (!m || typeof m !== "object" || !isId(m.id) || typeof m.method !== "string") return null;
    const reason = own ? why : "another message in the same batch failed validation";
    return m.method === "tools/call" ? blockedCall(m.id, reason) : rpcError(m.id, own ? code : -32600, `MoorAI refused this MCP message: ${reason}`);
  };
  if (Array.isArray(parsed)) {
    const out = parsed.map((m, i) => answer(m, i === bad.index)).filter(Boolean);
    return out.length ? sendJson(res, 200, out) : sendJson(res, 400, rpcError(null, code, `MoorAI refused this MCP message: ${why}`));
  }
  const one = answer(parsed, true);
  return one ? sendJson(res, 200, one) : sendJson(res, 400, rpcError(null, code, `MoorAI refused this MCP message: ${why}`));
}
function toolOfBad(parsed, bad) {
  const m = Array.isArray(parsed) ? parsed[bad.index] : parsed;
  const n = m && m.method === "tools/call" && m.params && m.params.name;
  return typeof n === "string" && TOOL_NAME_RE.test(n) ? n : "mcp";
}
function reportUnknownMethod(server) {
  alertSchema(server, { stage: "method", path: "$.method" }, { direction: "client", refused: false });
}
function refuseCooldown(res, parsed, left) {
  const reason = `this client is in a cool-down after repeated refusals (${left} s left)`;
  const one = (m) => (m.method === "tools/call" ? blockedCall(m.id, reason) : rpcError(m.id, -32603, `MoorAI refused this MCP request: ${reason}`));
  const reqs = (Array.isArray(parsed) ? parsed : [parsed]).filter((m) => m && typeof m === "object" && isId(m.id) && typeof m.method === "string");
  return sendJson(res, 200, Array.isArray(parsed) ? reqs.map(one) : one(reqs[0]));
}
// The client a cool-down is kept for: the route plus a one-way hash of its Authorization header when it
// sends one, else the TCP peer. Never leaves the process.
function clientKey(route, req) {
  const auth = req.headers.authorization;
  return `${route.path}|${auth ? "a:" + createHash("sha256").update(String(auth)).digest("hex").slice(0, 32) : "p:" + (req.socket && req.socket.remoteAddress)}`;
}

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
  if (cfg.schemaValidation === undefined) cfg = { ...cfg, schemaValidation: "enforce" };
  if (cfg.maxResponseBytes === undefined) cfg = { ...cfg, maxResponseBytes: DEFAULT_MAX_RESPONSE_BYTES };
  const cooldown = createCooldown(cfg.cooldown || {});
  // A refusal the gateway made for this client (policy block, invalid message, profile block). Starting a
  // cool-down is reported once; requests refused DURING it are not counted again.
  function noteRefusal(key, route) {
    if (cooldown.refused(key)) alertCooldown(route.server, cooldown.seconds);
  }

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

    // ---- the CALL side: validate the body (C5), then gate every tools/call in it ----
    const ctx = { idTool: new Map(), idMethod: new Map(), requestIds: [], route, guard, cfg };
    const ckey = clientKey(route, req);
    if (req.method === "POST" && body.length) {
      const enforce = cfg.schemaValidation === "enforce";
      const validating = cfg.schemaValidation !== "off";
      const hpv = req.headers["mcp-protocol-version"];
      let parsed = null;
      const pb = parseBody(body);
      let bad = null;
      if (validating) {
        bad = pb.error || validateHeaderPv(hpv);
        if (bad && !pb.error) bad = { ...bad, header: "MCP-Protocol-Version" };
        if (!bad) {
          const v = validateClientBody(pb.value, { allowedMethods: cfg.allowedMethods ? new Set(cfg.allowedMethods) : null, headerPv: hpv });
          if (v && v.stage) bad = v;
          else if (v && v.unknownMethods) reportUnknownMethod(route.server);
        }
      }
      if (!pb.error) parsed = pb.value;
      if (bad) {
        alertSchema(route.server, bad, { direction: "client", refused: enforce, tool: toolOfBad(parsed, bad) });
        if (enforce) { noteRefusal(ckey, route); return refuseInvalid(res, parsed, bad); }
      }
      if (parsed && typeof parsed === "object") {
        const msgs = Array.isArray(parsed) ? parsed : [parsed];
        ctx.batch = Array.isArray(parsed);
        for (const m of msgs) {
          if (m && typeof m === "object" && typeof m.method === "string" && isId(m.id)) {
            ctx.requestIds.push(m.id);
            ctx.idMethod.set(String(m.id), m.method);
          }
        }
        // C5 cool-down: a client that tripped it is refused for its duration, every request in the body.
        const left = cooldown.remaining(ckey);
        if (left && ctx.requestIds.length) return refuseCooldown(res, parsed, left);
        if (!Array.isArray(parsed)) {
          const mm = headerMismatch(req, parsed);
          if (mm) return sendJson(res, 400, rpcError(parsed.id, -32020, `Header mismatch: ${mm}`));
        }
        const blocked = new Map();
        for (const m of msgs) {
          if (!m || typeof m !== "object") continue;
          if (m.result && Array.isArray(m.result.roots)) { try { guard.rememberRoots(m.result.roots); } catch { /* roots are a hint */ } }
          if (m.method !== "tools/call" || !m.params || typeof m.params !== "object") continue;
          if (m.id != null) ctx.idTool.set(String(m.id), String(m.params.name || "mcp"));
          // C4 usage: per server and per tool name, blocked or not (mcp-gateway/usage.mjs). The tally
          // write is synchronous, so it runs after this request's own work is under way.
          { const tool = m.params.name; setImmediate(() => countCall(route.server, tool)); }
          try {
            const d = await guard.gateCall(m);
            if (d.block) blocked.set(m, d.block);
          } catch { /* governance, not a sandbox: a failing check forwards */ }
        }
        if (blocked.size) {
          noteRefusal(ckey, route);
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
      if (res.writableEnded) return; // already answered (e.g. an oversized response refused, then dropped)
      if (!res.headersSent) sendJson(res, 502, rpcError(null, -32603, "Upstream MCP server unreachable"));
      else res.destroy();
    });
    up.on("response", (ur) => onUpstream(ur, res, ctx));
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

function onUpstream(ur, res, ctx) {
  const ctype = String(ur.headers["content-type"] || "").toLowerCase();
  const enc = String(ur.headers["content-encoding"] || "identity").toLowerCase();
  const passthrough = () => { res.writeHead(ur.statusCode, ur.statusMessage, { ...respHeaders(ur), ...(ur.headers["content-length"] ? { "content-length": ur.headers["content-length"] } : {}) }); ur.pipe(res); };

  if (enc !== "identity" && (ctype.includes("json") || ctype.includes("event-stream"))) {
    reportOnce("MCP gateway: compressed upstream response forwarded unscanned", `gateway:unscanned:encoding:${enc}`, "Info");
    return passthrough();
  }
  const x = {
    ...ctx,
    toolOf: (id) => (id != null && ctx.idTool.get(String(id))) || "mcp",
    methodOf: (id) => (id != null && ctx.idMethod.get(String(id))) || "",
    cap: ctx.cfg.maxResponseBytes,
    validating: ctx.cfg.schemaValidation !== "off",
    enforce: ctx.cfg.schemaValidation === "enforce"
  };
  if (ctype.startsWith("text/event-stream")) return onSse(ur, res, x);
  if (ctype.startsWith("application/json")) return onJson(ur, res, x);
  return passthrough();
}

// The answer that stands in for a response over the cap (C5 RESPONSE_TOO_LARGE): per request id in the
// POST, a tool error for a tools/call and a JSON-RPC error for anything else. null when the POST carried
// no request (nothing to answer).
function tooLargeReply(x) {
  const why = `it exceeded the gateway's ${x.cap}-byte response limit`;
  const one = (id) => (x.methodOf(id) === "tools/call" ? blockedResult(id, `the server's response was refused: ${why}`) : rpcError(id, -32603, `MoorAI blocked this MCP response: ${why}`));
  if (!x.requestIds.length) return null;
  return x.batch ? x.requestIds.map(one) : one(x.requestIds[0]);
}
const tooLargeTool = (x) => (!x.batch && x.requestIds.length === 1 ? x.toolOf(x.requestIds[0]) : "mcp");

// One server → client message (C5 schema stage): report an invalid one; in enforce mode, an invalid
// response to a tools/call is replaced by a tool error (a malformed result could otherwise carry text past
// the result scan, which reads the shape the spec defines). Other responses — a tools/list above all,
// which is never altered — are reported only. → a replacement message or null.
function checkServerMessage(m, x, path = "$") {
  if (!x.validating) return null;
  const bad = validateServerMessage(m, { path, methodOf: x.methodOf });
  if (!bad) return null;
  const replace = x.enforce && m && isId(m.id) && x.methodOf(m.id) === "tools/call";
  alertSchema(x.route.server, bad, { direction: "server", refused: replace, tool: m && isId(m.id) ? x.toolOf(m.id) : "mcp" });
  return replace ? blockedResult(m.id, `the server's response failed MCP validation (${bad.stage} at ${bad.path})`) : null;
}

// A JSON response: buffered, scanned, then forwarded byte-for-byte unless a message in it was replaced.
// With a cap (default 4 MiB): a body over the cap is refused (tooLargeReply); one between the scan's
// CAPS.maxLineBytes (1 MB) and the cap is forwarded unscanned, as before. Without a cap (0) a body past
// 1 MB streams through unscanned, the gateway's original behaviour.
function onJson(ur, res, x) {
  const { guard } = x;
  const chunks = [];
  let n = 0;
  let streaming = false, refused = false;
  const refuseLarge = () => {
    refused = true;
    alertTooLarge(x.route.server, tooLargeTool(x), x.cap);
    if (res.headersSent) { ur.destroy(); return res.destroy(); }
    const r = tooLargeReply(x);
    if (r) sendJson(res, 200, r); else sendJson(res, 502, rpcError(null, -32603, `MoorAI blocked this MCP response: it exceeded the gateway's ${x.cap}-byte response limit`));
    ur.destroy();
  };
  if (x.cap && Number(ur.headers["content-length"]) > x.cap) return refuseLarge();
  ur.on("data", (c) => {
    if (streaming || refused) return;
    n += c.length;
    if (x.cap && n > x.cap) return refuseLarge();
    chunks.push(c);
    if (!x.cap && n > CAPS.maxLineBytes) {
      streaming = true;
      reportOnce("MCP gateway: oversized response forwarded unscanned", "gateway:unscanned:size", "Info");
      res.writeHead(ur.statusCode, ur.statusMessage, respHeaders(ur));
      res.write(Buffer.concat(chunks));
      ur.pipe(res);
    }
  });
  ur.on("end", async () => {
    if (streaming || refused) return;
    const raw = Buffer.concat(chunks);
    let out = raw;
    if (raw.length > CAPS.maxLineBytes) reportOnce("MCP gateway: oversized response forwarded unscanned", "gateway:unscanned:size", "Info");
    else {
      try {
        const pb = parseBody(raw);
        if (pb.error) { if (x.validating && raw.length) alertSchema(x.route.server, pb.error, { direction: "server", refused: false }); }
        else if (Array.isArray(pb.value)) {
          let changed = false;
          const next = [];
          for (let i = 0; i < pb.value.length; i++) {
            const m = pb.value[i];
            const r = checkServerMessage(m, x, `$[${i}]`) || await guard.gateResult(m, x.toolOf(m && m.id));
            if (r) changed = true;
            next.push(r || m);
          }
          if (changed) out = Buffer.from(JSON.stringify(next));
        } else {
          const m = pb.value;
          const r = checkServerMessage(m, x) || await guard.gateResult(m, x.toolOf(m && m.id));
          if (r) out = Buffer.from(JSON.stringify(r));
        }
      } catch { /* a failed scan: the original goes */ }
    }
    if (res.destroyed) return;
    res.writeHead(ur.statusCode, ur.statusMessage, { ...respHeaders(ur), "content-length": out.length });
    res.end(out);
  });
  ur.on("error", () => { if (!res.writableEnded) res.destroy(); });
}

// An SSE response: each event is framed, validated, scanned and forwarded in order before the next one
// goes. Notifications and comments pass as written; a result event that policy blocks (or, in enforce
// mode, an invalid tools/call result) is replaced by an event carrying the tool error (same id: line).
// An event over the cap is dropped (C5): when the POST carried exactly one request its answer is a tool
// error / JSON-RPC error event and the stream ends; on a stream with no single request (a GET stream, a
// batch) the event is dropped and the stream goes on. Upstream is paused while the client is slow.
function onSse(ur, res, x) {
  const { guard } = x;
  res.writeHead(ur.statusCode, ur.statusMessage, { ...respHeaders(ur), "x-accel-buffering": "no" });
  if (res.flushHeaders) res.flushHeaders();
  let queue = Promise.resolve();
  let depth = 0;
  let paused = false;
  const write = (text) => new Promise((resolve) => {
    if (res.destroyed || res.writableEnded) return resolve();
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
    maxEventBytes: x.cap || CAPS.maxLineBytes,
    onRaw: (text) => enqueue(() => write(text)),
    onOverflow: x.cap ? ({ id }) => enqueue(async () => {
      alertTooLarge(x.route.server, tooLargeTool(x), x.cap);
      if (x.batch || x.requestIds.length !== 1) return;
      await write(sseEvent(tooLargeReply(x), id));
      if (!res.writableEnded) res.end();
      ur.destroy();
    }) : null,
    onEvent: (ev) => enqueue(async () => {
      if (ev.bytes > CAPS.maxLineBytes) {
        reportOnce("MCP gateway: oversized SSE event forwarded unscanned", "gateway:unscanned:sse-size", "Info");
        return write(ev.raw);
      }
      let rep = null;
      if (ev.data != null && (ev.type == null || ev.type === "" || ev.type === "message")) {
        let m, ok = true;
        try { m = JSON.parse(ev.data); } catch { ok = false; }
        if (!ok) { if (x.validating) alertSchema(x.route.server, { stage: "json", path: "$" }, { direction: "server", refused: false }); }
        else if (Array.isArray(m)) { for (let i = 0; i < m.length; i++) { const v = x.validating && validateServerMessage(m[i], { path: `$[${i}]`, methodOf: x.methodOf }); if (v) alertSchema(x.route.server, v, { direction: "server", refused: false }); } }
        else {
          rep = checkServerMessage(m, x);
          if (!rep && ev.data.indexOf("\"result\"") >= 0) { try { rep = await guard.gateResult(m, x.toolOf(m && m.id)); } catch { rep = null; } }
        }
      }
      await write(rep ? sseEvent(rep, ev.id) : ev.raw);
    })
  });
  ur.on("data", (c) => { try { framer.push(c); } catch { enqueue(() => write(c.toString("utf8"))); } });
  ur.on("end", () => { try { framer.end(); } catch { /* nothing left to frame */ } enqueue(async () => { if (!res.writableEnded) res.end(); }); });
  ur.on("error", () => { if (!res.writableEnded) res.destroy(); });
}
