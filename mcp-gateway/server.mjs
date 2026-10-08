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
// With placeholder credentials configured (cfg.credentials, ../model-proxy/credentials.mjs), a header
// holding `moorai-ph:<name>` has its value replaced by the bound secret on the bound route only, any other
// placeholder use is refused before the body is read, and every upstream response is masked for the bound
// secrets (../model-proxy/credential-mask.mjs) before anything reads it. Without them, nothing changes.
import http from "node:http";
import https from "node:https";
import { pipeline } from "node:stream";
import { createGunzip, createInflate, createBrotliDecompress } from "node:zlib";
import { createHash, timingSafeEqual } from "node:crypto";
import { CAPS } from "../mcp-proxy/tool-scan.mjs";
import { isLoopbackHost, TOKEN_HEADER, DEFAULT_MAX_RESPONSE_BYTES, HOP } from "./config.mjs";
import { createGate } from "../model-proxy/credentials.mjs";
import { maskResponse } from "../model-proxy/credential-mask.mjs";
import { createGuard, blockedCall } from "./guard.mjs";
import { createSseFramer, sseEvent } from "./sse.mjs";
import { reportOnce, alertSchema, alertTooLarge, alertCooldown } from "./report.mjs";
import { parseBody, parseLenient, validateClientBody, validateHeaderPv, validateServerMessage, MAX_DEPTH } from "./validate.mjs";
import { createCooldown } from "./cooldown.mjs";
import { countCall } from "./usage.mjs";
import { createPendingLists, idKey, PENDING_LIST_MAX, PENDING_LIST_TTL_MS } from "./pending-lists.mjs";

export const MAX_REQUEST_BYTES = 16 * 1048576;
// Messages in one client batch. Each tools/call in a batch is gated in turn without yielding to other
// clients (~3.7 ms each, measured, most of it the ledger write), so an uncapped 16 MB batch held the
// gateway for minutes. Refused like an oversized body, in every --schema mode.
export const MAX_BATCH_MESSAGES = 64;
const RESP_HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-connection", "transfer-encoding", "trailer", "upgrade", "content-length"]);
const AGENTS = { "http:": new http.Agent({ keepAlive: true }), "https:": new https.Agent({ keepAlive: true }) };
// MOORAI_TEST_PENDING_LIST_TTL_MS / MOORAI_TEST_PENDING_LIST_MAX: test hooks that shorten the outstanding
// tools/list TTL and lower its bound (an entry dropped unanswered clears the verdicts: more clearing, never less).
const lowered = (v, dflt) => { const n = Math.floor(Number(v)); return v != null && n > 0 ? Math.min(n, dflt) : dflt; };
const PENDING_OPTS = { ttlMs: lowered(process.env.MOORAI_TEST_PENDING_LIST_TTL_MS, PENDING_LIST_TTL_MS), max: lowered(process.env.MOORAI_TEST_PENDING_LIST_MAX, PENDING_LIST_MAX) };

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
// What the MCP SDK client makes of one parsed message (types.js JSONRPCMessageSchema: strict request,
// notification, result and error schemas; anything else it refuses, unparsed): "request",
// "notification", "result", "error", or null.
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
function sdkKind(m) {
  if (!isObj(m) || m.jsonrpc !== "2.0") return null;
  const has = (k) => Object.hasOwn(m, k);
  const only = (...keys) => Object.keys(m).every((k) => keys.includes(k));
  if (has("method")) {
    if (typeof m.method !== "string" || (has("params") && !isObj(m.params))) return null;
    if (has("id")) return isId(m.id) && only("jsonrpc", "id", "method", "params") ? "request" : null;
    return only("jsonrpc", "method", "params") ? "notification" : null;
  }
  if (has("result")) return isId(m.id) && isObj(m.result) && only("jsonrpc", "id", "result") ? "result" : null;
  if (has("error")) return (!has("id") || isId(m.id)) && isObj(m.error) && Number.isInteger(m.error.code) && typeof m.error.message === "string" && only("jsonrpc", "id", "error") ? "error" : null;
  return null;
}
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
// sends one, else the TCP peer (`key`). An Authorization value on a refused call is never checked by
// anyone, so it is also counted at its peer once per distinct value (`peer`, cooldown.refusedOnce): a
// client that rotates it is cooled down at its address. Never leaves the process.
function clientKey(route, req) {
  const auth = req.headers.authorization;
  const peer = `${route.path}|r:${req.socket && req.socket.remoteAddress}`;
  if (!auth) return { key: `${route.path}|p:${req.socket && req.socket.remoteAddress}`, peer, cred: null };
  const cred = createHash("sha256").update(String(auth)).digest("hex").slice(0, 32);
  return { key: `${route.path}|a:${cred}`, peer, cred };
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
  // A tools/list whose outstanding entry expires or is evicted unanswered may still be answered, unseen:
  // the route's drift verdicts are cleared then (fail closed), as for a listing forwarded unjudged.
  const routes = new Map(cfg.routes.map((r) => {
    const guard = createGuard(r);
    return [r.path, { route: r, guard, pending: createPendingLists({ ...PENDING_OPTS, onDrop: () => guard.listingUnjudged() }) }];
  }));
  if (cfg.schemaValidation === undefined) cfg = { ...cfg, schemaValidation: "enforce" };
  if (cfg.maxResponseBytes === undefined) cfg = { ...cfg, maxResponseBytes: DEFAULT_MAX_RESPONSE_BYTES };
  const cooldown = createCooldown(cfg.cooldown || {});
  const creds = cfg.credentials || null;
  const gate = creds ? createGate(creds, { requirePlaceholders: cfg.requirePlaceholders === true }) : null;
  // A refusal the gateway made for this client (policy block, invalid message, profile block). Starting a
  // cool-down is reported once; requests refused DURING it are not counted again, at any key: counting
  // them let a cooled-down client fill the bounded tables with fresh credentials until its own entry was
  // evicted.
  function noteRefusal(ck, route) {
    if (cooldown.noteRefusal(ck)) alertCooldown(route.server, cooldown.seconds);
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
    const { route, guard, pending } = entry;
    // Placeholder credentials: refused here, before the body is read or anything is gated or counted.
    let swaps = null;
    if (gate) {
      const c = gate(req.rawHeaders, new URL(req.url, "http://x").search, route.path, upstreamUrl(route, req.url));
      if (c.error || c.raw) {
        const refused = !!(c.error && c.error.raw);
        // content-free, once per route: the route label only, never a header, a value or a hash of one
        if (refused || c.raw) reportOnce(refused ? "MCP gateway: raw credential refused (placeholders required)" : "MCP gateway: raw credential sent where placeholders are configured", `gateway:credential:raw:${refused ? "refused" : "sent"}:${route.server}`, refused ? "Blocked" : "Medium");
      }
      if (c.error) return sendJson(res, c.error.status, rpcError(null, -32600, `MoorAI MCP gateway: ${c.error.message}`));
      swaps = c.swaps;
    }
    pending.sweep(); // an entry past its TTL clears the verdicts before any call on the route is gated

    let body;
    try { body = await readBody(req, MAX_REQUEST_BYTES); }
    catch (e) { if (e.tooLarge) return sendJson(res, 413, rpcError(null, -32600, "Request too large for the gateway to inspect")); return; }

    // ---- the CALL side: validate the body (C5), then gate every tools/call in it ----
    // Keyed by idKey(id): the id as the MCP SDK client matches a response to it (Number(id)).
    const ctx = { idTool: new Map(), idMethod: new Map(), paged: new Set(), requestIds: [], route, guard, pending, cfg, httpMethod: req.method };
    const ckey = clientKey(route, req);
    if (req.method === "POST" && body.length) {
      const enforce = cfg.schemaValidation === "enforce";
      const validating = cfg.schemaValidation !== "off";
      const hpv = req.headers["mcp-protocol-version"];
      let parsed = null;
      const pb = parseBody(body, { uniqueKeys: true, maxDepth: MAX_DEPTH });
      // report|off read a body the strict stage rejected as a lenient upstream would (below), so its depth
      // is checked on that reading too.
      const lp = pb.value === undefined && !enforce ? parseLenient(body, { maxDepth: MAX_DEPTH }) : null;
      // Nesting past MAX_DEPTH is refused in every --schema mode, before any scan: the gate cannot read it.
      const deep = [pb.error, lp && lp.error].find((e) => e && e.tooDeep);
      if (deep) {
        const v = pb.value !== undefined ? pb.value : lp.value;
        alertSchema(route.server, deep, { direction: "client", refused: true, tool: toolOfBad(v, deep) });
        noteRefusal(ckey, route);
        return refuseInvalid(res, v, deep);
      }
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
      if (pb.value !== undefined) parsed = pb.value;
      if (bad) {
        alertSchema(route.server, bad, { direction: "client", refused: enforce, tool: toolOfBad(parsed, bad) });
        if (enforce) { noteRefusal(ckey, route); return refuseInvalid(res, parsed, bad); }
      }
      // --schema report|off forward a body that failed the json stage; it is still gated as a lenient
      // upstream (the MCP SDK's TextDecoder: BOM dropped, invalid UTF-8 replaced) would read it.
      if (lp && !lp.error) parsed = lp.value;
      if (Array.isArray(parsed) && parsed.length > MAX_BATCH_MESSAGES) return sendJson(res, 413, rpcError(null, -32600, `Batch too large for the gateway to inspect (more than ${MAX_BATCH_MESSAGES} messages)`));
      if (parsed && typeof parsed === "object") {
        const msgs = Array.isArray(parsed) ? parsed : [parsed];
        ctx.batch = Array.isArray(parsed);
        for (const m of msgs) {
          if (m && typeof m === "object" && typeof m.method === "string" && isId(m.id)) {
            ctx.requestIds.push(m.id);
            ctx.idMethod.set(idKey(m.id), m.method);
            if (m.method === "tools/list" && m.params && typeof m.params === "object" && m.params.cursor != null) ctx.paged.add(idKey(m.id));
          }
        }
        // C5 cool-down: a client that tripped it is refused for its duration, every request in the body.
        const left = Math.max(cooldown.remaining(ckey.key), cooldown.remaining(ckey.peer));
        if (left && ctx.requestIds.length) return refuseCooldown(res, parsed, left);
        // Every message of a batch must agree with the mirrored headers too (a header names one message).
        for (const m of msgs) {
          const mm = headerMismatch(req, m);
          if (mm) { noteRefusal(ckey, route); return sendJson(res, 400, rpcError(Array.isArray(parsed) ? null : parsed.id, -32020, `Header mismatch: ${mm}`)); }
        }
        const blocked = new Map();
        for (const m of msgs) {
          if (!m || typeof m !== "object") continue;
          if (m.result && Array.isArray(m.result.roots)) { try { guard.rememberRoots(m.result.roots); } catch { /* roots are a hint */ } }
          if (m.method !== "tools/call" || !m.params || typeof m.params !== "object") continue;
          if (m.id != null) ctx.idTool.set(idKey(m.id), String(m.params.name || "mcp"));
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
    if (swaps) for (const [k, v] of swaps) headers[k] = v; // after the hop-by-hop strip; keys lower-case, as Node's
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
    up.on("response", (raw) => {
      const ur = creds ? maskResponse(raw, creds.secrets) : raw;
      if (ur.refuse) {
        // Not forwarded, and not judged either: a listing it may carry clears the drift verdicts, as onUpstream's
        // unjudged() does for a body it cannot read.
        if (!ctx.requestIds.length || pending.any() || ctx.requestIds.some((id) => ctx.idMethod.get(idKey(id)) === "tools/list")) guard.listingUnjudged();
        return sendJson(res, 502, rpcError(null, -32603, "MoorAI MCP gateway: the upstream answered with a content coding the gateway cannot check for an echoed credential"));
      }
      onUpstream(ur, res, ctx);
    });
    // Each tools/list forwarded is outstanding until a message answering it is judged (pending-lists.mjs).
    for (const id of ctx.requestIds) if (ctx.idMethod.get(idKey(id)) === "tools/list") pending.add(id, { paged: ctx.paged.has(idKey(id)) });
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

// The content-codings the gateway decodes (RFC 9110 8.4.1: "deflate" is the zlib format).
const DECODERS = { gzip: createGunzip, "x-gzip": createGunzip, deflate: createInflate, br: createBrotliDecompress };

// The upstream response with its body decoded: the same status and headers minus Content-Encoding, read
// through the decoder. pipeline() destroys the upstream response when the decoder is destroyed (an
// over-cap body) and the decoder when the response fails, so both callers' error paths still run.
function decoded(ur, enc) {
  const dec = DECODERS[enc]();
  pipeline(ur, dec, () => {});
  const headers = { ...ur.headers };
  delete headers["content-encoding"];
  delete headers["content-length"];
  return Object.assign(dec, { statusCode: ur.statusCode, statusMessage: ur.statusMessage, headers });
}

function onUpstream(ur, res, ctx) {
  const ctype = String(ur.headers["content-type"] || "").toLowerCase();
  const enc = String(ur.headers["content-encoding"] || "identity").trim().toLowerCase();
  const passthrough = () => { res.writeHead(ur.statusCode, ur.statusMessage, { ...respHeaders(ur), ...(ur.headers["content-length"] ? { "content-length": ur.headers["content-length"] } : {}) }); ur.pipe(res); };
  const lists = ctx.requestIds.some((id) => ctx.idMethod.get(idKey(id)) === "tools/list");
  // A response with no request ids (a GET stream, a resumed one, the answer to a POST of notifications)
  // can carry the answer to ANY earlier tools/list: the client dispatches each message by its id, and the
  // MCP SDK reads any 2xx GET body as SSE whatever its Content-Type. It is decoded and scanned like a
  // tools/list answer; one forwarded unscanned clears the verdicts once a byte of it goes out.
  const idless = !ctx.requestIds.length;
  // So can the response to any other POST while a tools/list the route forwarded is still unanswered
  // (pending-lists.mjs): a hostile server answers it inside a compressed tools/call result.
  const outstanding = ctx.pending.any();
  // Every path below that forwards a tools/list answer without judging it clears the route's drift
  // verdicts (guard.listingUnjudged): no earlier verdict may vouch for a tool the client was just told about.
  // Any other response clears them once a byte of it goes out while a tools/list is outstanding, also one
  // sent after this response started (answered on a long compressed stream already passing through).
  const unjudged = () => {
    if (lists) return ctx.guard.listingUnjudged();
    ur.on("data", function watch(c) { if (c.length && (idless || ctx.pending.any())) { ur.off("data", watch); ctx.guard.listingUnjudged(); } });
  };

  if (enc !== "identity" && (ctype.includes("json") || ctype.includes("event-stream"))) {
    // A compressed answer to a tools/list (the gateway asked for identity; the server ignored it), a
    // compressed response with no request ids, or any compressed response while a tools/list is
    // outstanding, is decoded and judged like any other, and the client gets the decoded body. Anything
    // else compressed is forwarded unscanned, as before.
    if ((lists || idless || outstanding) && Object.hasOwn(DECODERS, enc)) ur = decoded(ur, enc);
    else {
      unjudged();
      reportOnce("MCP gateway: compressed upstream response forwarded unscanned", `gateway:unscanned:encoding:${enc}`, "Info");
      return passthrough();
    }
  }
  const x = {
    ...ctx,
    idless,
    toolOf: (id) => (id != null && ctx.idTool.get(idKey(id))) || "mcp",
    // an id this POST did not send may answer an outstanding tools/list
    methodOf: (id) => (id != null && (ctx.idMethod.get(idKey(id)) || (ctx.pending.get(id) ? "tools/list" : ""))) || "",
    pagedOf: (id) => id != null && (ctx.idMethod.has(idKey(id)) ? ctx.paged.has(idKey(id)) : !!(ctx.pending.get(id) || {}).paged),
    // The MCP SDK client reads messages from the response to a POST that carried a request, and from a
    // GET stream (SSE only); the body of any other POST it cancels unread.
    sdkReads: ctx.httpMethod === "GET" || ctx.requestIds.length > 0,
    cap: ctx.cfg.maxResponseBytes,
    validating: ctx.cfg.schemaValidation !== "off",
    enforce: ctx.cfg.schemaValidation === "enforce"
  };
  if (ctype.startsWith("text/event-stream")) return onSse(ur, res, x);
  if (ctype.startsWith("application/json")) return onJson(ur, res, x);
  unjudged();
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
// A response forwarded unscanned to a POST that carried a tools/list, with no request ids at all, or
// while any tools/list on the route is outstanding (it may answer an earlier one): the listing went unjudged.
const listUnjudged = (x) => { if (x.idless || x.pending.any() || x.requestIds.some((id) => x.methodOf(id) === "tools/list")) x.guard.listingUnjudged(); };
// A message answers an outstanding tools/list, and takes its entry as it is judged, only when the MCP
// SDK client would dispatch it as that answer: read at all (x.sdkReads, `dispatchable`: a JSON batch the
// SDK refuses whole, an SSE event that is not a single "message", is not), a well-formed response
// (sdkKind) that is an error or a result with a `tools` array, whose id (as the SDK reads it) this POST
// did not send for another method, while an entry for that id is outstanding. → { paged } or null.
// Every other listing is judged tighten-only (guard.gateResult): a late duplicate for an id already
// answered, which the SDK drops (it keeps the first answer), can quarantine a tool but never clear one.
function claim(x, m, dispatchable) {
  if (!x.sdkReads || !dispatchable) return null;
  const kind = sdkKind(m);
  if (!(kind === "error" && isId(m.id)) && !(kind === "result" && Array.isArray(m.result.tools))) return null;
  const own = x.idMethod.get(idKey(m.id));
  if (own !== undefined && own !== "tools/list") return null;
  return x.pending.take(m.id);
}
// A claimed answer that did not reach the client (it went away first) is outstanding again.
const unclaim = (x, claims) => { for (const [m, c] of claims) x.pending.add(m.id, c); };
// One server → client message, judged: schema stage, then the result / listing gate.
async function judge(x, m, path, claims, dispatchable) {
  const rep = checkServerMessage(m, x, path);
  const c = claim(x, m, dispatchable);
  if (c) claims.push([m, c]);
  return rep || await x.guard.gateResult(m, x.toolOf(m && m.id), { paged: c ? c.paged : x.pagedOf(m && m.id), tightenOnly: !c });
}

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
      listUnjudged(x);
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
    const claims = [];
    if (raw.length > CAPS.maxLineBytes) { listUnjudged(x); reportOnce("MCP gateway: oversized response forwarded unscanned", "gateway:unscanned:size", "Info"); }
    else {
      try {
        const pb = parseBody(raw);
        let value = pb.value;
        // A body that fails the strict json stage is reported, and still scanned as the client will read
        // it (fetch().json(): BOM dropped, invalid UTF-8 replaced), as the gateway scanned it before C5.
        if (pb.error) {
          if (x.validating && raw.length) alertSchema(x.route.server, pb.error, { direction: "server", refused: false });
          const lp = parseLenient(raw);
          value = lp.error ? undefined : lp.value;
        }
        if (value === undefined) { if (raw.length) listUnjudged(x); /* nothing a client can parse either: forwarded as it came */ }
        else if (Array.isArray(value)) {
          // the SDK parses every message of a JSON body before dispatching any: one it refuses, none go
          const dispatchable = value.every((m) => sdkKind(m) !== null);
          let changed = false;
          const next = [];
          for (let i = 0; i < value.length; i++) {
            const m = value[i];
            const r = await judge(x, m, `$[${i}]`, claims, dispatchable);
            if (r) changed = true;
            next.push(r || m);
          }
          if (changed) out = Buffer.from(JSON.stringify(next));
        } else {
          const r = await judge(x, value, "$", claims, true);
          if (r) out = Buffer.from(JSON.stringify(r));
        }
      } catch { listUnjudged(x); /* a failed scan: the original goes, unjudged */ }
    }
    if (res.destroyed) return unclaim(x, claims);
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
    // No cap (0): an event past CAPS.maxLineBytes streams through as raw text, never parsed or scanned.
    onUnscanned: () => enqueue(() => listUnjudged(x)),
    onOverflow: x.cap ? ({ id }) => enqueue(async () => {
      alertTooLarge(x.route.server, tooLargeTool(x), x.cap);
      if (x.batch || x.requestIds.length !== 1) return;
      await write(sseEvent(tooLargeReply(x), id));
      if (!res.writableEnded) res.end();
      ur.destroy();
    }) : null,
    onEvent: (ev) => enqueue(async () => {
      if (ev.bytes > CAPS.maxLineBytes) {
        listUnjudged(x);
        reportOnce("MCP gateway: oversized SSE event forwarded unscanned", "gateway:unscanned:sse-size", "Info");
        return write(ev.raw);
      }
      // Validated as a message only when it is one ("message" or no event: type); scanned whatever its
      // type, every element of an array, on the parsed value (a "\u0072esult" key is still a result).
      let rep = null;
      const claims = [];
      // the SDK dispatches a "message" event holding one message; an array or another type, never
      const scan = async (m, dispatchable) => {
        const c = claim(x, m, dispatchable);
        if (c) claims.push([m, c]);
        try { return await guard.gateResult(m, x.toolOf(m && m.id), { paged: c ? c.paged : x.pagedOf(m && m.id), tightenOnly: !c }); } catch { listUnjudged(x); return null; }
      };
      if (ev.data != null) {
        const isMessage = ev.type == null || ev.type === "" || ev.type === "message";
        let m, ok = true;
        try { m = JSON.parse(ev.data); } catch { ok = false; }
        // On a stream with no request ids only a "message" event can be a listing the client reads (the
        // SDK parses no other type), so an unparseable keep-alive there does not clear the verdicts.
        if (!ok) { if (isMessage || !x.idless) listUnjudged(x); if (x.validating && isMessage) alertSchema(x.route.server, { stage: "json", path: "$" }, { direction: "server", refused: false }); }
        else if (Array.isArray(m)) {
          let changed = false;
          const next = [];
          for (let i = 0; i < m.length; i++) {
            const v = x.validating && isMessage && validateServerMessage(m[i], { path: `$[${i}]`, methodOf: x.methodOf });
            if (v) alertSchema(x.route.server, v, { direction: "server", refused: false });
            const r = await scan(m[i], false);
            if (r) changed = true;
            next.push(r || m[i]);
          }
          if (changed) rep = next;
        } else rep = (isMessage && checkServerMessage(m, x)) || await scan(m, isMessage);
      }
      await write(rep ? sseEvent(rep, ev.id) : ev.raw);
      if (res.destroyed) unclaim(x, claims);
    })
  });
  ur.on("data", (c) => { try { framer.push(c); } catch { enqueue(() => write(c.toString("utf8"))); } });
  ur.on("end", () => { try { framer.end(); } catch { /* nothing left to frame */ } enqueue(async () => { if (!res.writableEnded) res.end(); }); });
  ur.on("error", () => { if (!res.writableEnded) res.destroy(); });
}
