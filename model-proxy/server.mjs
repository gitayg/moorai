// The model proxy's HTTP server: routes, forwarding, the checks in each direction, report vs enforce.
//
//   agent SDK ──http──▶ 127.0.0.1:8791/<route>/… ──https──▶ provider (the route's upstream base URL)
//
// Every request header except hop-by-hop ones, Host and X-MoorAI-Proxy-Token goes upstream as sent —
// x-api-key, Authorization, anthropic-version / -beta, OpenAI-Organization: the client's own credentials,
// never read, stored, logged or reported. Accept-Encoding is replaced by "identity" so a response can be
// parsed. Every response header except hop-by-hop ones comes back.
//
// Only POST …/messages (Anthropic) and POST …/chat/completions (OpenAI) are parsed; any other path or
// method is forwarded unparsed.
import http from "node:http";
import https from "node:https";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { timingSafeEqual, createHash } from "node:crypto";
import { createMoorAI } from "../packages/agent-sdk/src/runtime.mjs";
import { isLoopback } from "../cli/moorai-serve.mjs";
import * as anthropic from "./anthropic.mjs";
import * as openai from "./openai.mjs";
import { createSplitter } from "./sse.mjs";
import { createChecker } from "./check.mjs";
import { wrapReporter, unevaluatedReporter, refusalMessage } from "./report.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFAULTS = Object.freeze({
  host: "127.0.0.1", port: 8791, mode: "report", maxBody: 33554432, maxResponse: 33554432, maxInflight: 268435456,
  maxEvent: 1048576, maxScanItems: 256, maxScanChars: 524288, timeoutMs: 10000, upstreamTimeoutMs: 600000, maxConnections: 128,
  routes: Object.freeze({ "/anthropic": "https://api.anthropic.com", "/openai": "https://api.openai.com/v1" })
});
export const TOKEN_HEADER = "x-moorai-proxy-token";
const HOP = new Set(["connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding", TOKEN_HEADER]);
const HOP_RES = new Set(["connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]);

// Report-only work runs after the response is complete, so a scan (≈10 ms for 2 KB, measured) never
// sits between the provider's bytes and the agent. Bounded: at most 256 queued checks per request.
function deferrer() {
  const q = [];
  let closed = false, running = false;
  const pump = async () => {
    if (running) return;
    running = true;
    while (q.length) { const f = q.shift(); try { await f(); } catch { /* report-only */ } }
    running = false;
  };
  return { push(f) { if (q.length >= 256) return; q.push(f); if (closed) setImmediate(pump); }, close() { closed = true; setImmediate(pump); } };
}

// The provider closed the connection before its response ended. Headers still unsent (non-streaming), the
// 502 carries `x-should-retry: false`: the Anthropic and OpenAI SDKs obey that header before their status
// rules (408/409/429/>=500 retried), so the request is not silently re-sent. Mid-stream no status can be
// sent; the SDKs raise the error event as an APIError and do not retry a stream.
const UPSTREAM_CLOSED = "MoorAI model-proxy: the upstream closed the response before it ended";
const UPSTREAM_CLOSED_IN_CALL = "MoorAI model-proxy: the upstream closed inside a tool call; it was not released";
const NO_RETRY = { "x-should-retry": "false" };

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }

function hostHeaderOk(header) {
  const h = String(header || "");
  const name = h.startsWith("[") ? h.slice(0, h.indexOf("]") + 1) : h.split(":")[0];
  return isLoopback(name);
}
// A browser Origin is accepted only when it is loopback or listed with --allow-origin — the MCP gateway's
// rule (mcp-gateway/server.mjs originOk), so a web page cannot drive the proxy with the agent's key.
function originOk(origin, allow) {
  if (origin == null) return true;
  if (allow.includes(origin)) return true;
  try { const u = new URL(origin); return (u.protocol === "http:" || u.protocol === "https:") && isLoopback(u.hostname); } catch { return false; }
}
const digest = (s) => createHash("sha256").update(String(s)).digest();
const apiFor = (method, path) => (method !== "POST" ? null : /\/messages$/.test(path) ? anthropic : /\/chat\/completions$/.test(path) ? openai : null);
const parseJson = (buf) => { try { const v = JSON.parse(buf.toString("utf8")); return v && typeof v === "object" ? v : null; } catch { return null; } };

// Proxy-generated errors on a parsed path take that provider's documented error shape; elsewhere a shape
// both SDKs read (`error.message`).
function errorPayload(api, status, message) {
  return api ? api.errorBody(status, message) : { type: "error", error: { type: "proxy_error", message } };
}

export async function createProxy(opts = {}) {
  const o = { ...DEFAULTS, ...opts, routes: opts.routes || DEFAULTS.routes };
  const enforce = o.mode === "enforce";
  // Report-only passes an "ask" through unsettled (nothing is enforced, so nothing is settled); enforce
  // applies server mode's headless rule: an ask with no approver is a deny unless a trusted source says
  // allow-with-report.
  const rt = await createMoorAI({ policyFile: o.policyFile, policy: o.policy, serviceId: o.serviceId, headlessAsk: enforce ? o.headlessAsk : "pass-through", console: o.console, fetch: o.fetch, env: o.env, systemConfig: o.systemConfig, surface: "model-proxy" });
  await rt.ready();
  wrapReporter(rt, { enforce });
  const unevaluated = unevaluatedReporter(rt);
  const checker = createChecker(rt, { enforce, cwd: o.cwd || process.cwd(), onUnevaluated: unevaluated, maxItems: o.maxScanItems, itemCap: o.maxScanChars });
  const version = (() => { try { return JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version; } catch { return "unknown"; } })();
  const routes = Object.entries(o.routes).map(([prefix, base]) => ({ prefix: prefix === "/" ? "" : prefix.replace(/\/+$/, ""), base: String(base).replace(/\/+$/, "") })).sort((a, b) => b.prefix.length - a.prefix.length);
  const agents = { "http:": new http.Agent({ keepAlive: true, maxSockets: o.maxConnections }), "https:": new https.Agent({ keepAlive: true, maxSockets: o.maxConnections }) };
  const loopbackBind = isLoopback(o.host);
  let inflight = 0;
  const stats = { refused: 0, forwarded: 0 };

  function reserve(n, api) {
    if (inflight + n > o.maxInflight) throw new HttpError(api === openai ? 503 : 529, "the proxy is at its in-flight memory budget; retry");
    inflight += n;
  }
  function send(res, status, payload, extra = {}) {
    if (res.headersSent) { res.destroy(); return; }
    const body = JSON.stringify(payload);
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff", "content-length": Buffer.byteLength(body), ...extra });
    res.end(body);
  }
  const refuse = (res, api, verdict, direction) => { stats.refused++; send(res, 403, api.errorBody(403, refusalMessage(verdict, direction)), { "x-moorai-model-proxy": "refused" }); };

  // The request body, buffered (it is needed whole to scan before forwarding in enforce mode, and its
  // length goes upstream). Over the cap: 413 once the client has finished sending, as moorai-serve does;
  // past 8x the cap the socket is dropped.
  function readBody(req, api, held) {
    return new Promise((resolve, reject) => {
      const declared = Number(req.headers["content-length"]);
      const tooBig = () => new HttpError(413, `request body over ${o.maxBody} bytes`);
      if (declared > o.maxBody * 8) { req.destroy(); return reject(tooBig()); }
      const chunks = []; let n = 0, over = declared > o.maxBody, done = false;
      req.on("data", (c) => {
        if (done) return;
        n += c.length;
        if (n > o.maxBody) { over = true; if (chunks.length) { inflight -= held.n; held.n = 0; chunks.length = 0; } }
        if (n > o.maxBody * 8) { done = true; req.destroy(); return reject(tooBig()); }
        if (over) return;
        try { reserve(c.length, api); held.n += c.length; chunks.push(c); } catch (e) { done = true; req.resume(); reject(e); }
      });
      req.on("end", () => { if (done) return; done = true; if (over) return reject(tooBig()); resolve(Buffer.concat(chunks)); });
      req.on("error", () => { if (!done) { done = true; reject(new HttpError(400, "request aborted")); } });
    });
  }

  function upstreamHeaders(req, length) {
    const h = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k)) h[k] = v;
    h["accept-encoding"] = "identity";
    h["content-length"] = String(length);
    return h;
  }
  function responseHeaders(ur, { dropLength = false } = {}) {
    const h = {};
    for (const [k, v] of Object.entries(ur.headers)) if (!HOP_RES.has(k) && !(dropLength && k === "content-length")) h[k] = v;
    return h;
  }
  const withTimeout = (p) => { let t; return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error("evaluation timeout")), o.timeoutMs); })]).finally(() => clearTimeout(t)); };

  // Response side ----------------------------------------------------------------------------------------
  async function onResponse(ur, res, api, held, later) {
    const ct = String(ur.headers["content-type"] || "");
    const enc = String(ur.headers["content-encoding"] || "identity").toLowerCase();
    const ok = ur.statusCode >= 200 && ur.statusCode < 300;
    const sse = /^text\/event-stream\b/i.test(ct);
    if (!api || !ok) { res.writeHead(ur.statusCode, responseHeaders(ur)); ur.pipe(res); return; }
    if (enc !== "identity") {
      // Unscannable. Report-only forwards it (and says so once); enforce does not forward what it cannot read.
      unevaluated("response-encoding", "response");
      if (enforce) { ur.resume(); return send(res, 502, api.errorBody(502, "MoorAI model-proxy: the provider answered with a compressed body it cannot inspect")); }
      res.writeHead(ur.statusCode, responseHeaders(ur)); ur.pipe(res); return;
    }
    const ALLOW = { decision: "allow", denied: [] };
    const decide = enforce
      ? (calls) => (calls.length ? withTimeout(checker.checkToolCalls(calls)) : Promise.resolve(ALLOW))
      : (calls) => { if (calls.length) later.push(() => checker.checkToolCalls(calls)); return Promise.resolve(ALLOW); };
    if (sse) return enforce ? streamEnforce(ur, res, api, decide) : streamObserve(ur, res, api, decide);
    if (!enforce) {
      // Report-only: bytes go to the client as they arrive; a bounded copy is parsed after the end.
      res.writeHead(ur.statusCode, responseHeaders(ur));
      const chunks = []; let n = 0, over = false;
      ur.on("data", (c) => { if (over) return; n += c.length; if (n > o.maxResponse) { over = true; chunks.length = 0; return; } chunks.push(c); });
      ur.on("end", () => {
        if (over) return;
        const body = parseJson(Buffer.concat(chunks));
        if (body) decide(api.responseToolCalls(body));
      });
      ur.pipe(res);
      return;
    }
    // Enforce, non-streaming: the whole body is held, decided, then sent unchanged or refused.
    const chunks = []; let n = 0;
    try {
      for await (const c of ur) {
        n += c.length;
        if (n > o.maxResponse) { ur.destroy(); return send(res, 502, api.errorBody(502, `MoorAI model-proxy: the response is over the ${o.maxResponse}-byte inspection cap`)); }
        reserve(c.length, api); held.n += c.length;
        chunks.push(c);
      }
    } catch (e) {
      if (e instanceof HttpError) throw e;
      // The provider closed the connection before the body ended. Nothing of it is forwarded.
      return send(res, 502, api.errorBody(502, UPSTREAM_CLOSED), NO_RETRY);
    }
    const buf = Buffer.concat(chunks);
    const body = parseJson(buf);
    if (body) {
      let v;
      try { v = await decide(api.responseToolCalls(body)); } catch { return send(res, api === openai ? 503 : 529, api.errorBody(api === openai ? 503 : 529, "MoorAI model-proxy: evaluation did not finish in time; retry")); }
      if (v.decision === "deny") return refuse(res, api, v, "response");
    }
    res.writeHead(ur.statusCode, { ...responseHeaders(ur, { dropLength: true }), "content-length": buf.length });
    res.end(buf);
  }

  async function streamObserve(ur, res, api, decide) {
    res.writeHead(ur.statusCode, responseHeaders(ur));
    const split = createSplitter(o.maxEvent);
    const machine = api.createStream({ enforce: false, decide, maxHold: o.maxEvent });
    let stopped = false;
    const feed = (evs) => { for (const ev of evs) machine.onEvent(ev).catch(() => {}); };
    ur.on("data", (c) => { if (stopped) return; feed(split.push(c)); if (split.overflow) { stopped = true; unevaluated("stream-event", "response"); } });
    ur.on("end", () => { if (stopped) return; feed(split.end()); machine.onEnd().catch(() => {}); });
    ur.pipe(res);
  }

  async function streamEnforce(ur, res, api, decide) {
    res.writeHead(ur.statusCode, responseHeaders(ur, { dropLength: true }));
    const split = createSplitter(o.maxEvent);
    const machine = api.createStream({ enforce: true, decide, maxHold: o.maxEvent });
    const write = async (bufs) => { for (const b of bufs) if (!res.write(b)) await Promise.race([once(res, "drain"), once(res, "close")]); };
    const stop = async (status, message) => { stats.refused++; ur.destroy(); res.end(api.streamError(status, message)); };
    const step = async (r) => {
      if (r.refuse) { await stop(403, refusalMessage(r.refuse, "response")); return false; }
      await write(r.out);
      return true;
    };
    try {
      for await (const c of ur) {
        for (const ev of split.push(c)) if (!(await step(await machine.onEvent(ev)))) return;
        if (split.overflow) return stop(502, "MoorAI model-proxy: a stream event exceeded the inspection cap");
        if (res.destroyed) { ur.destroy(); return; }
      }
      for (const ev of split.end()) if (!(await step(await machine.onEvent(ev)))) return;
      if (!(await step(await machine.onEnd()))) return;
      res.end();
    } catch (e) {
      if (res.writableEnded) return;
      // Only the evaluation budget is "retry later"; the provider closing the stream mid-way is a 502-class
      // error (Anthropic api_error, OpenAI server_error), and a held tool call is never released.
      if (e && e.message === "evaluation timeout") stop(api === openai ? 503 : 529, "MoorAI model-proxy: evaluation did not finish in time");
      else stop(502, machine.holding ? UPSTREAM_CLOSED_IN_CALL : UPSTREAM_CLOSED);
    }
  }

  // Request side -----------------------------------------------------------------------------------------
  async function handle(req, res) {
    const [path, query] = (() => { const i = req.url.indexOf("?"); return i < 0 ? [req.url, ""] : [req.url.slice(0, i), req.url.slice(i)]; })();
    if (loopbackBind && !hostHeaderOk(req.headers.host)) throw new HttpError(421, "Host header is not a loopback name");
    if (!originOk(req.headers.origin, o.allowOrigins || [])) throw new HttpError(403, "Origin not allowed");
    if (path === "/healthz" && req.method === "GET") { const s = await rt.ready(); return send(res, 200, { status: "ok", version, policyId: s.policyId, mode: o.mode }); }
    if (o.token) {
      const got = String(req.headers[TOKEN_HEADER] || "");
      if (!got || !timingSafeEqual(digest(got), digest(o.token))) throw new HttpError(401, `missing or wrong ${TOKEN_HEADER}`);
    }
    const route = routes.find((r) => path === r.prefix || path.startsWith(`${r.prefix}/`));
    if (!route) throw new HttpError(404, "no model-proxy route at this path");
    const rest = path.slice(route.prefix.length) || "/";
    const api = apiFor(req.method, rest);
    const held = { n: 0 };
    const later = deferrer();
    res.on("close", () => { inflight -= held.n; held.n = 0; later.close(); });
    let body;
    try { body = await readBody(req, api, held); } catch (e) { e.api = api; throw e; }

    if (api) {
      const json = parseJson(body);
      const items = json ? api.outboundItems(json) : [];
      if (enforce && items.length) {
        let v;
        try { v = await withTimeout(checker.checkRequest(items)); } catch { return send(res, api === openai ? 503 : 529, api.errorBody(api === openai ? 503 : 529, "MoorAI model-proxy: evaluation did not finish in time; retry")); }
        if (v.decision === "deny") return refuse(res, api, v, "request");
      } else if (items.length) later.push(() => checker.checkRequest(items));
    }

    const url = new URL(route.base + rest + query);
    const lib = url.protocol === "https:" ? https : http;
    stats.forwarded++;
    await new Promise((resolve) => {
      const up = lib.request(url, { method: req.method, headers: upstreamHeaders(req, body.length), agent: agents[url.protocol] }, (ur) => {
        onResponse(ur, res, api, held, later).catch(() => { if (!res.headersSent) send(res, 502, errorPayload(api, 502, "MoorAI model-proxy: upstream response failed")); else res.destroy(); }).finally(resolve);
      });
      up.setTimeout(o.upstreamTimeoutMs, () => up.destroy(new Error("upstream timeout")));
      // The URL is never put in an error: its query string can carry a credential.
      up.on("error", () => { if (!res.headersSent) send(res, 502, errorPayload(api, 502, "MoorAI model-proxy: the upstream provider could not be reached")); else res.destroy(); resolve(); });
      res.on("close", () => { if (!res.writableFinished) up.destroy(); });
      up.end(body);
    });
  }

  const log = (req, status, t0) => { if (o.log) process.stderr.write(`${new Date().toISOString()} ${req.method} ${req.url.split("?")[0]} ${status} ${(performance.now() - t0).toFixed(1)}ms\n`); };
  const server = http.createServer(async (req, res) => {
    const t0 = performance.now();
    res.on("finish", () => log(req, res.statusCode, t0));
    try { await handle(req, res); } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      if (status === 413 || status === 529 || status === 503) req.resume();
      send(res, status, errorPayload(e.api, status, e instanceof HttpError ? `MoorAI model-proxy: ${e.message}` : "MoorAI model-proxy: internal error"));
    }
  });
  server.headersTimeout = 10000;
  server.requestTimeout = 120000;
  server.keepAliveTimeout = 5000;
  server.maxConnections = o.maxConnections;
  await new Promise((res, rej) => { server.once("error", rej); server.listen(o.port, o.host, () => { server.off("error", rej); res(); }); });
  const addr = server.address();
  const url = `http://${addr.family === "IPv6" ? `[${addr.address}]` : addr.address}:${addr.port}`;
  const close = async () => { await new Promise((r) => server.close(() => r())); server.closeAllConnections?.(); for (const a of Object.values(agents)) a.destroy(); await rt.flush(); };
  return { server, url, runtime: rt, close, stats: () => ({ ...stats, inflight, cache: checker.cacheSize() }) };
}
