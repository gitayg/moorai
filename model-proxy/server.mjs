// The model proxy's HTTP server: routes, forwarding, the checks in each direction, report vs enforce.
//
//   agent SDK ──http──▶ 127.0.0.1:8791/<route>/… ──https──▶ provider (the route's upstream base URL)
//
// Every request header except hop-by-hop ones, Host and X-MoorAI-Proxy-Token goes upstream as sent —
// x-api-key, Authorization, anthropic-version / -beta, OpenAI-Organization: the client's own credentials,
// never read, stored, logged or reported. Accept-Encoding is replaced by "identity" so a response can be
// parsed, and traceparent / tracestate by this hop's trace (below). Every response header except hop-by-hop
// ones comes back.
//
// With placeholder credentials configured (opts.credentials, credentials.mjs) a header carrying a
// `moorai-ph:<name>` placeholder has its whole value replaced by the bound secret, on the bound route only;
// any other placeholder use is refused before the body is read, and every response is masked for the bound
// secrets (credential-mask.mjs) before anything reads it. Without them, nothing here changes.
//
// Only POST …/messages (Anthropic), POST …/chat/completions (OpenAI), POST …/models/{model}:generateContent
// / :streamGenerateContent (Gemini, on any route) and POST …/api/chat / …/api/generate (Ollama's native API,
// on any route; NDJSON streams) are parsed; any other path or method is forwarded unparsed.
//
// Every forwarded request carries the agent session's W3C trace (trace-w3c.mjs): `traceparent` is set to
// this request's span — continuing a valid incoming traceparent, else the session's trace when the client
// names its session in X-Claude-Code-Session-Id (Claude Code sends the same id its hooks get), else a new
// trace — and the moorai entry is merged into `tracestate`. Every alert raised for the request carries
// traceId / spanId / parentSpanId, the provider and the request's model (report.mjs REQUEST).
import http from "node:http";
import https from "node:https";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { timingSafeEqual, createHash } from "node:crypto";
import { createMoorAI, resolveSettings } from "../packages/agent-sdk/src/runtime.mjs";
import { createTracer, applyTraceHeaders, cleanModel } from "./trace-w3c.mjs";
import { createTrail } from "./trail.mjs";
import { REASON } from "../cli/provenance.mjs";
import { isLoopback } from "../cli/moorai-serve.mjs";
import * as anthropic from "./anthropic.mjs";
import * as openai from "./openai.mjs";
import * as gemini from "./gemini.mjs";
import * as ollama from "./ollama.mjs";
import { createSplitter } from "./sse.mjs";
import { createLineSplitter } from "./ndjson.mjs";
import { strictBytes, PROBLEM_TEXT } from "./json-strict.mjs";
import { createChecker } from "./check.mjs";
import { wrapReporter, unevaluatedReporter, uncheckedReporter, refusalMessage, REQUEST } from "./report.mjs";
import { createUncheckedTracker, DEFAULT_MAX as UNCHECKED_MAX, MAX_ID } from "./unchecked.mjs";
import { PATH as CHECKED_PATH, MAX_BATCH as CHECKED_BATCH } from "./checked-notify.mjs";
import { createGate } from "./credentials.mjs";
import { maskResponse } from "./credential-mask.mjs";
import { resolveFailMode } from "../cli/fail-mode.mjs";
import { systemConfig } from "../cli/server-mode.mjs";
import { operatorContextMode } from "./context.mjs";
import { createDecoyCheck, decoyAlert, DECOY_REFUSAL } from "./decoy.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFAULTS = Object.freeze({
  host: "127.0.0.1", port: 8791, mode: "report", maxBody: 33554432, maxResponse: 33554432, maxInflight: 268435456,
  maxEvent: 1048576, maxScanItems: 256, maxScanChars: 524288, timeoutMs: 10000, upstreamTimeoutMs: 600000, connectTimeoutMs: 10000, maxConnections: 128,
  deniedToolCall: "refuse", uncheckedWindowMs: 0, uncheckedMax: UNCHECKED_MAX,
  routes: Object.freeze({ "/anthropic": "https://api.anthropic.com", "/openai": "https://api.openai.com/v1", "/gemini": "https://generativelanguage.googleapis.com", "/ollama": "http://127.0.0.1:11434" })
});
// The /ollama default (Ollama's documented default address) is a default on a loopback bind only: Ollama's
// API has no authentication, so on a remote bind the default would hand its model-management endpoints
// (/api/pull, /api/delete, /api/create …, forwarded unparsed) to every token holder. An explicit --route
// /ollama=… keeps it anywhere.
export function defaultRoutes(host) {
  const r = { ...DEFAULTS.routes };
  if (!isLoopback(host)) delete r["/ollama"];
  return r;
}
export const TOKEN_HEADER = "x-moorai-proxy-token";
// The agent session a request belongs to, as Claude Code states it to its model endpoint (measured, Claude
// Code 2.1.295: the same id as its hooks' session_id). Read for the trace id only; forwarded as sent.
export const SESSION_HEADER = "x-claude-code-session-id";
export const HOP = new Set(["connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding", TOKEN_HEADER]);
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
const apiFor = (method, path) => (method !== "POST" ? null : /\/messages$/.test(path) ? anthropic : /\/chat\/completions$/.test(path) ? openai : gemini.isPath(path) ? gemini : ollama.isPath(path) ? ollama : null);
// The retryable status of the proxy's own budget errors: OpenAI, Gemini and Ollama 503, Anthropic 529 (overloaded).
const busy = (api) => (api === openai || api === gemini || api === ollama ? 503 : 529);
// A response (body, SSE event data, NDJSON line) that is not strict JSON has no one reading (json-strict.mjs):
// enforce does not forward it; report mode forwards it and reports it.
const strictMessage = (p) => `MoorAI model-proxy: the response ${PROBLEM_TEXT[p]}, so a client could read it differently than it was checked; it was not forwarded`;
const eventScan = (ev) => (!ev.data || !ev.data.trim() || ev.data === "[DONE]" ? null : strictBytes(ev.raw, ev.data));
// Numbers JSON.parse rounds (an id past 2^53) are not refused outside an index field; their source digits,
// from every body or event of this response, go with each tool call to the content scan (check.mjs scanArgs),
// so a re-serialized, rounded number never hides a digit run the scan matches on. Bounded.
function largeNumbers() {
  const list = [];
  return {
    note(r) { if (r && r.large.length && list.length < 256) list.push(...r.large.slice(0, 256 - list.length)); },
    attach: (calls) => (list.length ? calls.map((c) => ({ ...c, numbers: [...(c.numbers || []), ...list] })) : calls)
  };
}
// The provider a request goes to, by the API it speaks, else by the default route it took.
const PROVIDER_OF = { anthropic: "anthropic", openai: "openai", gemini: "google", ollama: "ollama" };
const PROVIDER_OF_ROUTE = { "/anthropic": "anthropic", "/openai": "openai", "/gemini": "google", "/ollama": "ollama" };
const providerOf = (api, prefix) => (api && PROVIDER_OF[api.NAME]) || PROVIDER_OF_ROUTE[prefix] || "other";
// The request's model: Gemini names it in the path (…/models/{model}:generateContent), the others in the body.
function modelOf(api, rest, json) {
  if (api === gemini) { let p = rest; try { p = decodeURIComponent(rest); } catch { /* as sent */ } const m = /\/(?:models|tunedModels|endpoints)\/([^/]+):[A-Za-z]+$/.exec(p); return cleanModel(m && m[1]); }
  return cleanModel(json && json.model);
}
const parseJson = (buf) => { try { const v = JSON.parse(buf.toString("utf8")); return v && typeof v === "object" ? v : null; } catch { return null; } };

// Proxy-generated errors on a parsed path take that provider's documented error shape; elsewhere a shape
// both SDKs read (`error.message`).
function errorPayload(api, status, message) {
  return api ? api.errorBody(status, message) : { type: "error", error: { type: "proxy_error", message } };
}

export async function createProxy(opts = {}) {
  const o = { ...DEFAULTS, ...opts, routes: opts.routes || defaultRoutes(opts.host || DEFAULTS.host) };
  const enforce = o.mode === "enforce";
  // --denied-tool-call replace: a denied tool call is withheld and its turn delivered as text explaining
  // why (anthropic-replace.mjs, openai-replace.mjs) instead of the whole response being refused.
  const replace = enforce && o.deniedToolCall === "replace";
  // Report-only passes an "ask" through unsettled (nothing is enforced, so nothing is settled); enforce
  // applies server mode's headless rule: an ask with no approver is a deny unless a trusted source says
  // allow-with-report.
  const rt = await createMoorAI({ policyFile: o.policyFile, policy: o.policy, serviceId: o.serviceId, headlessAsk: enforce ? o.headlessAsk : "pass-through", console: o.console, fetch: o.fetch, env: o.env, systemConfig: o.systemConfig, surface: "model-proxy" });
  await rt.ready();
  wrapReporter(rt, { enforce });
  const consoleConfig = resolveSettings({ console: o.console }, { env: o.env || process.env, system: o.systemConfig }).config;
  const tracer = createTracer({ tenantKey: consoleConfig.installToken, agentName: rt.identity.agentName });
  const unevaluated = unevaluatedReporter(rt);
  // What to do with content the proxy cannot judge (an item past a scan cap, an engine error, the evaluation
  // budget run out): cli/fail-mode.mjs decides — the root-owned admin binding, then the signed policy's
  // failMode, then this proxy's own behaviour (enforce: closed, report: open). opts.resolveFailMode replaces
  // the resolver (tests); opts.systemConfig is the admin binding, as for the runtime.
  const resolveFM = typeof o.resolveFailMode === "function" ? o.resolveFailMode : resolveFailMode;
  const admin = o.systemConfig !== undefined ? o.systemConfig : systemConfig();
  const fallback = enforce ? "closed" : "open";
  const failMode = (policy) => { const m = resolveFM(policy, "modelProxy", { admin, fallback })?.mode; return m === "open" || m === "closed" ? m : fallback; };
  // Operator context (context.mjs): judged like any request content unless the verified signed policy or the
  // admin binding sets operatorContext.privacy "report". A --policy-file or options policy cannot.
  const warned = new Set();
  const contextPrivacy = (s) => {
    const r = operatorContextMode({ policy: s.policy, policySource: s.source, admin });
    if (r.ignored && !warned.has(s.policyId)) { warned.add(s.policyId); try { process.stderr.write(`moorai-model-proxy: operatorContext in a ${s.source} policy ignored; only the verified signed policy or the admin binding sets it\n`); } catch { /* a warning */ } }
    return r.mode;
  };
  const checker = createChecker(rt, { enforce, cwd: o.cwd || process.cwd(), onUnevaluated: unevaluated, maxItems: o.maxScanItems, itemCap: o.maxScanChars, failClosed: (policy) => enforce && failMode(policy) === "closed", contextPrivacy });
  const version = (() => { try { return JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version; } catch { return "unknown"; } })();
  // The allow trail (trail.mjs): one record per forwarded model request, when the signed policy turns it on.
  const trail = createTrail(rt, { config: consoleConfig, appVersion: version });
  const routes = Object.entries(o.routes).map(([prefix, base]) => ({ prefix: prefix === "/" ? "" : prefix.replace(/\/+$/, ""), base: String(base).replace(/\/+$/, "") })).sort((a, b) => b.prefix.length - a.prefix.length);
  const agents = { "http:": new http.Agent({ keepAlive: true, maxSockets: o.maxConnections }), "https:": new https.Agent({ keepAlive: true, maxSockets: o.maxConnections }) };
  const loopbackBind = isLoopback(o.host);
  const readySockets = new WeakSet(); // upstream sockets past connect (and TLS handshake): reused ones skip the connect budget
  let inflight = 0;
  const stats = { refused: 0, replaced: 0, forwarded: 0 };
  // The skip alert (unchecked.mjs): off unless --unchecked-window-ms is set.
  const tracker = o.uncheckedWindowMs > 0 ? createUncheckedTracker({ windowMs: o.uncheckedWindowMs, max: o.uncheckedMax, onUnchecked: uncheckedReporter(rt, { windowMs: o.uncheckedWindowMs }) }) : null;
  const track = tracker ? (calls) => { for (const c of calls) tracker.forwarded(c.id, c.name); } : () => {};
  const creds = o.credentials || null;
  const gate = creds ? createGate(creds, { requirePlaceholders: o.requirePlaceholders === true }) : null;
  const rawReported = new Set();
  // A raw credential where placeholders are configured: one content-free alert per route (the route prefix
  // only — never the header, its value or a hash of it).
  function reportRaw(prefix, refused) {
    const k = `${prefix}:${refused}`;
    if (rawReported.has(k)) return;
    rawReported.add(k);
    rt.ready().then((s) => rt.reporter.post({
      threatId: 0, category: refused ? "Model proxy: raw credential refused (placeholders required)" : "Model proxy: raw credential sent where placeholders are configured",
      riskLevel: refused ? "Blocked" : "Medium", stage: "prompt", tool: `model-proxy:credential:${prefix.replace(/^\//, "").replace(/[^A-Za-z0-9_.\-]/g, "_").slice(0, 48)}`,
      decision: refused ? "deny" : "notify", ...(refused ? {} : { reasonCode: REASON.OBSERVATION_ONLY }), contentHash: rt.hash(`credential-raw:${k}`)
    }, { prov: { policyId: s.policyId, policySource: s.source, event: "ModelRequest" } })).catch(() => {});
  }

  function reserve(n, api) {
    if (inflight + n > o.maxInflight) throw new HttpError(busy(api), "the proxy is at its in-flight memory budget; retry");
    inflight += n;
  }
  function send(res, status, payload, extra = {}) {
    if (res.headersSent) { res.destroy(); return; }
    const body = JSON.stringify(payload);
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff", "content-length": Buffer.byteLength(body), ...extra });
    res.end(body);
  }
  // Decoy AI keys (decoy.mjs): refused in either mode, before anything is forwarded. opts.decoys: test seam.
  const decoy = createDecoyCheck(o.decoys || {});
  const refuseDecoy = (res, api, id, part) => { stats.refused++; decoyAlert(rt, id, part); send(res, 403, errorPayload(api, 403, DECOY_REFUSAL), { "x-moorai-model-proxy": "refused", ...NO_RETRY }); };
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

  function upstreamHeaders(req, length, swaps, trace) {
    const h = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k)) h[k] = v;
    // After the hop-by-hop strip, so a swapped value is never dropped; the keys are lower-case, as Node's.
    if (swaps) for (const [k, v] of swaps) h[k] = v;
    applyTraceHeaders(h, trace);
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
  async function onResponse(ur, res, api, held, later, fm) {
    const ct = String(ur.headers["content-type"] || "");
    const enc = String(ur.headers["content-encoding"] || "identity").toLowerCase();
    const ok = ur.statusCode >= 200 && ur.statusCode < 300;
    const sse = /^text\/event-stream\b/i.test(ct);
    // Ollama streams NDJSON (application/x-ndjson): framed by lines instead of SSE events.
    const lines = Boolean(api && api.NDJSON) && /^application\/x-ndjson\b/i.test(ct);
    if (!api || !ok) { res.writeHead(ur.statusCode, responseHeaders(ur)); ur.pipe(res); return; }
    if (enc !== "identity") {
      // Unscannable. Report-only forwards it (and says so once); enforce does not forward what it cannot read.
      unevaluated("response-encoding", "response");
      if (enforce) { ur.resume(); return send(res, 502, api.errorBody(502, "MoorAI model-proxy: the provider answered with a compressed body it cannot inspect")); }
      res.writeHead(ur.statusCode, responseHeaders(ur)); ur.pipe(res); return;
    }
    const ALLOW = { decision: "allow", denied: [] };
    // A call is recorded for the skip alert once it is on its way to the agent: in enforce mode when it is
    // allowed (it is released right after), in report mode as soon as it is parsed (it is already sent).
    const nums = largeNumbers();
    // An engine error or the evaluation budget run out: refused (closed: the caller answers it), or, under an
    // open fail mode, reported unevaluated and released.
    const unjudged = (e) => { if (fm !== "open") throw e; unevaluated("evaluation", "response", "error"); return ALLOW; };
    const decide = enforce
      ? (calls) => (calls.length ? withTimeout(checker.checkToolCalls(nums.attach(calls))).catch(unjudged).then((v) => { if (v.decision === "allow") track(calls); return v; }) : Promise.resolve(ALLOW))
      : (calls) => { if (calls.length) { track(calls); const cs = nums.attach(calls); later.push(() => checker.checkToolCalls(cs)); } return Promise.resolve(ALLOW); };
    // The model's own text where an API has no structured tool calls (Ollama /api/generate): report-only,
    // after the response has ended, in every mode.
    const observe = (items) => { if (items.length) later.push(() => checker.observe(items)); };
    if (sse || lines) return enforce ? streamEnforce(ur, res, api, decide, lines, observe, nums) : streamObserve(ur, res, api, decide, lines, observe, nums);
    if (!enforce) {
      // Report-only: bytes go to the client as they arrive; a bounded copy is parsed after the end.
      res.writeHead(ur.statusCode, responseHeaders(ur));
      const chunks = []; let n = 0, over = false;
      ur.on("data", (c) => { if (over) return; n += c.length; if (n > o.maxResponse) { over = true; chunks.length = 0; return; } chunks.push(c); });
      ur.on("end", () => {
        if (over) return;
        const all = Buffer.concat(chunks);
        const body = parseJson(all);
        if (body) {
          const sc = strictBytes(all), bad = sc.problem;
          nums.note(sc);
          if (bad) unevaluated(`response-${bad}`, "response", "input");
          decide(api.responseToolCalls(body)); if (api.responseItems) observe(api.responseItems(body));
        }
        else unevaluated("response-unparsed", "response");
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
    // A 2xx body on a parsed path that is neither an event stream nor a JSON object (a local server that
    // labels its stream application/json, say) cannot be checked for tool calls: enforce does not forward it.
    if (!body) { unevaluated("response-unparsed", "response"); return send(res, 502, api.errorBody(502, "MoorAI model-proxy: the response is not a JSON object or an event stream; it cannot be checked"), NO_RETRY); }
    // A repeated key is read as its last value here and may be read as its first by the client (a repeated
    // `message` or `choices` could hide a tool call from this check); a `Choices` beside `choices` is the same
    // field to Go's encoding/json. Any body that is not strict JSON is not forwarded (json-strict.mjs).
    const sc = strictBytes(buf), bad = sc.problem;
    nums.note(sc);
    if (bad) { unevaluated(`response-${bad}`, "response", "input"); return send(res, 502, api.errorBody(502, strictMessage(bad)), NO_RETRY); }
    const calls = api.responseToolCalls(body);
    if (api.responseItems) observe(api.responseItems(body));
    let v;
    try { v = await decide(calls); } catch { return send(res, busy(api), api.errorBody(busy(api), "MoorAI model-proxy: evaluation did not finish in time; retry")); }
    if (v.decision === "deny") {
      if (!replace) return refuse(res, api, v, "response");
      stats.replaced++;
      const out = Buffer.from(JSON.stringify(api.replaceResponse(body, v)));
      res.writeHead(ur.statusCode, { ...responseHeaders(ur, { dropLength: true }), "content-length": out.length, "x-moorai-model-proxy": "replaced" });
      return res.end(out);
    }
    res.writeHead(ur.statusCode, { ...responseHeaders(ur, { dropLength: true }), "content-length": buf.length });
    res.end(buf);
  }

  async function streamObserve(ur, res, api, decide, lines, observe, nums) {
    res.writeHead(ur.statusCode, responseHeaders(ur));
    const split = lines ? createLineSplitter(o.maxEvent) : createSplitter(o.maxEvent);
    const machine = api.createStream({ enforce: false, decide, maxHold: o.maxEvent, observe });
    let stopped = false;
    const feed = (evs) => { for (const ev of evs) { const sc = eventScan(ev); nums.note(sc); const bad = sc && sc.problem; if (bad) unevaluated(`response-${bad}`, "response", "input"); machine.onEvent(ev).catch(() => {}); } };
    ur.on("data", (c) => { if (stopped) return; feed(split.push(c)); if (split.overflow) { stopped = true; unevaluated("stream-event", "response"); } });
    ur.on("end", () => { if (stopped) return; feed(split.end()); machine.onEnd().catch(() => {}); });
    ur.pipe(res);
  }

  async function streamEnforce(ur, res, api, decide, lines, observe, nums) {
    res.writeHead(ur.statusCode, responseHeaders(ur, { dropLength: true }));
    const split = lines ? createLineSplitter(o.maxEvent) : createSplitter(o.maxEvent);
    const machine = replace ? api.createReplaceStream({ decide, maxHold: o.maxEvent, observe }) : api.createStream({ enforce: true, decide, maxHold: o.maxEvent, observe });
    const write = async (bufs) => { for (const b of bufs) if (!res.write(b)) await Promise.race([once(res, "drain"), once(res, "close")]); };
    const stop = async (status, message) => { stats.refused++; ur.destroy(); res.end(api.streamError(status, message)); };
    const step = async (r) => {
      if (r.refuse) { await stop(403, refusalMessage(r.refuse, "response")); return false; }
      if (r.replaced) stats.replaced++;
      await write(r.out);
      return true;
    };
    // An event that is not strict JSON (a repeated key, NaN, …) is refused wherever it is, as the
    // non-streaming body is: a lenient client could read a tool call this check never saw.
    const one = async (ev) => {
      const sc = eventScan(ev);
      nums.note(sc);
      const bad = sc && sc.problem;
      if (bad) { unevaluated(`response-${bad}`, "response", "input"); await stop(502, strictMessage(bad)); return false; }
      return step(await machine.onEvent(ev));
    };
    try {
      for await (const c of ur) {
        for (const ev of split.push(c)) if (!(await one(ev))) return;
        if (split.overflow) return stop(502, "MoorAI model-proxy: a stream event exceeded the inspection cap");
        if (res.destroyed) { ur.destroy(); return; }
      }
      for (const ev of split.end()) if (!(await one(ev))) return;
      if (!(await step(await machine.onEnd()))) return;
      res.end();
    } catch (e) {
      if (res.writableEnded) return;
      // Only the evaluation budget is "retry later"; the provider closing the stream mid-way is a 502-class
      // error (Anthropic api_error, OpenAI server_error), and a held tool call is never released.
      if (e && e.message === "evaluation timeout") stop(busy(api), "MoorAI model-proxy: evaluation did not finish in time");
      else stop(502, machine.holding ? UPSTREAM_CLOSED_IN_CALL : UPSTREAM_CLOSED);
    }
  }

  // moorai-serve telling the proxy which tool call ids a framework checked (checked-notify.mjs). Only with
  // the skip alert on; loopback Host, the proxy token and application/json (no cross-site form) as for any
  // request. Answers how many ids it took, never whether one was known.
  async function checkedIds(req, res) {
    if (req.method !== "POST") throw new HttpError(405, "use POST");
    if (!/^application\/json\b/i.test(String(req.headers["content-type"] || ""))) { req.resume(); throw new HttpError(415, "content-type must be application/json"); }
    const cap = CHECKED_BATCH * (MAX_ID + 8) + 64;
    if (Number(req.headers["content-length"]) > cap) { req.resume(); throw new HttpError(413, "body too large"); }
    const chunks = []; let n = 0;
    for await (const c of req) { n += c.length; if (n <= cap) chunks.push(c); }
    if (n > cap) throw new HttpError(413, "body too large");
    const body = parseJson(Buffer.concat(chunks));
    const ids = body && Array.isArray(body.toolCallIds) ? body.toolCallIds : null;
    if (!ids || ids.length > CHECKED_BATCH || !ids.every((x) => typeof x === "string" && x && x.length <= MAX_ID)) throw new HttpError(400, `toolCallIds must be an array of at most ${CHECKED_BATCH} non-empty strings of at most ${MAX_ID} characters`);
    for (const id of ids) tracker.checked(id);
    return send(res, 200, { accepted: ids.length });
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
    if (tracker && path === CHECKED_PATH) return checkedIds(req, res);
    const route = routes.find((r) => path === r.prefix || path.startsWith(`${r.prefix}/`));
    if (!route) throw new HttpError(404, "no model-proxy route at this path");
    const rest = path.slice(route.prefix.length) || "/";
    const api = apiFor(req.method, rest);
    const url = new URL(route.base + rest + query);
    const current = REQUEST.getStore();
    current.trace = tracer({ traceparent: req.headers.traceparent, tracestate: req.headers.tracestate, sessionKey: req.headers[SESSION_HEADER] });
    current.provider = providerOf(api, route.prefix);
    if (api === gemini) current.model = modelOf(api, rest, null);
    const dh = decoy.request(req.rawHeaders, query);
    if (dh) { req.resume(); return refuseDecoy(res, api, dh, "header"); }
    let swaps = null;
    if (gate) {
      const c = gate(req.rawHeaders, query, route.prefix || "/", url);
      if (c.error) {
        if (c.error.raw) reportRaw(route.prefix || "/", true);
        throw Object.assign(new HttpError(c.error.status, c.error.message), { api });
      }
      if (c.raw) reportRaw(route.prefix || "/", false);
      swaps = c.swaps;
    }
    const held = { n: 0 };
    const later = deferrer();
    res.on("close", () => { inflight -= held.n; held.n = 0; later.close(); });
    let body;
    try { body = await readBody(req, api, held); } catch (e) { e.api = api; throw e; }
    const db = decoy.body(body);
    if (db) return refuseDecoy(res, api, db, "body");

    const fm = failMode((await rt.ready()).policy);
    if (api) {
      const json = parseJson(body);
      if (api !== gemini) current.model = modelOf(api, rest, json);
      const items = json ? api.outboundItems(json) : [];
      if (enforce && items.length) {
        let v = null;
        try { v = await withTimeout(checker.checkRequest(items)); } catch {
          if (fm !== "open") return send(res, busy(api), api.errorBody(busy(api), "MoorAI model-proxy: evaluation did not finish in time; retry"));
          unevaluated("evaluation", "request", "error");
        }
        if (v && v.decision === "deny") return refuse(res, api, v, "request");
      } else if (items.length) {
        // Report mode under a closed fail mode: what cannot be judged is refused before it is forwarded.
        if (fm === "closed") { const denied = await checker.unjudged(items); if (denied.length) return refuse(res, api, { decision: "deny", denied }, "request"); }
        later.push(() => checker.checkRequest(items));
      }
    }

    const lib = url.protocol === "https:" ? https : http;
    if (api) trail.record(await rt.ready(), current, req.headers[SESSION_HEADER] ? "claude-code" : rt.identity.agentName);
    stats.forwarded++;
    await new Promise((resolve) => {
      const up = lib.request(url, { method: req.method, headers: upstreamHeaders(req, body.length, swaps, current.trace), agent: agents[url.protocol] }, (raw) => {
        const ur = creds ? maskResponse(raw, creds.secrets) : raw;
        if (ur.refuse) { send(res, 502, errorPayload(api, 502, "MoorAI model-proxy: the upstream answered with a content coding the proxy cannot check for an echoed credential"), NO_RETRY); return resolve(); }
        onResponse(ur, res, api, held, later, fm).catch(() => { if (!res.headersSent) send(res, 502, errorPayload(api, 502, "MoorAI model-proxy: upstream response failed")); else res.destroy(); }).finally(resolve);
      });
      up.setTimeout(o.upstreamTimeoutMs, () => up.destroy(new Error("upstream timeout")));
      // Connect budget: a fresh socket must be ready to carry the request (TCP connected; for https, the TLS
      // handshake done) within connectTimeoutMs. A reused keep-alive socket is already ready. Cleared once
      // ready, so a slow first byte or a long stream is governed by the idle timeout above, as before.
      let connectTimedOut = false;
      up.on("socket", (sock) => {
        const tls = url.protocol === "https:";
        if (readySockets.has(sock) || (!tls && !sock.connecting)) return;
        const t = setTimeout(() => { connectTimedOut = true; up.destroy(new Error("connect timeout")); }, o.connectTimeoutMs);
        sock.once(tls ? "secureConnect" : "connect", () => { clearTimeout(t); readySockets.add(sock); });
        sock.once("close", () => clearTimeout(t));
      });
      // The URL is never put in an error: its query string can carry a credential.
      up.on("error", () => {
        if (res.headersSent) res.destroy();
        else if (connectTimedOut) send(res, 504, errorPayload(api, 504, `MoorAI model-proxy: the upstream provider did not accept a connection within ${o.connectTimeoutMs} ms`));
        else send(res, 502, errorPayload(api, 502, "MoorAI model-proxy: the upstream provider could not be reached"));
        resolve();
      });
      res.on("close", () => { if (!res.writableFinished) up.destroy(); });
      up.end(body);
    });
  }

  const log = (req, status, t0) => { if (o.log) process.stderr.write(`${new Date().toISOString()} ${req.method} ${req.url.split("?")[0]} ${status} ${(performance.now() - t0).toFixed(1)}ms\n`); };
  const server = http.createServer(async (req, res) => {
    const t0 = performance.now();
    res.on("finish", () => log(req, res.statusCode, t0));
    try { await REQUEST.run({}, () => handle(req, res)); } catch (e) {
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
  const close = async () => { await new Promise((r) => server.close(() => r())); server.closeAllConnections?.(); for (const a of Object.values(agents)) a.destroy(); if (tracker) tracker.stop(); await trail.close(); await rt.flush(); };
  return { server, url, runtime: rt, close, stats: () => ({ ...stats, inflight, cache: checker.cacheSize(), ...(tracker ? { unchecked: tracker.stats() } : {}) }) };
}
