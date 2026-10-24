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
// Only POST …/messages (Anthropic), POST …/chat/completions, …/responses and …/embeddings (OpenAI;
// openai-responses.mjs, openai-embeddings.mjs), POST …/models/{model}:generateContent
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
import { timingSafeEqual, createHash, createHmac, randomBytes } from "node:crypto";
import { createMoorAI, resolveSettings } from "../packages/agent-sdk/src/runtime.mjs";
import { createTracer, applyTraceHeaders, cleanModel } from "./trace-w3c.mjs";
import { createTrail } from "./trail.mjs";
import { REASON } from "../cli/provenance.mjs";
import { isLoopback } from "../cli/moorai-serve.mjs";
import * as anthropic from "./anthropic.mjs";
import * as openai from "./openai.mjs";
import * as openaiResponses from "./openai-responses.mjs";
import * as openaiEmbeddings from "./openai-embeddings.mjs";
import * as gemini from "./gemini.mjs";
import * as ollama from "./ollama.mjs";
import { createSplitter } from "./sse.mjs";
import { createLineSplitter } from "./ndjson.mjs";
import { strictBytes, strictScan, PROBLEM_TEXT } from "./json-strict.mjs";
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
import { createUsageMeter, FLUSH_MS as USAGE_FLUSH_MS } from "./token-usage.mjs";
import { budgetBlock, budgetErrorBody, budgetAlert } from "./budget.mjs";
import { createIntent, loadIntentKey } from "./intent.mjs";
import { responseScanMode, responseDetectors, createEcho, createScanner } from "./response-scan.mjs";
import { createTextGuard, guardBody } from "./text-guard.mjs";
import { parseLossless } from "./json-lossless.mjs";
import { textAlert, textRefusal } from "./text-report.mjs";
import * as codecs from "./text-codecs.mjs";
import { fileParts, batchFileParts } from "./file-parts.mjs";
import { fileScanPolicy } from "../cli/file-scan-policy.mjs";
import { loadFileScanKeys } from "../cli/file-scan-keys.mjs";
import { createFileScanner, fileScanDecision, fileScanAlert, mimeClass, PROVIDER_LABEL } from "../cli/file-scan.mjs";
import { headlessAskMode } from "../cli/server-mode.mjs";

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
// X-MoorAI-Session-Id names the session for intent alignment (intent.mjs); it is addressed to this proxy and
// is not sent upstream.
export const HOP = new Set(["connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding", TOKEN_HEADER, "x-moorai-session-id"]);
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
const apiFor = (method, path) => (method !== "POST" ? null : /\/messages$/.test(path) ? anthropic : /\/chat\/completions$/.test(path) ? openai : /\/responses$/.test(path) ? openaiResponses : /\/embeddings$/.test(path) ? openaiEmbeddings : gemini.isPath(path) ? gemini : ollama.isPath(path) ? ollama : null);
// The retryable status of the proxy's own budget errors: OpenAI, Gemini and Ollama 503, Anthropic 529 (overloaded).
// Endpoints that carry files outside the parsed APIs, with policy fileScan on: Anthropic Message Batches and Gemini
// cachedContents are read and scanned like their model requests; the Files / uploads APIs (Anthropic and OpenAI
// /files, OpenAI /uploads and their parts, Gemini's /upload/… media uploads) and Gemini batch generation are not
// read, so they are refused in enforce mode or under a closed fail mode and alerted otherwise.
// With fileScan on, the path is normalised before it is matched and forwarded (normalPath): percent-encoded
// unreserved characters decoded, dot segments resolved, duplicate slashes collapsed, a trailing slash removed. It is
// matched (matchPath) with %2F / %5C also read as "/", case-insensitively (the endpoint patterns carry the i flag,
// and the parsed-API choice is tried as sent and in lower case), since a provider may route either way; the
// normalised, case-kept path is what goes upstream.
const UNRESERVED_PCT = /%(?:4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|3[0-9]|2[DdEe]|5[Ff]|7[Ee])/g;
export function normalPath(p) {
  const decoded = String(p).replace(UNRESERVED_PCT, (m) => String.fromCharCode(parseInt(m.slice(1), 16)));
  const out = [];
  for (const seg of decoded.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") { out.pop(); continue; }
    out.push(seg);
  }
  return `/${out.join("/")}`;
}
export const matchPath = (p) => normalPath(String(p).replace(/%2f|%5c/gi, "/").replace(/\\/g, "/"));
const UPLOAD_PATHS = [/^(?:\/v1(?:beta)?)?\/files$/i, /^(?:\/v1)?\/uploads(?:\/[^/]+\/parts)?$/i, /^\/upload\//i, /:batchGenerateContent$/i];
function fileEndpoint(method, path) {
  if (method === "POST" && /\/messages\/batches$/i.test(path)) return { kind: "anthropic-batch", api: anthropic };
  if (method === "POST" && /\/messages\/count_tokens$/i.test(path)) return { kind: "anthropic", api: anthropic };
  if (method === "POST" && /\/cachedContents$/i.test(path)) return { kind: "gemini", api: gemini };
  if ((method === "POST" || method === "PUT" || method === "PATCH") && UPLOAD_PATHS.some((re) => re.test(path))) return { kind: "upload", api: null };
  return null;
}
const busy = (api) => (api && api !== anthropic ? 503 : 529);
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
// Each parsed API's name for intent alignment (user-turns.mjs) and its reply-text codec (text-codecs.mjs).
// Embeddings have neither: no tool call and no reply text.
const KIND = new Map([[anthropic, "anthropic"], [openai, "openai-chat"], [openaiResponses, "openai-responses"], [gemini, "gemini"], [ollama, "ollama"]]);
const CODEC = new Map([[anthropic, codecs.anthropic], [openai, codecs.openaiChat], [openaiResponses, codecs.openaiResponses], [gemini, codecs.gemini], [ollama, codecs.ollama]]);
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
  // An unsettled ask has no approver behind this proxy: in enforce mode it would be forwarded as if allowed.
  if (enforce && o.headlessAsk === "pass-through") throw new Error("model-proxy: headlessAsk pass-through is not accepted in --mode enforce (use deny or allow-with-report)");
  // --denied-tool-call replace: a denied tool call is withheld and its turn delivered as text explaining
  // why (anthropic-replace.mjs, openai-replace.mjs) instead of the whole response being refused.
  const replace = enforce && o.deniedToolCall === "replace";
  // Report-only passes an "ask" through unsettled (nothing is enforced, so nothing is settled); enforce
  // applies server mode's headless rule: an ask with no approver is a deny unless a trusted source says
  // allow-with-report. intentStore false: the runtime's own intent step is off, since this proxy judges intent
  // with its own sessions (intent.mjs) and runtime.toolCall carries none (every risky call would be task-unknown).
  const rt = await createMoorAI({ policyFile: o.policyFile, policy: o.policy, serviceId: o.serviceId, headlessAsk: enforce ? o.headlessAsk : "pass-through", console: o.console, fetch: o.fetch, env: o.env, systemConfig: o.systemConfig, surface: "model-proxy", intentStore: false });
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
  // Token usage (token-usage.mjs): each parsed response's provider usage, cumulative hourly buckets, POST /api/token-usage.
  const usage = createUsageMeter({ config: consoleConfig, identity: rt.identity, enrolled: rt.config.enrolled, fetch: o.fetch, flushMs: o.usageFlushMs ?? USAGE_FLUSH_MS });
  // Usage budgets (budget.mjs): one alert per budget and period from this process.
  const budgetSeen = new Set();
  const reportBudget = (s, hit) => { const k = `${hit.budgetId}|${hit.periodStart}`; if (budgetSeen.has(k) || budgetSeen.size > 256) return; budgetSeen.add(k); try { rt.reporter.post(budgetAlert(hit, enforce, rt.hash), { prov: { policyId: s.policyId, policySource: s.source, event: "ModelRequest" } }); } catch { /* report-only */ } };
  // Intent alignment (intent.mjs): the store is data/intent-server.mjs unless a test injects one (opts.intentLib);
  // the key is opts.intentKey (tests), --intent-key-file, or random per process.
  const intentLib = o.intentLib || await import("../data/intent-server.mjs");
  const intent = createIntent({ lib: intentLib, key: loadIntentKey({ key: o.intentKey, keyFile: o.intentKeyFile }).key, rt, enforce, now: o.intentNow });
  // Response text scanning (response-scan.mjs): the system-prompt shingle key, random per process.
  const echoKey = randomBytes(32);
  // A payment card (#1) or personal data (#15) in the reply is a value from a small space (a card is 10^16
  // candidates less the Luhn check, a phone number 10^10): its contentHash is not the tenant-keyed hash, which
  // anyone holding the install token could enumerate back to the value, but an HMAC under a key random to this
  // process ("proc:" and 16 hex). The same value seen twice by this process hashes alike; nothing outside it —
  // the console, another proxy, a restart — can link or reverse it. A secret (#39, high entropy) and a
  // system-prompt echo (#52, a keyed shingle) keep the tenant-keyed hash, so the console can correlate them.
  const piiKey = randomBytes(32);
  const LOW_ENTROPY = new Set([1, 15]);
  const findingHash = (id, match) => (LOW_ENTROPY.has(id) ? `proc:${createHmac("sha256", piiKey).update(String(match), "utf8").digest("hex").slice(0, 16)}` : rt.hash(match));
  // Cloud file scanning (cli/file-scan.mjs, policy fileScan): every inline file, document or image part of a
  // request (file-parts.mjs) looked up — or, in "upload" mode, uploaded — at the policy's provider before the
  // request goes upstream. The keys come only from the root-owned admin binding, a root-owned key file
  // (--file-scan-key-file) or this process's environment (cli/file-scan-keys.mjs); opts.fileScanKeys is an
  // embedder's own (tests). opts.fileScanEndpoints / fileScanFetch / fileScanPollMs: test seams.
  const fileScanner = createFileScanner({
    keys: { ...loadFileScanKeys({ admin, keyFiles: o.fileScanKeyFiles || {}, env: o.env || process.env }).keys, ...(o.fileScanKeys || {}) },
    endpoints: o.fileScanEndpoints || {}, fetch: o.fileScanFetch || globalThis.fetch, pollMs: o.fileScanPollMs ?? 1000
  });
  const fileAlerted = new Set();
  // Scans one request's files. Returns the refusal text when the request must not go upstream — enforce: any
  // file whose decision is deny; report: only a fail-closed one (what cannot be judged, as for text) — else
  // null. One content-free alert per file, verdict and decision per process (a conversation re-sends its files).
  async function scanFiles(found, cfg, s, fm) {
    const headless = headlessAskMode({ active: true, headless: rt.settings.headless || {} }, s.policy).mode;
    const jobs = found.parts.map((p) => fileScanner.scan(p.bytes, cfg).then((r) => ({ p, r })));
    const results = await Promise.all(jobs);
    // Data that fails strict base64 (file-parts.mjs): not scanned, never clean. Its alert's keyed hash is of the
    // raw text (no bytes exist that the provider would agree on).
    // A file sent by reference (a URL or a provider file id): its content is not in the request; unknown, so an
    // alert and onUnknown. The keyed hash is of the reference; the reference itself never leaves.
    for (const x of found.refs || []) results.push({ p: { mediaType: "", bytes: { length: 0 } }, r: { verdict: "unknown", why: "reference", provider: cfg.provider, sha256: `ref:${createHash("sha256").update(x.ref).digest("hex")}`, uploaded: false } });
    for (const u of found.unscannable) results.push({ p: { mediaType: u.mediaType, bytes: { length: u.raw.length } }, r: { verdict: "error", why: "unscannable", provider: cfg.provider, sha256: `raw:${createHash("sha256").update(u.raw).digest("hex")}`, uploaded: false } });
    if (found.over) results.push({ p: { mediaType: "", bytes: { length: 0 } }, r: { verdict: "error", why: "budget", provider: cfg.provider, sha256: `over-cap:${found.over}`, uploaded: false } });
    let refusal = null;
    for (const { p, r } of results) {
      const d = fileScanDecision(r, cfg, { failMode: fm, headless });
      if (d.alert) {
        const k = `${r.sha256}|${r.verdict}|${d.decision}|${d.failClosed}`;
        if (!fileAlerted.has(k)) {
          if (fileAlerted.size >= 4096) fileAlerted.clear();
          fileAlerted.add(k);
          try { rt.reporter.post(fileScanAlert({ result: r, cfg, decision: d, hash: rt.hash, tool: "model-proxy:file-scan", mime: p.mediaType, size: p.bytes.length }), { prov: { policyId: s.policyId, policySource: s.source, event: "ModelRequest" } }); } catch { /* report-only */ }
        }
      }
      if (refusal || d.action !== "deny" || !(enforce || d.failClosed)) continue;
      const label = PROVIDER_LABEL[r.provider] || r.provider;
      const what = r.verdict === "malicious" ? `malicious file (${label}: ${r.detections ?? 0} of ${r.engines ?? 0} engines${r.threat ? `, ${r.threat}` : ""})`
        : d.failClosed ? `not scanned (${r.why}), and your organization blocks what MoorAI cannot evaluate`
        : `${r.why === "reference" ? "sent by reference (a URL or a file id the scan cannot read)" : r.verdict === "unknown" ? `unknown to ${label}` : `not scanned (${r.why})`}; ${d.headlessAsk ? "it needs an approval and this server has no approver" : "your organization blocks files the scan cannot vouch for"}`;
      refusal = `MoorAI model-proxy refused this request — file (${mimeClass(p.mediaType)}): ${what}`;
    }
    return refusal;
  }
  const refuseFile = (res, errApi, message) => { stats.refused++; send(res, 403, errorPayload(errApi, 403, `MoorAI model-proxy refused this request — ${message}`), { "x-moorai-model-proxy": "refused" }); return true; };
  // The cloud file scan of one request body (policy fileScan on). kind: a file-parts.mjs API kind, or
  // "anthropic-batch". ref.body is replaced by the body to forward. Returns true when the request was refused.
  //   * A body that carries a content coding, or is not a JSON object, cannot be read for files: refused in enforce
  //     mode or under a closed fail mode, otherwise forwarded with an UNEVALUATED_BAD_INPUT alert.
  //   * Read from the lossless parse (json-lossless.mjs), and the body forwarded is always that object re-serialised,
  //     file or not, so the upstream receives exactly what was scanned. A body that repeats a key, or has keys that
  //     differ only in case (Go's encoding/json, Ollama's, folds them), is a parser differential: refused in enforce
  //     mode or under a closed fail mode, otherwise forwarded re-serialised with an UNEVALUATED_BAD_INPUT alert.
  //   * Two spellings of one field with different content (file-parts.mjs): the same rule.
  //   * The files: before the upstream when enforcing or under a closed fail mode, else after the response.
  async function fileScanRequest(kind, errApi, req, res, ref, s, fm, later, cfg) {
    const coding = String(req.headers["content-encoding"] || "").trim().toLowerCase();
    const exact = !coding || coding === "identity" ? parseLossless(ref.body) : null;
    if (!exact || typeof exact !== "object" || Array.isArray(exact)) {
      unevaluated("file-scan-body", "request", "input");
      return (enforce || fm === "closed") && refuseFile(res, errApi, "the request body could not be read for files (it carries a content coding or is not a JSON object), so it cannot be checked");
    }
    const sc = strictScan(ref.body.toString("utf8"));
    const dupe = ["duplicate-key", "key-collision"].find((p) => sc.problems.has(p));
    if (dupe) {
      unevaluated(`file-scan-${dupe}`, "request", "input");
      if (enforce || fm === "closed") return refuseFile(res, errApi, `the request body ${PROBLEM_TEXT[dupe]} (duplicate keys are a parser differential), so the provider could read a file the scan never saw`);
    }
    ref.body = Buffer.from(JSON.stringify(exact));
    const found = kind === "anthropic-batch" ? batchFileParts(exact) : fileParts(kind, exact);
    if (found.ambiguous.length) {
      unevaluated(`file-${found.ambiguous[0]}`, "request", "input");
      if (enforce || fm === "closed") return refuseFile(res, errApi, `a file part is ambiguous (${found.ambiguous[0].replace(/[^A-Za-z0-9:_]/g, "_")} spelled two ways with different content), so the provider could read a different file than the one checked`);
    }
    if (!(found.parts.length || found.over || found.unscannable.length || found.refs.length)) return false;
    if (!(enforce || fm === "closed")) { later.push(() => scanFiles(found, cfg, s, fm)); return false; }
    const why = await scanFiles(found, cfg, s, fm);
    if (!why) return false;
    stats.refused++;
    send(res, 403, errorPayload(errApi, 403, why), { "x-moorai-model-proxy": "refused" });
    return true;
  }
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
  // The reply-text scan for one response (response-scan.mjs): mode report unless --mode enforce and the policy
  // says mask / block. Findings are posted as they are made, deduplicated per response (class + keyed hash),
  // at most 32; in block mode the first one sets `blocked`.
  function textScan(api, rctx, current) {
    const codec = CODEC.get(api);
    if (!codec || !rctx) return null;
    const mode = enforce ? rctx.mode : "report";
    const seen = new Set();
    const t = { codec, mode, hold: mode !== "report", blocked: null, scanner: null };
    t.scanner = createScanner({ dets: rctx.dets, policy: rctx.policy, echo: rctx.echo, hold: t.hold, onFind: ({ id, match, sent }) => {
      const h = findingHash(id, match);
      const k = `${id}:${h}`;
      if (seen.has(k) || seen.size >= 32) return;
      seen.add(k);
      if (mode === "block" && !t.blocked) t.blocked = id;
      REQUEST.run(current, () => { try { rt.reporter.post(textAlert({ id, hash: h, sent, mode, configured: rctx.mode, enforce, riskLevel: rctx.risk(id) }), { prov: { policyId: rctx.policyId, policySource: rctx.source, event: "PostToolUse" } }); } catch { /* report-only */ } });
    } });
    return t;
  }

  async function onResponse(ur, res, api, held, later, fm, meter, ictx, rctx) {
    const ct = String(ur.headers["content-type"] || "");
    const enc = String(ur.headers["content-encoding"] || "identity").toLowerCase();
    const ok = ur.statusCode >= 200 && ur.statusCode < 300;
    const sse = /^text\/event-stream\b/i.test(ct);
    // Ollama streams NDJSON (application/x-ndjson): framed by lines instead of SSE events.
    const lines = Boolean(api && api.NDJSON) && /^application\/x-ndjson\b/i.test(ct);
    // The provider accepted the request: its user turns become the task (intent.mjs), before any tool call in
    // this response is judged. A rejected request adds nothing.
    if (ok && ictx) intent.commit(ictx);
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
    // Intent alignment for each call (intent.mjs), when this request has a session to judge against.
    const copts = ictx ? { intent: (tool, input, findings, name, verdict) => intent.judge(ictx, tool, input, findings, name, verdict) } : {};
    const decide = enforce
      ? (calls) => (calls.length ? withTimeout(checker.checkToolCalls(nums.attach(calls), copts)).catch(unjudged).then((v) => { if (v.decision === "allow") track(calls); return v; }) : Promise.resolve(ALLOW))
      : (calls) => { if (calls.length) { track(calls); const cs = nums.attach(calls); later.push(() => checker.checkToolCalls(cs, copts)); } return Promise.resolve(ALLOW); };
    const text = textScan(api, rctx, REQUEST.getStore());
    // The model's own text where an API has no structured tool calls (Ollama /api/generate): report-only,
    // after the response has ended, in every mode.
    const observe = (items) => { if (items.length) later.push(() => checker.observe(items)); };
    if (sse || lines) return enforce ? streamEnforce(ur, res, api, decide, lines, observe, nums, meter, text, fm) : streamObserve(ur, res, api, decide, lines, observe, nums, meter, text);
    if (!enforce) {
      // Report-only: bytes go to the client as they arrive; a bounded copy is parsed after the end.
      res.writeHead(ur.statusCode, responseHeaders(ur));
      const chunks = []; let n = 0, over = false;
      ur.on("data", (c) => { if (over) return; n += c.length; if (n > o.maxResponse) { over = true; chunks.length = 0; return; } chunks.push(c); });
      ur.on("end", () => {
        if (over) return;
        const all = Buffer.concat(chunks);
        const body = parseJson(all);
        if (body && meter) meter.body(body);
        if (body) {
          const sc = strictBytes(all), bad = sc.problem;
          nums.note(sc);
          if (bad) unevaluated(`response-${bad}`, "response", "input");
          decide(api.responseToolCalls(body)); if (api.responseItems) observe(api.responseItems(body));
          if (text) later.push(() => { guardBody(text.codec, text.scanner, body, false); });
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
    if (body && meter) meter.body(body);
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
    if (v.decision === "deny" && !replace) return refuse(res, api, v, "response");
    // A body the reply-text scan may rewrite is re-parsed keeping each number's source text (json-lossless.mjs),
    // so re-serializing it never rounds an integer past 2^53 in a function call's arguments beside the text.
    const sent = v.decision === "deny" ? api.replaceResponse(body, v) : text && text.hold ? (parseLossless(buf) || body) : body;
    if (v.decision === "deny") stats.replaced++;
    // The reply text (response-scan.mjs): report mode after the response; mask / block before it is sent.
    let masked = false;
    if (text && !text.hold) later.push(() => { guardBody(text.codec, text.scanner, sent, false); });
    else if (text) {
      try { masked = guardBody(text.codec, text.scanner, sent, true); } catch {
        unevaluated("response-text", "response", "error");
        if (fm !== "open") return send(res, 502, api.errorBody(502, "MoorAI model-proxy: the reply text could not be scanned; it was not forwarded"), NO_RETRY);
      }
      if (text.blocked) { stats.refused++; return send(res, 403, api.errorBody(403, textRefusal(text.blocked)), { "x-moorai-model-proxy": "refused" }); }
    }
    if (v.decision === "deny" || masked) {
      const out = Buffer.from(JSON.stringify(sent));
      res.writeHead(ur.statusCode, { ...responseHeaders(ur, { dropLength: true }), "content-length": out.length, "x-moorai-model-proxy": v.decision === "deny" ? "replaced" : "masked" });
      return res.end(out);
    }
    res.writeHead(ur.statusCode, { ...responseHeaders(ur, { dropLength: true }), "content-length": buf.length });
    res.end(buf);
  }

  async function streamObserve(ur, res, api, decide, lines, observe, nums, meter, text) {
    res.writeHead(ur.statusCode, responseHeaders(ur));
    const split = lines ? createLineSplitter(o.maxEvent) : createSplitter(o.maxEvent);
    const machine = api.createStream({ enforce: false, decide, maxHold: o.maxEvent, observe });
    // The reply text, report-only: a copy of each event's text goes through the rolling window; nothing is held.
    const guard = text ? createTextGuard({ codec: text.codec, scanner: text.scanner, lines, hold: false }) : null;
    const tap = (f) => { if (!guard) return; try { f(); } catch { unevaluated("response-text", "response", "error"); } };
    let stopped = false;
    const feed = (evs) => { for (const ev of evs) { if (meter) meter.event(ev); const sc = eventScan(ev); nums.note(sc); const bad = sc && sc.problem; if (bad) unevaluated(`response-${bad}`, "response", "input"); machine.onEvent(ev).catch(() => {}); tap(() => guard.event(ev.raw)); } };
    ur.on("data", (c) => { if (stopped) return; feed(split.push(c)); if (split.overflow) { stopped = true; unevaluated("stream-event", "response"); } });
    ur.on("end", () => { if (stopped) return; feed(split.end()); machine.onEnd().catch(() => {}); tap(() => guard.end()); });
    ur.pipe(res);
  }

  async function streamEnforce(ur, res, api, decide, lines, observe, nums, meter, text, fm) {
    res.writeHead(ur.statusCode, responseHeaders(ur, { dropLength: true }));
    const split = lines ? createLineSplitter(o.maxEvent) : createSplitter(o.maxEvent);
    const machine = replace ? api.createReplaceStream({ decide, maxHold: o.maxEvent, observe }) : api.createStream({ enforce: true, decide, maxHold: o.maxEvent, observe });
    const write = async (bufs) => { for (const b of bufs) if (!res.write(b)) await Promise.race([once(res, "drain"), once(res, "close")]); };
    const stop = async (status, message) => { stats.refused++; ur.destroy(); res.end(api.streamError(status, message)); };
    // The reply text (text-guard.mjs) on what the tool-call machine releases: mask / block hold and rewrite it
    // before it is written; report reads it after the bytes are written. A scan error is reported unevaluated;
    // in mask / block mode under a closed fail mode it stops the stream.
    const guard = text ? createTextGuard({ codec: text.codec, scanner: text.scanner, lines, hold: text.hold }) : null;
    const guarded = async (f, bufs) => {
      if (!guard) return bufs;
      if (!text.hold) { await write(bufs); try { f(); } catch { unevaluated("response-text", "response", "error"); } return []; }
      let out;
      try { out = f(); } catch {
        unevaluated("response-text", "response", "error");
        if (fm !== "open") { await stop(502, "MoorAI model-proxy: the reply text could not be scanned; the stream was stopped"); return null; }
        out = bufs;
      }
      if (text.blocked) { await stop(403, textRefusal(text.blocked)); return null; }
      return out;
    };
    const step = async (r) => {
      if (r.refuse) { await stop(403, refusalMessage(r.refuse, "response")); return false; }
      if (r.replaced) stats.replaced++;
      const out = await guarded(() => r.out.flatMap((b) => guard.event(b)), r.out);
      if (!out) return false;
      await write(out);
      return true;
    };
    // An event that is not strict JSON (a repeated key, NaN, …) is refused wherever it is, as the
    // non-streaming body is: a lenient client could read a tool call this check never saw.
    const one = async (ev) => {
      if (meter) meter.event(ev);
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
      const tail = await guarded(() => guard.end(), []);
      if (!tail) return;
      await write(tail);
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
    const scanOn = fileScanPolicy((await rt.ready()).policy).mode !== "off";
    const rest = scanOn ? normalPath(path.slice(route.prefix.length) || "/") : path.slice(route.prefix.length) || "/";
    const api = scanOn ? apiFor(req.method, matchPath(rest)) || apiFor(req.method, matchPath(rest).toLowerCase()) : apiFor(req.method, rest);
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
    // A signed usage budget in state "exceeded" with action "block" (budget.mjs): refused in enforce mode, before
    // anything is judged or forwarded; reported in report mode.
    if (api) {
      const s0 = await rt.ready();
      const hit = budgetBlock(s0.policy, { source: s0.source });
      if (hit) { reportBudget(s0, hit); if (enforce) { stats.refused++; return send(res, 429, budgetErrorBody(hit.budgetId), { "x-moorai-model-proxy": "refused", ...NO_RETRY }); } }
    }
    let ictx = null, rctx = null;
    if (api) {
      const json = parseJson(body);
      if (api !== gemini) current.model = modelOf(api, rest, json);
      const items = json ? api.outboundItems(json) : [];
      const s1 = await rt.ready();
      // Intent alignment: this request's session and the person's turns in it (intent.mjs). A body that does not
      // parse is judged too: the header's session (or the trace's), else "none", with no turns captured.
      if (KIND.has(api)) ictx = intent.begin(KIND.get(api), json, req.headers, current.trace, s1.policy);
      // Reply-text scanning: the policy's mode, the engine's response detectors, this request's system prompt
      // as keyed shingles (response-scan.mjs).
      if (CODEC.has(api)) {
        const threats = s1.engine.threatsById;
        rctx = { mode: responseScanMode(s1.policy), policy: s1.policy, policyId: s1.policyId, source: s1.source, dets: responseDetectors(s1.engine),
          echo: createEcho(items.filter((it) => it.kind === "system").map((it) => it.text).join("\n"), echoKey),
          risk: (id) => (threats && threats.get(id) && threats.get(id).riskLevel) || "High" };
      }
      // Cloud file scan (policy fileScan): fileScanRequest above.
      const fsCfg = fileScanPolicy(s1.policy);
      if (fsCfg.mode !== "off" && KIND.has(api)) {
        const ref = { body };
        if (await fileScanRequest(KIND.get(api), api, req, res, ref, s1, fm, later, fsCfg)) return;
        body = ref.body;
      }
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

    // File-carrying endpoints the APIs above do not parse (fileEndpoint), with policy fileScan on.
    if (!api && scanOn) {
      const ep = fileEndpoint(req.method, matchPath(rest));
      const s2 = ep ? await rt.ready() : null;
      const fsCfg = s2 ? fileScanPolicy(s2.policy) : null;
      if (ep && fsCfg.mode !== "off") {
        if (ep.kind === "upload") {
          unevaluated("file-scan-endpoint", "request", "input");
          if (enforce || fm === "closed") return refuseFile(res, null, "a file uploaded through this endpoint is not scanned (policy fileScan), and your organization blocks what MoorAI cannot evaluate; send the file inline in a model request instead");
        } else {
          const ref = { body };
          if (await fileScanRequest(ep.kind, ep.api, req, res, ref, s2, fm, later, fsCfg)) return;
          body = ref.body;
        }
      } else if (!ep && body.length && (req.method === "POST" || req.method === "PUT" || req.method === "PATCH")) {
        // Any other path this proxy does not parse: a body that is not plain JSON (multipart, binary, a content coding,
        // unparseable) could carry a file nothing here reads. Refused in enforce mode or under a closed fail mode,
        // alerted otherwise. A JSON body there is forwarded unscanned (README "Cloud file scanning").
        const ct = String(req.headers["content-type"] || "").toLowerCase();
        const coding = String(req.headers["content-encoding"] || "").trim().toLowerCase();
        const v = /^application\/(?:[a-z0-9.!#$&^_-]+\+)?json\b/.test(ct) && (!coding || coding === "identity") ? parseLossless(body) : null;
        if (!v || typeof v !== "object") {
          unevaluated("file-scan-unparsed", "request", "input");
          if (enforce || fm === "closed") return refuseFile(res, null, "a request body this proxy does not parse (multipart, binary or not JSON) is not scanned for files (policy fileScan), and your organization blocks what MoorAI cannot evaluate");
        }
      }
    }

    const lib = url.protocol === "https:" ? https : http;
    if (api) trail.record(await rt.ready(), current, req.headers[SESSION_HEADER] ? "claude-code" : rt.identity.agentName);
    // This request's usage collector; counted once the response is over, however it ended.
    const meter = api ? usage.begin({ provider: current.provider, model: current.model, agentName: req.headers[SESSION_HEADER] ? "claude-code" : rt.identity.agentName }) : null;
    if (meter) res.on("close", () => meter.end());
    stats.forwarded++;
    await new Promise((resolve) => {
      const up = lib.request(url, { method: req.method, headers: upstreamHeaders(req, body.length, swaps, current.trace), agent: agents[url.protocol] }, (raw) => {
        const ur = creds ? maskResponse(raw, creds.secrets) : raw;
        if (ur.refuse) { send(res, 502, errorPayload(api, 502, "MoorAI model-proxy: the upstream answered with a content coding the proxy cannot check for an echoed credential"), NO_RETRY); return resolve(); }
        onResponse(ur, res, api, held, later, fm, meter, ictx, rctx).catch(() => { if (!res.headersSent) send(res, 502, errorPayload(api, 502, "MoorAI model-proxy: upstream response failed")); else res.destroy(); }).finally(resolve);
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
  const close = async () => { await new Promise((r) => server.close(() => r())); server.closeAllConnections?.(); for (const a of Object.values(agents)) a.destroy(); if (tracker) tracker.stop(); await trail.close(); await usage.close(); await rt.flush(); };
  return { server, url, runtime: rt, close, stats: () => ({ ...stats, inflight, cache: checker.cacheSize(), intentSessions: intent.size(), fileScan: fileScanner.stats(), ...(tracker ? { unchecked: tracker.stats() } : {}) }) };
}
