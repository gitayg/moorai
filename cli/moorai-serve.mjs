#!/usr/bin/env node
// moorai serve — the MoorAI engine as a localhost HTTP sidecar, for agent loops that are not Claude Code
// or the Claude Agent SDK (OpenAI Agents SDK, LangGraph, CrewAI, a custom loop): one long-lived process,
// one runtime, no process per call. Same decisions as the hook and @moorai/agent-sdk — it IS that
// package's runtime (packages/agent-sdk/src/runtime.mjs), with the same server-mode semantics: headless
// ask -> deny by default, workload identity, content-free reporting to the console when one is configured.
//
//   POST /v1/scan       { text, stage?, ctx?, session? } -> content-free verdict on one string
//   POST /v1/tool-call  { tool, input, cwd?, toolCallId?, session? } -> the decision the hook makes for that tool call;
//                                                     toolCallId (the model's tool call id) is passed on to
//                                                     moorai-model-proxy for its skip alert when
//                                                     --model-proxy-url is set, and otherwise ignored
//   POST /v1/index-scan { chunks, source?, session? } -> one content-free verdict per chunk about to be
//                                                     embedded (allow / flag / hold / deny), index stage;
//                                                     source: a string label, or { name?, trust?:
//                                                     "trusted" | "untrusted" | "unknown", kind? } (the
//                                                     author: cli/index-scan.mjs PROVENANCE)
//   POST /v1/task      { session, prompt }          -> { mode, captured, features }: the user's task for that
//                                                     session, for intent alignment (data/intent-server.mjs).
//                                                     Send each turn a PERSON wrote, never a tool result or
//                                                     other machine-injected text. Held in memory as keyed
//                                                     hashes of the sites, paths, service names and labels it
//                                                     mentions; the prompt is never stored or echoed.
//                                                     A later /v1/tool-call with the same `session` is judged
//                                                     when risky (upload, credential read, destructive
//                                                     command, MCP write) under policy.intentAlignment:
//                                                     "report" (default: one alert per target, verdict
//                                                     unchanged), "ask" (allow -> ask, then the headless
//                                                     rule), "block" (deny), "off". The verdict then carries
//                                                     `intent: { class, mode }`. No session, no judgement.
//                                                     A session that was held and is gone (evicted, expired)
//                                                     is judged as class "task-unknown" (fails closed).
//                                                     PRINCIPALS: each token in --token-file (one per line)
//                                                     is a principal; a session's task is namespaced by the
//                                                     token that set it, so only that principal's tool calls
//                                                     are judged against it and no other principal can set,
//                                                     replace or evict it. Each principal holds at most
//                                                     --intent-sessions-per-caller sessions (default 256);
//                                                     over that, its own oldest goes. WITHOUT A TOKEN every
//                                                     local process is one principal and can set any
//                                                     session's task.
//   session (optional, every POST but /v1/task, where it is required): the caller's own session /
//   conversation id. Only its keyed hash leaves, as the `session` field of each console alert the request
//   raises; omitted, no field.
//   GET  /healthz                                  -> { status, version, policyId }
//
// Responses never contain the submitted text: decision, threat ids, categories, the hook's reasons
// ("#55 Identity & Access"), static safer-alternative hints, content-free findings. Nothing is written
// to disk and request bodies are never logged.
//
// EXPOSURE. Default bind 127.0.0.1. A non-loopback bind (a Kubernetes pod IP, 0.0.0.0) is refused
// unless BOTH --allow-remote and a token are given. A loopback listener without a token still refuses a
// browser: a Host header that is not a loopback name (DNS rebinding) is rejected, and a body must be
// sent as application/json, which a cross-site form cannot do without a CORS preflight this server
// never answers.
//
//   moorai-serve [--host 127.0.0.1] [--port 8790] [--token-file <path>] [--allow-remote] [--intent-sessions-per-caller 256]
//                [--max-body 1048576] [--timeout-ms 10000] [--policy-file <path>] [--service-id <name>]
//                [--headless-ask deny|allow-with-report] [--log]
//                [--model-proxy-url http://127.0.0.1:8791] [--model-proxy-token-file <path>]
//   Token: --token-file (one token per line; each line is a principal), else MOORAI_SERVE_TOKEN (one). The model proxy's token: --model-proxy-token-file, else
//   MOORAI_MODEL_PROXY_TOKEN. Console binding: MOORAI_SERVER_URL / MOORAI_TENANT /
//   MOORAI_INSTALL_TOKEN or /etc/moorai/config.json, as server mode reads them.
import http from "node:http";
import { readFileSync, realpathSync } from "node:fs";
import { timingSafeEqual, createHash } from "node:crypto";
import { isIP } from "node:net";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { createMoorAI, STAGES } from "../packages/agent-sdk/src/runtime.mjs";
import { inboundLib, indexScanLib } from "../packages/agent-sdk/src/core.mjs";
import { createCheckedNotifier } from "../model-proxy/checked-notify.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFAULTS = Object.freeze({ host: "127.0.0.1", port: 8790, maxBody: 1048576, timeoutMs: 10000, intentSessionsPerCaller: 256 });
const CTX_KEYS = { template: "boolean", egress: "boolean", inbound: "boolean", targetPath: "string", tool: "string" };
const MAX_TEXT = 4 * 1048576;

export function isLoopback(host) {
  const h = String(host || "").replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost" || h === "::1") return true;
  return isIP(h) === 4 && h.startsWith("127.");
}
// The Host header a loopback listener accepts: a loopback name, with or without a port.
function hostHeaderOk(header) {
  const h = String(header || "");
  const name = h.startsWith("[") ? h.slice(0, h.indexOf("]") + 1) : h.split(":")[0];
  return isLoopback(name);
}

export function parseArgs(argv, env = process.env) {
  const o = { ...DEFAULTS, allowRemote: false, log: false, token: "", tokens: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i], v = () => { const x = argv[++i]; if (x === undefined) throw new Error(`${a} needs a value`); return x; };
    if (a === "--host") o.host = v();
    else if (a === "--port") o.port = Number(v());
    else if (a === "--token-file") o.tokens = readFileSync(v(), "utf8").split(/\r?\n/).map((t) => t.trim()).filter(Boolean);
    else if (a === "--allow-remote") o.allowRemote = true;
    else if (a === "--max-body") o.maxBody = Number(v());
    else if (a === "--timeout-ms") o.timeoutMs = Number(v());
    else if (a === "--policy-file") o.policyFile = resolve(v());
    else if (a === "--service-id") o.serviceId = v();
    else if (a === "--headless-ask") o.headlessAsk = v();
    else if (a === "--log") o.log = true;
    else if (a === "--model-proxy-url") o.modelProxyUrl = v();
    else if (a === "--model-proxy-token-file") o.modelProxyToken = readFileSync(v(), "utf8").trim();
    else if (a === "--intent-sessions-per-caller") o.intentSessionsPerCaller = Number(v());
    else throw new Error(`unknown argument ${a}`);
  }
  if (!o.tokens.length && env.MOORAI_SERVE_TOKEN) o.tokens = [String(env.MOORAI_SERVE_TOKEN).trim()].filter(Boolean);
  o.token = o.tokens[0] || "";
  if (o.modelProxyUrl) {
    let u;
    try { u = new URL(o.modelProxyUrl); } catch { throw new Error("--model-proxy-url is not a URL"); }
    if (u.username || u.password || u.search || (u.protocol !== "http:" && u.protocol !== "https:")) throw new Error("--model-proxy-url must be an http(s) URL with no credentials or query string");
    // The proxy's token travels with every batch: never in clear across a network.
    if (u.protocol === "http:" && !isLoopback(u.hostname)) throw new Error("--model-proxy-url: plain http to a non-loopback host is refused");
    if (!o.modelProxyToken && env.MOORAI_MODEL_PROXY_TOKEN) o.modelProxyToken = String(env.MOORAI_MODEL_PROXY_TOKEN).trim();
  }
  if (!Number.isInteger(o.port) || o.port < 0 || o.port > 65535) throw new Error("--port must be 0-65535");
  if (!Number.isInteger(o.maxBody) || o.maxBody < 1024) throw new Error("--max-body must be an integer >= 1024");
  if (!Number.isInteger(o.timeoutMs) || o.timeoutMs < 100) throw new Error("--timeout-ms must be an integer >= 100");
  if (!isLoopback(o.host)) {
    if (!o.allowRemote) throw new Error(`refusing to listen on ${o.host}: not a loopback address (pass --allow-remote and a token to expose it)`);
    if (!o.token) throw new Error(`refusing to listen on ${o.host} without a token (--token-file or MOORAI_SERVE_TOKEN)`);
  }
  if (o.tokens.some((t) => t.length < 16)) throw new Error("the token must be at least 16 characters");
  if (!Number.isInteger(o.intentSessionsPerCaller) || o.intentSessionsPerCaller < 1) throw new Error("--intent-sessions-per-caller must be an integer >= 1");
  return o;
}

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const digest = (s) => createHash("sha256").update(String(s)).digest();
// The principal a request authenticates as: "" with no token configured (every local process is the same
// caller), else the token it presented (kept in memory only, as the intent store's owner), else null.
function principal(req, tokens) {
  if (!tokens.length) return "";
  const m = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ""));
  if (!m) return null;
  const got = digest(m[1].trim());
  let hit = null;
  for (const t of tokens) if (timingSafeEqual(got, digest(t))) hit = t;
  return hit;
}
// An over-size body is answered 413 only after the client has finished sending it (discarded, never
// buffered), so the client reads the 413 instead of a connection reset mid-write. Past DRAIN_FACTOR x the
// cap the socket is dropped: a client that keeps streaming gets no more of the server's time.
const DRAIN_FACTOR = 8;
function readJson(req, maxBody) {
  return new Promise((res, rej) => {
    if (!/^application\/json\b/i.test(String(req.headers["content-type"] || ""))) { req.resume(); return rej(new HttpError(415, "content-type must be application/json")); }
    const tooBig = () => new HttpError(413, `body over ${maxBody} bytes`);
    const declared = Number(req.headers["content-length"]);
    if (declared > maxBody * DRAIN_FACTOR) { req.destroy(); return rej(tooBig()); }
    const chunks = []; let n = 0, over = declared > maxBody, done = false;
    req.on("data", (c) => {
      n += c.length;
      if (n > maxBody) { over = true; chunks.length = 0; }
      if (n > maxBody * DRAIN_FACTOR && !done) { done = true; req.destroy(); rej(tooBig()); return; }
      if (!over) chunks.push(c);
    });
    req.on("end", () => {
      if (done) return;
      done = true;
      if (over) return rej(tooBig());
      try { res(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch { rej(new HttpError(400, "body is not valid JSON")); }
    });
    req.on("error", () => { if (!done) { done = true; rej(new HttpError(400, "request aborted")); } });
  });
}
function cleanCtx(ctx) {
  if (ctx == null) return {};
  if (typeof ctx !== "object" || Array.isArray(ctx)) throw new HttpError(400, "ctx must be an object");
  const out = {};
  for (const [k, t] of Object.entries(CTX_KEYS)) if (typeof ctx[k] === t) out[k] = t === "string" ? ctx[k].slice(0, 1024) : ctx[k];
  return out;
}
function withTimeout(p, ms) {
  let t;
  return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new HttpError(503, `evaluation exceeded ${ms} ms`)), ms); })]).finally(() => clearTimeout(t));
}

export async function createServer(opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const tokens = Array.isArray(o.tokens) && o.tokens.length ? o.tokens : o.token ? [o.token] : [];
  const rt = await createMoorAI({ policyFile: o.policyFile, policy: o.policy, serviceId: o.serviceId, headlessAsk: o.headlessAsk, console: o.console, fetch: o.fetch, env: o.env, surface: "serve", intentStore: { maxSessionsPerOwner: o.intentSessionsPerCaller } });
  await rt.ready();
  const version = (() => { try { return JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version; } catch { return "unknown"; } })();
  const loopbackBind = isLoopback(o.host);
  const notifier = o.modelProxyUrl ? createCheckedNotifier({ url: o.modelProxyUrl, token: o.modelProxyToken || "", fetchImpl: o.notifyFetch }) : null;
  const log = (req, status, t0) => { if (o.log) process.stderr.write(`${new Date().toISOString()} ${req.method} ${req.url.split("?")[0]} ${status} ${(performance.now() - t0).toFixed(1)}ms\n`); };

  async function route(req) {
    const path = req.url.split("?")[0];
    if (path === "/healthz") {
      if (req.method !== "GET") throw new HttpError(405, "use GET");
      const s = await rt.ready();
      return { status: "ok", version, policyId: s.policyId };
    }
    if (path !== "/v1/scan" && path !== "/v1/tool-call" && path !== "/v1/index-scan" && path !== "/v1/task") throw new HttpError(404, "not found");
    if (req.method !== "POST") throw new HttpError(405, "use POST");
    const owner = principal(req, tokens);
    if (owner === null) throw new HttpError(401, "missing or wrong bearer token");
    const body = await readJson(req, o.maxBody);
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new HttpError(400, "body must be a JSON object");
    if (body.session != null && (typeof body.session !== "string" || !body.session || body.session.length > 256)) throw new HttpError(400, "session must be a non-empty string of at most 256 characters");
    const session = body.session == null ? undefined : body.session;
    if (path === "/v1/task") {
      if (session === undefined) throw new HttpError(400, "session is required");
      if (typeof body.prompt !== "string") throw new HttpError(400, "prompt must be a string");
      if (body.prompt.length > MAX_TEXT) throw new HttpError(413, "prompt too long");
      return withTimeout(rt.captureTask(session, body.prompt, owner), o.timeoutMs);
    }
    if (path === "/v1/scan") {
      const ctx = cleanCtx(body.ctx);
      const { tool, ...engineCtx } = ctx;
      // Inbound content (ctx.inbound) may arrive as the tool's raw `result` (any JSON) instead of `text`;
      // either way it is reduced to the same decoded text the hook, the SDK and the MCP gateway scan
      // (cli/inbound.mjs inboundText), so a client that sends JSON.stringify(result) is not scanning
      // escaped text.
      const raw = engineCtx.inbound === true && body.result !== undefined ? body.result : body.text;
      if (typeof raw !== "string" && !(engineCtx.inbound === true && raw && typeof raw === "object")) throw new HttpError(400, engineCtx.inbound === true ? "text must be a string, or result a JSON value" : "text must be a string");
      if (typeof raw === "string" && raw.length > MAX_TEXT) throw new HttpError(413, "text too long");
      const stage = body.stage === undefined ? "prompt" : body.stage;
      if (!STAGES.includes(stage)) throw new HttpError(400, `stage must be one of ${STAGES.join(", ")}`);
      const text = engineCtx.inbound === true ? inboundLib.inboundText(raw, MAX_TEXT) : raw;
      return withTimeout(rt.scan(text, stage, engineCtx, { tool: tool || "scan", event: "Scan", decoded: true, session }), o.timeoutMs);
    }
    if (path === "/v1/index-scan") {
      // Chunks an application is about to embed (cli/index-scan.mjs). Strings, or objects whose string
      // values are scanned (a LangChain Document's pageContent and metadata). The verdicts carry indexes,
      // never chunk text; `source` only ever leaves as a keyed hash.
      const { chunks, source } = body;
      if (!Array.isArray(chunks)) throw new HttpError(400, "chunks must be an array");
      if (chunks.length > indexScanLib.INDEX_MAX_CHUNKS) throw new HttpError(413, `at most ${indexScanLib.INDEX_MAX_CHUNKS} chunks`);
      for (const c of chunks) {
        if (typeof c === "string") { if (c.length > MAX_TEXT) throw new HttpError(413, "chunk too long"); }
        else if (!c || typeof c !== "object") throw new HttpError(400, "each chunk must be a string or an object");
      }
      const bad = indexScanLib.indexSourceProblem(source);
      if (bad) throw new HttpError(400, bad);
      return withTimeout(rt.scanForIndex(chunks, { source, session }), o.timeoutMs);
    }
    if (typeof body.tool !== "string" || !body.tool || body.tool.length > 256) throw new HttpError(400, "tool must be a non-empty string");
    if (body.input != null && (typeof body.input !== "object" || Array.isArray(body.input))) throw new HttpError(400, "input must be an object");
    if (body.cwd != null && typeof body.cwd !== "string") throw new HttpError(400, "cwd must be a string");
    if (body.toolCallId != null && (typeof body.toolCallId !== "string" || !body.toolCallId || body.toolCallId.length > 256)) throw new HttpError(400, "toolCallId must be a non-empty string of at most 256 characters");
    const v = await withTimeout(rt.toolCall({ tool: body.tool, input: body.input || {}, cwd: body.cwd || process.cwd(), permissionMode: typeof body.permissionMode === "string" ? body.permissionMode.slice(0, 32) : "", session, owner }), o.timeoutMs);
    if (notifier && body.toolCallId) notifier.note(body.toolCallId);
    return v;
  }

  const server = http.createServer(async (req, res) => {
    const t0 = performance.now();
    let status = 200, payload;
    try {
      if (loopbackBind && !hostHeaderOk(req.headers.host)) throw new HttpError(421, "Host header is not a loopback name");
      payload = await route(req);
    } catch (e) {
      status = e instanceof HttpError ? e.status : 500;
      payload = { error: e instanceof HttpError ? e.message : "internal error" };
    }
    const body = JSON.stringify(payload);
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff", "content-length": Buffer.byteLength(body) });
    res.end(body);
    log(req, status, t0);
  });
  server.headersTimeout = 5000;
  server.requestTimeout = o.timeoutMs + 5000;
  server.keepAliveTimeout = 5000;
  server.maxConnections = 256;
  await new Promise((res, rej) => { server.once("error", rej); server.listen(o.port, o.host, () => { server.off("error", rej); res(); }); });
  const addr = server.address();
  const url = `http://${addr.family === "IPv6" ? `[${addr.address}]` : addr.address}:${addr.port}`;
  const close = async () => { await new Promise((r) => server.close(() => r())); server.closeAllConnections?.(); if (notifier) await notifier.close(); await rt.flush(); };
  return { server, url, runtime: rt, close, ...(notifier ? { notifier } : {}) };
}

async function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { process.stderr.write(`moorai-serve: ${e.message}\n`); process.exit(2); }
  const s = await createServer(o);
  // One machine-readable line, so a supervisor (or a test using --port 0) can find the port.
  process.stdout.write(JSON.stringify({ listening: s.url, auth: o.token ? "bearer" : "none", serviceId: s.runtime.settings.serviceId, ...(o.modelProxyUrl ? { modelProxy: new URL(o.modelProxyUrl).origin } : {}) }) + "\n");
  const stop = async () => { await s.close(); process.exit(0); };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
const invoked = (() => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (invoked) main();
