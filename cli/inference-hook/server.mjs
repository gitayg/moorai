// The Inference hooks server: Anthropic POSTs each governed prompt (and, with Validate tool calls on, each
// tool call frame) here, signed per Standard Webhooks; MoorAI answers allow or deny in Anthropic's schema.
// Protocol: platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint.
//
// ORDER OF CHECKS for a POST (any path: the configured URL is the endpoint, there is no fixed suffix)
//   1. body read raw, bounded (maxBody per request, maxInflight across requests)
//   2. Standard Webhooks signature over the raw bytes, constant-time, any configured secret  → else 401
//   3. timestamp within five minutes                                                          → else 401
//   4. webhook-id not already accepted inside its window                                      → else 409
//   5. the frame judged by the MoorAI runtime                                                 → 200 verdict
// A non-200 answer is a webhook failure to Anthropic, never a deny: the organization's failure handling
// decides it. So a request this server authenticated but could not judge in full (an item past the scan
// cap, the evaluation deadline, an engine error, an unreadable frame) gets a verdict from --fail: "open"
// answers allow, "closed" answers deny. A body that cannot even be read (over maxBody, or the in-flight
// budget) cannot be authenticated: "closed" answers deny, "open" answers 413 / 503 and leaves the outcome
// to Anthropic's own failure handling. Shadow mode answers allow to every frame it judged and reports what
// it would have denied.
//
// EXPOSURE. Default bind 127.0.0.1, with TLS terminated by a reverse proxy on the same host (Anthropic
// only calls an https:// URL on port 443 with a public certificate). A non-loopback bind needs
// --allow-remote. No Host-header check: every request must carry a valid HMAC signature, which a browser
// on a rebinding page cannot produce, and a TLS proxy commonly forwards the public Host name.
import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createMoorAI } from "../../packages/agent-sdk/src/runtime.mjs";
import { verify, createReplayCache } from "./signature.mjs";
import { createEvaluator, ITEM_CAP, MAX_NEW_ITEMS } from "./evaluate.mjs";
import { frameContext, wrapReporter, reportUnevaluated, cleanSource } from "./report.mjs";
import { ALLOW, denyBody, newReference, policyDenyReason, failDenyReason } from "./verdict.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const PROTOCOL_MAX_BODY = 64 * 1048576;
export const DEFAULTS = Object.freeze({
  host: "127.0.0.1", port: 8792, mode: "enforce", fail: "open",
  maxBody: PROTOCOL_MAX_BODY, maxInflight: 256 * 1048576, evalTimeoutMs: 4000,
  headersTimeoutMs: 5000, requestTimeoutMs: 30000, keepAliveTimeoutMs: 30000, maxConnections: 128,
  replayMax: 200000, itemCap: ITEM_CAP, maxItems: MAX_NEW_ITEMS
});

export async function createServer(opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  if (!Array.isArray(o.keys) || !o.keys.length) throw new Error("a signing secret is required");
  if (o.fail !== "open" && o.fail !== "closed") throw new Error("fail must be open or closed");
  const shadow = o.mode === "shadow";
  const rt = o.runtime || await createMoorAI({ policyFile: o.policyFile, policy: o.policy, serviceId: o.serviceId, headlessAsk: o.headlessAsk, console: o.console, fetch: o.fetch, env: o.env, systemConfig: o.systemConfig, surface: "inference-hook" });
  wrapReporter(rt, { shadow });
  await rt.ready();
  const evaluator = createEvaluator(rt, { itemCap: o.itemCap, maxItems: o.maxItems });
  const replay = createReplayCache({ max: o.replayMax });
  const now = o.now || (() => Date.now() / 1000);
  const version = (() => { try { return JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version; } catch { return "unknown"; } })();
  let inflight = 0;

  const send = (res, status, payload) => {
    const body = JSON.stringify(payload);
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff", "content-length": Buffer.byteLength(body) });
    res.end(body);
    return status;
  };
  const log = (status, note, t0) => { if (o.log) process.stderr.write(`${new Date().toISOString()} POST ${status} ${note} ${(performance.now() - t0).toFixed(1)}ms\n`); };

  // → { raw, release } | { refused: "body" | "busy" } | { dropped: true }. The raw bytes are held, and
  // counted against maxInflight, until release(). Past maxBody the rest is read and discarded (so the
  // sender reads the answer instead of a reset) up to twice maxBody, then the socket is dropped.
  function readRaw(req) {
    return new Promise((resolve) => {
      const chunks = [];
      let n = 0, held = 0, refused = null, done = false;
      const release = () => { inflight -= held; held = 0; chunks.length = 0; };
      const finish = (v) => { if (done) return; done = true; resolve(v); };
      const declared = Number(req.headers["content-length"]);
      if (declared > o.maxBody * 2) { req.destroy(); return finish({ dropped: true }); }
      if (declared > o.maxBody) refused = "body";
      req.on("data", (c) => {
        n += c.length;
        if (n > o.maxBody * 2) { release(); req.destroy(); finish({ dropped: true }); return; }
        if (refused) return;
        if (n > o.maxBody) { refused = "body"; release(); return; }
        if (inflight + c.length > o.maxInflight) { refused = "busy"; release(); return; }
        inflight += c.length; held += c.length; chunks.push(c);
      });
      req.on("end", () => {
        if (refused) { release(); return finish({ refused }); }
        const raw = Buffer.concat(chunks);
        finish({ raw, release });
      });
      req.on("error", () => { release(); finish({ dropped: true }); });
      req.on("close", () => { if (!done) { release(); finish({ dropped: true }); } });
    });
  }

  async function judge(frame, session) {
    let result, error = false;
    try { result = await evaluator.evaluate(frame, { deadline: Date.now() + o.evalTimeoutMs, session }); }
    catch { error = true; result = { denied: [], unevaluated: [{ kind: "request", why: "error" }] }; }
    return { ...result, error };
  }

  async function handle(req, res) {
    const t0 = performance.now();
    const path = req.url.split("?")[0];
    if (req.method === "GET" && path === "/healthz") { req.resume(); return send(res, 200, { status: "ok", version }); }
    if (req.method !== "POST") { req.resume(); return send(res, 405, { error: "use POST" }); }
    const body = await readRaw(req);
    if (body.dropped) return;
    if (body.refused) {
      if (shadow) return log(send(res, 200, ALLOW), `allow (shadow; ${body.refused} not read)`, t0);
      if (o.fail === "closed") return log(send(res, 200, denyBody(failDenyReason([body.refused === "body" ? "body" : "busy"]), newReference())), `deny (fail closed: ${body.refused})`, t0);
      return log(send(res, body.refused === "body" ? 413 : 503, { error: body.refused === "body" ? `body over ${o.maxBody} bytes` : "server busy" }), body.refused, t0);
    }
    const v = verify(o.keys, req.headers, body.raw, now());
    if (!v.ok) { body.release(); return log(send(res, 401, { error: `signature rejected: ${v.reason}` }), v.reason, t0); }
    if (!replay.claim(v.id, v.timestamp, now())) { body.release(); return log(send(res, 409, { error: "webhook-id already accepted (replay)" }), "replay", t0); }
    let frame = null;
    try { frame = JSON.parse(body.raw.toString("utf8")); } catch { frame = null; }
    body.release();
    const ref = newReference();
    if (!frame || typeof frame !== "object" || Array.isArray(frame)) {
      reportUnevaluated(rt, { unevaluated: [{ kind: "request", why: "unparseable" }], failed: true, fail: o.fail, shadow });
      const out = !shadow && o.fail === "closed" ? denyBody(failDenyReason(["unparseable"]), ref) : ALLOW;
      return log(send(res, 200, out), `${out.action} (unparseable)`, t0);
    }
    // Other hook event types will be introduced; the documented answer to one we don't know is allow.
    if (frame.type !== "prompt" && frame.type !== "tool_call") return log(send(res, 200, ALLOW), "allow (unknown type)", t0);
    const session = typeof frame.session_id === "string" && frame.session_id && frame.session_id.length <= 256 ? frame.session_id : undefined;
    const ctx = { ref, source: cleanSource(frame.source && frame.source.application) };
    return frameContext.run(ctx, async () => {
      const { denied, unevaluated, error } = await judge(frame, session);
      let out = ALLOW;
      if (denied.length) out = denyBody(policyDenyReason(frame.type, denied), ref);
      else if (unevaluated.length && o.fail === "closed") out = denyBody(failDenyReason(unevaluated.map((u) => u.why)), ref);
      if (unevaluated.length) reportUnevaluated(rt, { unevaluated, failed: !denied.length, fail: o.fail, shadow, session, error });
      const would = out.action;
      if (shadow) out = ALLOW;
      return log(send(res, 200, out), `${out.action}${shadow && would === "deny" ? " (shadow: would deny)" : ""} ${frame.type}`, t0);
    });
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch(() => { if (!res.headersSent) send(res, 500, { error: "internal error" }); });
  });
  server.headersTimeout = o.headersTimeoutMs;
  server.requestTimeout = o.requestTimeoutMs;
  server.keepAliveTimeout = o.keepAliveTimeoutMs;
  server.maxConnections = o.maxConnections;
  await new Promise((res, rej) => { server.once("error", rej); server.listen(o.port, o.host, () => { server.off("error", rej); res(); }); });
  const addr = server.address();
  const url = `http://${addr.family === "IPv6" ? `[${addr.address}]` : addr.address}:${addr.port}`;
  const close = async () => { await new Promise((r) => { server.close(() => r()); server.closeAllConnections?.(); }); await rt.flush(); };
  return { server, url, runtime: rt, close, inflight: () => inflight, replaySize: () => replay.size() };
}
