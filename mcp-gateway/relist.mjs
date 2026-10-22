// The gateway's own tools/list upstream, sent before a block-mode tools/call when the route's last judged
// listing is older than the policy's window (../mcp-proxy/tool-recheck.mjs owns the loop, the budget and
// the sharing; this file sends one page).
//
// A separate upstream POST, never part of the client's exchange: its answer is read here and never reaches
// the client. It carries the client's own session, built from the headers of the request that holds the
// tools/call exactly as the forward path builds them (hop-by-hop stripped, placeholder credentials
// swapped, this hop's trace): Mcp-Session-Id (2025-03-26 .. 2025-11-25), MCP-Protocol-Version and
// Authorization go as the client sent them. Then the request's own: a JSON body, an Accept of both JSON
// and SSE (the transport requires both), Mcp-Method "tools/list" when the client sends the 2026-07-28
// metadata headers, no Mcp-Name / Mcp-Param-* / Last-Event-ID, and the client's protocol-level `_meta`
// keys ("io.modelcontextprotocol/...", which carry the protocol version in 2026-07-28) copied from the
// call. The id is a string with a per-process random nonce, so it cannot collide with a request the
// client has in flight on the same session. The answer may be JSON or an SSE stream; only the message
// with that id counts, and anything else on the stream is ignored.
import http from "node:http";
import https from "node:https";
import { randomBytes } from "node:crypto";
import { pipeline } from "node:stream";
import { createGunzip, createInflate, createBrotliDecompress } from "node:zlib";
import { HOP, DEFAULT_MAX_RESPONSE_BYTES } from "./config.mjs";
import { maskResponse } from "../model-proxy/credential-mask.mjs";
import { applyTraceHeaders } from "../model-proxy/trace-w3c.mjs";
import { createSseFramer } from "./sse.mjs";

export const RELIST_ID_PREFIX = `moorai-gw-recheck-${randomBytes(12).toString("hex")}-`;
let seq = 0;
const DECODERS = { gzip: createGunzip, "x-gzip": createGunzip, deflate: createInflate, br: createBrotliDecompress };
const PROTOCOL_META = "io.modelcontextprotocol/";
const DROP = (k) => k === "mcp-name" || k.startsWith("mcp-param-") || k === "last-event-id" || k === "content-type" || k === "accept" || k === "mcp-method";

export function relistHeaders(reqHeaders, { swaps = null, trace = null } = {}) {
  const h = {};
  for (const [k, v] of Object.entries(reqHeaders)) if (!HOP.has(k) && !DROP(k)) h[k] = v;
  if (swaps) for (const [k, v] of swaps) h[k] = v;
  applyTraceHeaders(h, trace);
  if (reqHeaders["mcp-method"] != null) h["mcp-method"] = "tools/list";
  h["content-type"] = "application/json";
  h.accept = "application/json, text/event-stream";
  h["accept-encoding"] = "identity";
  return h;
}

// The protocol-level _meta keys of the client's tools/call, or null.
export function relistMeta(callMsg) {
  const m = callMsg && callMsg.params && callMsg.params._meta;
  if (!m || typeof m !== "object" || Array.isArray(m)) return null;
  const out = {};
  for (const [k, v] of Object.entries(m)) if (k.startsWith(PROTOCOL_META)) out[k] = v;
  return Object.keys(out).length ? out : null;
}

// → fetchPage(cursor, { signal }) for tool-recheck.mjs: resolves { tools, nextCursor }, rejects otherwise.
export function createRelistFetcher({ target, headers, agent, creds = null, meta = null, maxBytes = DEFAULT_MAX_RESPONSE_BYTES, lookup }) {
  const cap = maxBytes || DEFAULT_MAX_RESPONSE_BYTES;
  return (cursor, { signal } = {}) => new Promise((resolve, reject) => {
    const id = RELIST_ID_PREFIX + (++seq);
    const params = {};
    if (cursor != null) params.cursor = cursor;
    if (meta) params._meta = meta;
    const body = Buffer.from(JSON.stringify({ jsonrpc: "2.0", id, method: "tools/list", params }));
    const lib = target.protocol === "https:" ? https : http;
    let settled = false;
    let req = null;
    const end = () => { try { req.destroy(); } catch { /* gone */ } };
    const fail = () => { if (!settled) { settled = true; reject(new Error("re-list failed")); } end(); };
    const answer = (x) => {
      if (settled) return;
      if (x.error || !x.result || typeof x.result !== "object" || !Array.isArray(x.result.tools)) return fail();
      settled = true;
      resolve({ tools: x.result.tools, nextCursor: x.result.nextCursor });
      end();
    };
    // the message answering this id, from a parsed JSON body or SSE data (a batch array included)
    const take = (v) => { for (const x of Array.isArray(v) ? v : [v]) if (x && typeof x === "object" && x.id === id && x.method === undefined) { answer(x); return; } };
    try {
      req = lib.request(target, { method: "POST", headers: { ...headers, "content-length": String(body.length) }, agent, ...(lookup ? { lookup } : {}), ...(signal ? { signal } : {}) });
    } catch { fail(); return; }
    req.on("error", fail);
    req.on("response", (raw) => {
      const ctype = String(raw.headers["content-type"] || "").toLowerCase();
      if (raw.statusCode < 200 || raw.statusCode >= 300) { raw.resume(); return fail(); }
      let ur = raw;
      if (creds) { ur = maskResponse(raw, creds.secrets); if (ur.refuse) return fail(); }
      else {
        const enc = String(raw.headers["content-encoding"] || "identity").trim().toLowerCase();
        if (enc !== "identity") {
          if (!Object.hasOwn(DECODERS, enc)) { raw.resume(); return fail(); }
          ur = DECODERS[enc]();
          pipeline(raw, ur, () => {});
        }
      }
      ur.on("error", fail);
      if (ctype.startsWith("text/event-stream")) {
        const framer = createSseFramer({
          maxEventBytes: cap,
          onRaw: () => {},
          onOverflow: () => {},
          onEvent: (ev) => { if (ev.data == null) return; let v; try { v = JSON.parse(ev.data); } catch { return; } take(v); }
        });
        ur.on("data", (c) => { try { framer.push(c); } catch { fail(); } });
        ur.on("end", () => { try { framer.end(); } catch { /* nothing left */ } fail(); });
        return;
      }
      if (!ctype.startsWith("application/json")) { ur.resume(); return fail(); }
      const chunks = [];
      let n = 0;
      ur.on("data", (c) => { n += c.length; if (n > cap) return fail(); chunks.push(c); });
      ur.on("end", () => {
        if (settled) return;
        let v;
        try { v = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return fail(); }
        take(v);
        fail(); // no message answered this id
      });
    });
    req.end(body);
  });
}
