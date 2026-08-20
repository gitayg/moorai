#!/usr/bin/env node
// MoorAI local inference service. A tiny localhost-only HTTP server that lets the HTTPS console reach
// the developer's OWN provider key WITHOUT the console ever holding it: the browser POSTs the admin's
// plain-English policy to THIS service, the service compiles it with the device key (Anthropic, the
// same provider Claude Code uses), and returns the structured rule JSON. The console then re-validates
// that JSON server-side (validateRules is the security boundary) before persisting. No AI credential
// ever touches MoorAI's cloud; no NEW third party / no NEW egress is introduced.
//
//   node moorai-localsvc.mjs            # start (binds 127.0.0.1 only)
//   node moorai-localsvc.mjs start      # same
//   MOORAI_LOCALSVC_PORT=8799 node moorai-localsvc.mjs
//
// Launched by the MoorAI desktop host on login (a lightweight background helper), or by hand for dev.
//
// THREAT MODEL / why no auth beyond origin-lock + localhost bind:
//   - The socket binds 127.0.0.1 ONLY, so nothing off-box can connect.
//   - CORS is locked to the console origin (https://moorai.glick.run) + localhost dev origins, so a
//     random website the developer visits cannot script this endpoint (the browser blocks the response).
//   - Private Network Access preflight is answered so the console (public HTTPS) may call this private
//     endpoint at all in modern Chrome.
//   - The endpoint carries NO secret in/out: the request is plain English, the response is a policy
//     patch that the console independently re-validates. The device key never leaves this process.
//   Residual risk: a malicious local process could POST here to burn provider tokens; acceptable for a
//   dev-machine helper, and no elevation or data exposure results. Do NOT bind to 0.0.0.0.

import http from "node:http";
import { hasDeviceKey, compilePolicyWithProvider } from "../data/device-inference.mjs";

const PORT = Number(process.env.MOORAI_LOCALSVC_PORT || 8799);
const HOST = "127.0.0.1"; // loopback ONLY — never make this configurable to a public interface

// Origins allowed to script this endpoint. The production console plus localhost dev origins.
const ALLOWED_ORIGINS = new Set([
  "https://moorai.glick.run",
  process.env.MOORAI_CONSOLE_ORIGIN || "",
].filter(Boolean));
const isLocalhostOrigin = (o) => /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(o || "");
const originAllowed = (o) => !!o && (ALLOWED_ORIGINS.has(o) || isLocalhostOrigin(o));

// A minimal fallback schema for when the console does not supply its live-vocab schema. The console's
// schema (built from its authoritative threat/content/tier ids) is strongly preferred — the device
// output is re-validated server-side regardless, so this fallback only shapes the model's first draft.
const FALLBACK_SCHEMA = [
  "You compile a security administrator's plain-English policy request into a STRICT JSON array of policy calls.",
  "Output ONLY a JSON array — no prose, no markdown, no code fences. Each element is {\"setter\":string,\"args\":array,\"summary\":string}.",
  "Allowed setters: setPolicyThreat[id:int,action], setPolicyThreatMany[[id:int,...],action], setPolicyContent[id:string,action], setPolicyTiers[{tier:action}], setPolicyMcp[[name,...]], setPolicyEndpoints[[host,...]], setPolicyCapture[tier], setPolicyKill[boolean].",
  "action MUST be one of: disabled, alert, notify, justify, block. If part of the request cannot be mapped, omit it. Never invent ids, setters, or actions.",
].join("\n");

function setCors(res, origin) {
  if (originAllowed(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  // Private Network Access: the console is a PUBLIC (https) page reaching a PRIVATE (loopback) endpoint;
  // Chrome sends a preflight with Access-Control-Request-Private-Network and requires this header back.
  res.setHeader("Access-Control-Allow-Private-Network", "true");
}

const readBody = (req) => new Promise((resolve) => {
  let data = "";
  let done = false;
  const finish = (v) => { if (!done) { done = true; resolve(v); } };
  req.on("data", (c) => { data += c; if (data.length > 1e5) { req.destroy(); finish(null); } });
  req.on("end", () => { try { finish(JSON.parse(data || "{}")); } catch { finish(null); } });
  req.on("error", () => finish(null));
  req.on("close", () => finish(null));
});

const sendJson = (res, code, body) => {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
};

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin || "";
  setCors(res, origin);

  if (req.method === "OPTIONS") {
    // Answer the CORS + PNA preflight. 204, no body.
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${HOST}:${PORT}`);

  // Liveness probe so the browser can detect the service without spending a provider call.
  if (url.pathname === "/health" && req.method === "GET") {
    return sendJson(res, 200, { ok: true, service: "moorai-localsvc", deviceKey: hasDeviceKey() });
  }

  if (url.pathname === "/nl-compile" && req.method === "POST") {
    // Only origins we CORS-allow may drive this (defence in depth on top of the browser's own block).
    if (origin && !originAllowed(origin)) return sendJson(res, 403, { error: "origin not allowed" });
    if (!hasDeviceKey()) {
      return sendJson(res, 503, {
        error: "no-device-key",
        message: "AI authoring needs a provider API key on this machine (ANTHROPIC_API_KEY or the admin key file). Tier A (templates) still works.",
      });
    }
    const body = (await readBody(req)) || {};
    const text = String(body.text || "").trim();
    if (!text) return sendJson(res, 400, { error: "empty-text" });
    const schema = (body.schemaPrompt && String(body.schemaPrompt).trim()) || FALLBACK_SCHEMA;
    const rules = await compilePolicyWithProvider(text, schema);
    if (rules == null) return sendJson(res, 502, { error: "inference-failed", message: "The device provider call failed or returned no usable rules." });
    // Content-free: we return only the structured rule candidates; the console re-validates them.
    return sendJson(res, 200, { ok: Array.isArray(rules) ? rules.length > 0 : true, rules });
  }

  return sendJson(res, 404, { error: "not-found" });
});

import { fileURLToPath } from "node:url";
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const cmd = process.argv[2];
  if (cmd === undefined || cmd === "start") {
    server.listen(PORT, HOST, () => {
      process.stdout.write(`moorai-localsvc listening on http://${HOST}:${PORT} (deviceKey=${hasDeviceKey()})\n`);
    });
  } else {
    process.stderr.write(`unknown command "${cmd}" — usage: moorai-localsvc [start]\n`);
    process.exit(2);
  }
}

export { server, PORT, HOST, originAllowed };
