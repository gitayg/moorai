// The quarantined reader's model: an OpenAI-compatible chat-completions endpoint called with no tools,
// temperature 0, a hard max_tokens and a deadline. Which endpoint:
//   fileQuarantineModel { url, model } from the admin binding or the signed policy (data/quarantine-summary.js);
//   otherwise the first local runtime of cli/local-ai-inventory.mjs's table that answers on 127.0.0.1 among
//   Ollama (11434) and LM Studio (1234), with the first model its /v1/models lists.
// A non-loopback URL is refused unless the admin binding allows it, so file text stays on the device by default.
// Requests go through a fresh http.Agent, never the global one, so no environment proxy can carry them elsewhere.
import http from "node:http";
import https from "node:https";
import { LOCAL_AI_RUNTIMES } from "./local-ai-inventory.mjs";
import { modelEndpoint } from "../data/quarantine-summary.js";

const PROBE_MS = 400;
const BODY_MAX = 256 * 1024;
export const READER_MAX_TOKENS = 700;
const AUTODETECT = ["ollama", "lmstudio"];

function request(url, { method = "GET", body = null, timeoutMs = 1000 } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { resolve({ ok: false, why: "bad URL" }); return; }
    const mod = u.protocol === "https:" ? https : http;
    const agent = new mod.Agent({ keepAlive: false });
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    let done = false;
    const finish = (r) => { if (done) return; done = true; clearTimeout(timer); agent.destroy(); resolve(r); };
    const req = mod.request(u, { method, agent, headers: { accept: "application/json", ...(data ? { "content-type": "application/json", "content-length": data.length } : {}) } }, (res) => {
      const chunks = [];
      let n = 0;
      res.on("data", (c) => { n += c.length; if (n > BODY_MAX) { req.destroy(); finish({ ok: false, why: "reader response too large" }); return; } chunks.push(c); });
      res.on("end", () => finish(res.statusCode >= 200 && res.statusCode < 300 ? { ok: true, text: Buffer.concat(chunks).toString("utf8") } : { ok: false, why: `reader answered HTTP ${res.statusCode}` }));
      res.on("error", () => finish({ ok: false, why: "reader connection failed" }));
    });
    const timer = setTimeout(() => { req.destroy(); finish({ ok: false, why: "reader timed out" }); }, Math.max(1, timeoutMs));
    req.on("error", () => finish({ ok: false, why: "reader unreachable" }));
    if (data) req.write(data);
    req.end();
  });
}

async function firstModel(modelsUrl, timeoutMs) {
  const r = await request(modelsUrl, { timeoutMs });
  if (!r.ok) return null;
  try { const o = JSON.parse(r.text); const id = Array.isArray(o.data) && o.data[0] && o.data[0].id; return typeof id === "string" && id ? id : null; } catch { return null; }
}

// -> { ok: true, endpoint, model, kind: "local" | "remote", runtime } | { ok: false, why, kind? }
export async function resolveReader(cfg, { deadline = Date.now() + 2000 } = {}) {
  const left = () => Math.max(1, deadline - Date.now());
  if (cfg && cfg.model) {
    const ep = modelEndpoint(cfg.model.url, { allowRemote: !!cfg.allowRemote });
    if (!ep.ok) return { ok: false, why: ep.why, kind: ep.kind || null };
    const model = cfg.model.model || await firstModel(ep.modelsUrl, Math.min(PROBE_MS * 3, left()));
    if (!model) return { ok: false, why: "the configured reader lists no model", kind: ep.kind };
    return { ok: true, endpoint: ep.endpoint, model, kind: ep.kind, runtime: "configured" };
  }
  for (const r of LOCAL_AI_RUNTIMES.filter((x) => AUTODETECT.includes(x.runtime))) {
    for (const port of r.ports) {
      const ep = modelEndpoint(`http://127.0.0.1:${port}`);
      const model = await firstModel(ep.modelsUrl, Math.min(PROBE_MS, left()));
      if (model) return { ok: true, endpoint: ep.endpoint, model, kind: "local", runtime: r.runtime };
    }
  }
  return { ok: false, why: "no local model runtime answered", kind: null };
}

// -> { ok: true, content } | { ok: false, why }. No tools, temperature 0, max_tokens READER_MAX_TOKENS.
export async function callReader(reader, messages, { timeoutMs = 9000 } = {}) {
  const r = await request(reader.endpoint, { method: "POST", timeoutMs, body: { model: reader.model, messages, temperature: 0, max_tokens: READER_MAX_TOKENS, stream: false } });
  if (!r.ok) return r;
  try {
    const o = JSON.parse(r.text);
    const c = o && Array.isArray(o.choices) && o.choices[0] && o.choices[0].message && o.choices[0].message.content;
    return typeof c === "string" ? { ok: true, content: c } : { ok: false, why: "reader reply has no message content" };
  } catch { return { ok: false, why: "reader reply is not JSON" }; }
}
