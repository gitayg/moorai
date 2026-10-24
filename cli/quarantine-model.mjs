// The quarantined reader's model: an OpenAI-compatible chat-completions endpoint called with no tools,
// temperature 0, a hard max_tokens and a deadline. Which endpoint:
//   fileQuarantineModel { url, model } from the admin binding or the signed policy (data/quarantine-summary.js);
//   otherwise, only when the admin binding sets fileQuarantineAutodetect, the first local runtime of
//   cli/local-ai-inventory.mjs's table that answers on 127.0.0.1 among Ollama (11434) and LM Studio (1234), with
//   the first model its /v1/models lists. Neither: no reader.
// A non-loopback URL is refused unless the admin binding allows it, so file text stays on the device by default.
// On a loopback URL the request that carries the file is held until cli/quarantine-owner.mjs has checked the
// process that accepted the connection; a refusal sends nothing and is "untrusted".
// Requests go through a fresh http.Agent, never the global one, so no environment proxy can carry them elsewhere.
import http from "node:http";
import https from "node:https";
import { LOCAL_AI_RUNTIMES } from "./local-ai-inventory.mjs";
import { modelEndpoint } from "../data/quarantine-summary.js";

const PROBE_MS = 400;
const BODY_MAX = 256 * 1024;
export const READER_MAX_TOKENS = 700;
const AUTODETECT = ["ollama", "lmstudio"];

function request(url, { method = "GET", body = null, timeoutMs = 1000, verify = null } = {}) {
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
    const send = () => { if (data) req.write(data); req.end(); };
    if (!verify) { send(); return; }
    // Nothing is written until the accepting process is checked.
    req.on("socket", (sock) => {
      const check = () => {
        if (done) return;
        const v = verify({ serverPort: sock.remotePort, localPort: sock.localPort });
        if (v && v.ok) send();
        else { req.destroy(); finish({ ok: false, untrusted: true, why: (v && v.why) || "the reader could not be checked" }); }
      };
      if (sock.connecting) sock.once("connect", check); else check();
    });
  });
}

async function firstModel(modelsUrl, timeoutMs) {
  const r = await request(modelsUrl, { timeoutMs });
  if (!r.ok) return null;
  try { const o = JSON.parse(r.text); const id = Array.isArray(o.data) && o.data[0] && o.data[0].id; return typeof id === "string" && id ? id : null; } catch { return null; }
}

// -> { ok: true, endpoint, model, kind: "local" | "remote", runtime } | { ok: false, why, kind? }
export async function resolveReader(cfg, { deadline = Date.now() + 2000, runtimes = LOCAL_AI_RUNTIMES } = {}) {
  const left = () => Math.max(1, deadline - Date.now());
  if (cfg && cfg.model) {
    const ep = modelEndpoint(cfg.model.url, { allowRemote: !!cfg.allowRemote });
    if (!ep.ok) return { ok: false, why: ep.why, kind: ep.kind || null };
    const model = cfg.model.model || await firstModel(ep.modelsUrl, Math.min(PROBE_MS * 3, left()));
    if (!model) return { ok: false, why: "the configured reader lists no model", kind: ep.kind };
    return { ok: true, endpoint: ep.endpoint, model, kind: ep.kind, runtime: "configured", executables: cfg.model.executables || [] };
  }
  if (!cfg || cfg.autodetect !== true) return { ok: false, why: "no reader configured (fileQuarantineModel unset; auto-detection needs fileQuarantineAutodetect in the admin binding)", kind: null };
  for (const r of runtimes.filter((x) => AUTODETECT.includes(x.runtime))) {
    for (const port of r.ports) {
      const ep = modelEndpoint(`http://127.0.0.1:${port}`);
      const model = await firstModel(ep.modelsUrl, Math.min(PROBE_MS, left()));
      if (model) return { ok: true, endpoint: ep.endpoint, model, kind: "local", runtime: r.runtime, executables: [] };
    }
  }
  return { ok: false, why: "no local model runtime answered", kind: null };
}

// -> { ok: true, content } | { ok: false, why, untrusted? }. No tools, temperature 0, max_tokens READER_MAX_TOKENS.
// verify({ serverPort, localPort }) -> { ok, why } runs before the body is written (a loopback reader).
export async function callReader(reader, messages, { timeoutMs = 9000, verify = null } = {}) {
  const r = await request(reader.endpoint, { method: "POST", timeoutMs, verify, body: { model: reader.model, messages, temperature: 0, max_tokens: READER_MAX_TOKENS, stream: false } });
  if (!r.ok) return r;
  try {
    const o = JSON.parse(r.text);
    const c = o && Array.isArray(o.choices) && o.choices[0] && o.choices[0].message && o.choices[0].message.content;
    return typeof c === "string" ? { ok: true, content: c } : { ok: false, why: "reader reply has no message content" };
  } catch { return { ok: false, why: "reader reply is not JSON" }; }
}
