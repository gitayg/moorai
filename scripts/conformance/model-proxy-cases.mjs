// AI Servers live conformance: MoorAI's model proxy (a real moorai-model-proxy process, --mode enforce)
// in front of a real local model server (Ollama), through the paths a client SDK uses:
//   /openai/chat/completions     → Ollama's OpenAI-compatible /v1/chat/completions (JSON and SSE)
//   /anthropic/v1/messages       → Ollama's Anthropic-compatible /v1/messages
//   /ollama/api/chat             → Ollama's native /api/chat
//   /openai/responses            → Ollama's /v1/responses (the proxy forwards this unparsed: a known gap)
// An upstream recorder sits between the proxy and Ollama, so each case knows whether a refused request
// reached the model and whether the model really produced a tool call.
//
// Policy (a --policy-file): threat #39 (credentials) blocks, and functionToolActions blocks the
// delete_project_files function. Requests are fixed MoorAI probes; a fake AWS key stands in for a secret.
// Nothing calls a paid provider and no key is read: the Anthropic path gets a fixed non-key string.
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { startUpstreamRecorder, toolCallIn } from "./upstream-recorder.mjs";
import { startStandInConsole } from "./stand-in-console.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const PROXY = join(ROOT, "model-proxy", "moorai-model-proxy.mjs");
// The recorder's marker: the prefix every case's fake key shares. Each case gets its own key, because the
// proxy reports an item once (a repeated identical message is refused again without a second alert).
export const FAKE_AWS_KEY = "AKIAIOSFODNN7";
export const PROXY_POLICY = { captureTier: "content-free", threatPolicy: { 39: "block" }, functionToolActions: { delete_project_files: "block" } };
export const PREFERRED_MODELS = ["llama3.2:latest", "qwen3.5:9b", "mistral-nemo:latest"];

const OK_PROMPT = "Reply with the single word OK.";
const secretPrompt = (tag) => `Keep this for later: AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}${tag}\naws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYz${tag}KEY1"`;
const TOOL_PROMPT = "Call the delete_project_files tool now with path set to ./build. Do not answer with text.";
const FN = { name: "delete_project_files", description: "Delete the files under a project path", parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } };
const OPENAI_TOOLS = [{ type: "function", function: FN }];
const ANTHROPIC_TOOLS = [{ name: FN.name, description: FN.description, input_schema: FN.parameters }];
const ANTHROPIC_HEADERS = { "anthropic-version": "2023-06-01", "x-api-key": "moorai-conformance-not-a-key" };
const user = (content) => [{ role: "user", content }];

export const SERVER_CASES = [
  { id: "openai-chat-allow", kind: "allow", api: "openai", path: "/openai/chat/completions", body: (m) => ({ model: m, messages: user(OK_PROMPT), max_tokens: 16, temperature: 0, stream: false }) },
  { id: "openai-chat-stream-allow", kind: "stream-allow", api: "openai", path: "/openai/chat/completions", body: (m) => ({ model: m, messages: user(OK_PROMPT), max_tokens: 16, temperature: 0, stream: true }) },
  { id: "openai-chat-secret-deny", kind: "deny", api: "openai", path: "/openai/chat/completions", body: (m) => ({ model: m, messages: user(secretPrompt("OPENAIA")), max_tokens: 16, stream: false }) },
  { id: "openai-chat-toolcall-withhold", kind: "withhold", api: "openai", path: "/openai/chat/completions", body: (m) => ({ model: m, messages: user(TOOL_PROMPT), tools: OPENAI_TOOLS, temperature: 0, stream: false }) },
  { id: "openai-chat-stream-toolcall-withhold", kind: "withhold", api: "openai", stream: true, path: "/openai/chat/completions", body: (m) => ({ model: m, messages: user(TOOL_PROMPT), tools: OPENAI_TOOLS, temperature: 0, stream: true }) },
  { id: "anthropic-messages-allow", kind: "allow", api: "anthropic", path: "/anthropic/v1/messages", headers: ANTHROPIC_HEADERS, body: (m) => ({ model: m, max_tokens: 16, temperature: 0, messages: user(OK_PROMPT) }) },
  { id: "anthropic-messages-secret-deny", kind: "deny", api: "anthropic", path: "/anthropic/v1/messages", headers: ANTHROPIC_HEADERS, body: (m) => ({ model: m, max_tokens: 16, messages: user(secretPrompt("ANTHROP")) }) },
  { id: "anthropic-toolcall-withhold", kind: "withhold", api: "anthropic", path: "/anthropic/v1/messages", headers: ANTHROPIC_HEADERS, body: (m) => ({ model: m, max_tokens: 256, temperature: 0, tools: ANTHROPIC_TOOLS, messages: user(TOOL_PROMPT) }) },
  { id: "ollama-chat-allow", kind: "allow", api: "ollama", path: "/ollama/api/chat", body: (m) => ({ model: m, messages: user(OK_PROMPT), stream: false, options: { num_predict: 16, temperature: 0 } }) },
  { id: "ollama-chat-secret-deny", kind: "deny", api: "ollama", path: "/ollama/api/chat", body: (m) => ({ model: m, messages: user(secretPrompt("OLLAMAN")), stream: false, options: { num_predict: 16 } }) },
  { id: "ollama-chat-toolcall-withhold", kind: "withhold", api: "ollama", path: "/ollama/api/chat", body: (m) => ({ model: m, messages: user(TOOL_PROMPT), tools: OPENAI_TOOLS, stream: false, options: { temperature: 0 } }) },
  { id: "openai-responses-secret", kind: "unscanned", api: "responses", path: "/openai/responses", body: (m) => ({ model: m, input: secretPrompt("RESPONS"), max_output_tokens: 16 }) }
];

const EXPECT = { allow: "forward", "stream-allow": "forward", deny: "refuse", withhold: "withhold", unscanned: "unscanned" };
const isBlocked = (a) => a && (a.riskLevel === "Blocked" || a.decision === "deny");
const pickAlert = (a) => ({ category: a.category ?? null, riskLevel: a.riskLevel ?? null, decision: a.decision ?? null, reasonCode: a.reasonCode ?? null });

// What the client got back, as booleans. `text` is the raw body; `json` its parse (null for streams).
export function readResponse(def, status, contentType, text) {
  let json = null;
  try { json = JSON.parse(text); } catch { /* stream or not JSON */ }
  const stream = /event-stream|ndjson/.test(contentType || "");
  let okShape = false, errorShape = false;
  if (def.api === "openai") {
    okShape = stream ? /^data: /m.test(text) && !/"error"\s*:/.test(text) : !!(json && Array.isArray(json.choices) && json.choices[0] && json.choices[0].message);
    errorShape = stream ? /"error"\s*:/.test(text) : !!(json && json.error && json.error.code === "moorai_policy_denied");
  } else if (def.api === "anthropic") {
    okShape = !!(json && json.type === "message" && Array.isArray(json.content));
    errorShape = !!(json && json.type === "error" && json.error && json.error.type === "permission_error");
  } else if (def.api === "ollama") {
    okShape = !!(json && json.message && typeof json.message === "object");
    errorShape = !!(json && typeof json.error === "string");
  } else if (def.api === "responses") {
    okShape = !!(json && (json.object === "response" || Array.isArray(json.output)));
    errorShape = !!(json && json.error && (json.error.code === "moorai_policy_denied" || typeof json.error.message === "string"));
  }
  return { status, okShape, errorShape, doneMarker: /data: \[DONE\]/.test(text), toolCallReleased: toolCallIn(text) };
}

export function judgeServerCase(def, o) {
  const u = o.upstream || { requests: 0, markerSeen: false, toolCallSeen: false };
  const blocked = (o.alerts || []).find(isBlocked) || null;
  const checks = { reachedUpstream: u.requests > 0, upstreamSawMarker: !!u.markerSeen, modelMadeToolCall: !!u.toolCallSeen, toolCallReleased: !!o.toolCallReleased, clientShapeOk: !!o.okShape, refusalShapeOk: !!o.errorShape, alertSeen: !!blocked };
  let observed, status;
  if (def.kind === "allow" || def.kind === "stream-allow") {
    observed = o.status === 200 && o.okShape ? "forward" : o.status === 403 ? "refuse" : "none";
    status = o.status === 200 && o.okShape && u.requests > 0 && (def.kind !== "stream-allow" || !!o.doneMarker) ? "pass" : "fail";
  } else if (def.kind === "deny") {
    observed = !u.markerSeen && o.status === 403 ? "refuse" : u.markerSeen ? "forward" : "none";
    status = o.status === 403 && o.errorShape && !u.markerSeen && !!blocked ? "pass" : "fail";
  } else if (def.kind === "withhold") {
    if (!u.toolCallSeen) { observed = "none"; status = "inconclusive"; }
    else {
      observed = o.toolCallReleased ? "forward" : "withhold";
      status = !o.toolCallReleased && (o.status === 403 || o.errorShape) && !!blocked ? "pass" : "fail";
    }
  } else {
    observed = u.markerSeen ? "unscanned" : o.status === 403 ? "refuse" : "none";
    status = observed === "unscanned" ? "gap" : observed === "refuse" && !!blocked ? "pass" : "fail";
  }
  return { id: def.id, surface: "model-proxy", expect: EXPECT[def.kind], observed, status, checks, alert: blocked ? pickAlert(blocked) : null };
}

function startProxy(home, args, env) {
  return new Promise((resolve, reject) => {
    const c = spawn(process.execPath, [PROXY, "--port", "0", ...args], { cwd: home, env, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    const t = setTimeout(() => { c.kill(); reject(new Error(`model proxy did not start: ${err.slice(0, 300)}`)); }, 20000);
    c.stderr.on("data", (d) => { err += d; });
    c.stdout.on("data", (d) => {
      out += d;
      const nl = out.indexOf("\n");
      if (nl < 0 || t._done) return;
      t._done = true;
      clearTimeout(t);
      resolve({ ...JSON.parse(out.slice(0, nl)), stop: () => new Promise((r) => { if (c.exitCode !== null) return r(); c.once("close", r); c.kill("SIGTERM"); }) });
    });
    c.on("close", (code) => { clearTimeout(t); if (!t._done) reject(new Error(`model proxy exited ${code}: ${err.slice(0, 300)}`)); });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function getJson(url) {
  try { const r = await fetch(url, { signal: AbortSignal.timeout(5000) }); return r.ok ? await r.json() : null; } catch { return null; }
}

export const MODEL_PROXY_TARGET = { kind: "provider-api", id: "model-proxy-ollama", label: "MoorAI model proxy with Ollama" };

// ctx: { upstream, model, scratch, timeoutMs }
export async function runModelProxyTarget(ctx) {
  const ver = await getJson(`${ctx.upstream}/api/version`);
  const tags = await getJson(`${ctx.upstream}/api/tags`);
  const names = tags && Array.isArray(tags.models) ? tags.models.map((m) => m.name) : [];
  const model = ctx.model ? (names.includes(ctx.model) ? ctx.model : null) : PREFERRED_MODELS.find((m) => names.includes(m)) || null;
  if (!ver || !model) return { ...MODEL_PROXY_TARGET, version: ver && ver.version, ran: false, model: "ollama", reason: "model-unavailable", cases: [] };

  const con = await startStandInConsole({ policy: PROXY_POLICY });
  const rec = await startUpstreamRecorder({ upstream: ctx.upstream, marker: FAKE_AWS_KEY });
  const home = mkdtempSync(join(ctx.scratch, "model-proxy-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  const pf = join(home, "policy.json");
  writeFileSync(pf, JSON.stringify(PROXY_POLICY));
  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MOORAI_SERVICE_ID: "conformance-proxy", MOORAI_SERVER_URL: con.url, MOORAI_TENANT: con.tenant, MOORAI_INSTALL_TOKEN: "conformance" };
  let px;
  const cases = [];
  try {
    px = await startProxy(home, ["--mode", "enforce", "--policy-file", pf, "--route", `/openai=${rec.url}/v1`, "--route", `/anthropic=${rec.url}`, "--route", `/ollama=${rec.url}`], env);
    for (const def of SERVER_CASES) {
      const n0 = con.alerts.length, l0 = rec.log.length;
      const started = Date.now();
      let status = 0, ct = "", text = "";
      try {
        const r = await fetch(`${px.listening}${def.path}`, { method: "POST", headers: { "content-type": "application/json", ...(def.headers || {}) }, body: JSON.stringify(def.body(model)), signal: AbortSignal.timeout(ctx.timeoutMs || 300000) });
        status = r.status; ct = r.headers.get("content-type") || ""; text = await r.text();
      } catch { status = 0; }
      const latencyMs = Date.now() - started;
      const want = def.kind === "deny" || def.kind === "withhold" || def.kind === "unscanned";
      const end = Date.now() + (want ? 6000 : 300);
      while (Date.now() < end && !con.alerts.slice(n0).some(isBlocked)) await sleep(150);
      const slice = rec.log.slice(l0);
      const upstream = { requests: slice.length, markerSeen: slice.some((e) => e.markerSeen), toolCallSeen: slice.some((e) => e.toolCallSeen) };
      cases.push({ ...judgeServerCase(def, { ...readResponse(def, status, ct, text), upstream, alerts: con.alerts.slice(n0) }), latencyMs });
    }
  } finally {
    if (px) await px.stop();
    await rec.close();
    await con.close();
  }
  return { ...MODEL_PROXY_TARGET, version: ver.version, ran: true, model: "ollama", modelName: model, cases };
}
