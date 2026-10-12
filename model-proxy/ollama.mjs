// Ollama's native API: POST …/api/chat and POST …/api/generate, from github.com/ollama/ollama docs/api.md,
// docs/api/streaming.mdx and docs/api/errors.mdx (read 2026-10-12), and Ollama 0.15.6 measured on loopback.
// What this file knows:
//   request   /api/chat: `messages[]` of {role: "system" | "user" | "assistant" | "tool", content, images,
//             tool_calls, tool_name}; a `tool` message carries a tool's result back ("add the name of the
//             tool that was executed to inform the model of the result"). Assistant turns are the model's
//             own output and are not re-scanned; `tools` (definitions) is not scanned, as for every API.
//             /api/generate: `prompt`, `suffix` ("the text after the model response"), `system` ("system
//             message to (overrides what is defined in the Modelfile)") and `template` ("the prompt
//             template to use"). /api/generate has no `tools`.
//   response  /api/chat: `message` {role, content, thinking, tool_calls}; a tool call is
//             `message.tool_calls[]` {function: {name, arguments}} with `arguments` an OBJECT
//             ({"city": "Tokyo"} in every documented example), not a JSON string. Ollama 0.15.6 also sends
//             `id` and `function.index` (measured: {"id":"call_uv3mxz1k","function":{"index":0,…}}); the id
//             is read when present. /api/generate: `response` (the generated text), `thinking`.
//   stream    "Certain API endpoints stream responses by default … newline-delimited JSON format (i.e. the
//             application/x-ndjson content type)"; "Streaming can be disabled by providing {"stream":
//             false}", which returns application/json. /api/chat and /api/generate stream by default. The
//             last object has `done: true` (and `done_reason`); a streamed chat tool call arrives whole,
//             arguments included, in a `done: false` line (docs example "Chat request (Streaming with
//             tools)", and measured on 0.15.6).
//   errors    {"error": "<message>"} with the HTTP status. "If an error occurs mid-stream, the error will be
//             returned as an object in the application/x-ndjson format with an error property"; both
//             official clients raise on a line with `error` (ollama-python _client.py: `if err :=
//             part.get('error'): raise ResponseError(err)`; ollama-js src/utils.ts: `if ('error' in
//             message) throw new Error(message.error)`).
export { replaceResponse, createReplaceStream } from "./ollama-replace.mjs";
import { parseArgs } from "./json-strict.mjs";
export const NAME = "ollama";
export const BUSY_STATUS = 503;
// The response bodies this API frames as NDJSON (server.mjs picks the line splitter for them).
export const NDJSON = true;

export const PATH_RE = /\/api\/(?:chat|generate)$/;
export const isPath = (path) => PATH_RE.test(path);

export const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const str = (v) => (typeof v === "string" ? v : "");
const parse = (s) => { try { return JSON.parse(s); } catch { return null; } };

// Ollama message content is a string; a list of text parts is read too (OpenAI-shaped clients).
const textOf = (content) => {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.filter((p) => isObj(p) && typeof p.text === "string").map((p) => p.text).join("\n");
};
const PROMPT_ROLES = new Set(["system", "user"]);

// [{ kind, stage, ctx, text }] — the content this request sends the model that MoorAI scans.
export function outboundItems(body) {
  const out = [];
  if (!isObj(body)) return out;
  for (const k of ["system", "template"]) if (str(body[k])) out.push({ kind: "system", stage: "prompt", ctx: {}, text: body[k] });
  for (const k of ["prompt", "suffix"]) if (str(body[k])) out.push({ kind: "prompt", stage: "prompt", ctx: {}, text: body[k] });
  for (const m of Array.isArray(body.messages) ? body.messages : []) {
    if (!isObj(m)) continue;
    const t = textOf(m.content);
    if (!t) continue;
    if (PROMPT_ROLES.has(m.role)) out.push({ kind: m.role === "user" ? "prompt" : "system", stage: "prompt", ctx: {}, text: t });
    else if (m.role === "tool") out.push({ kind: "tool_result", stage: "output", ctx: { inbound: true }, text: t });
  }
  return out;
}

// One tool call as check.mjs takes it. `arguments` is documented as an object; a JSON string is parsed (an
// OpenAI-shaped server; a string that is not strict JSON is kept raw too, json-strict.mjs); anything else is kept
// raw, so enforce refuses it.
export function toCall(tc, over = false) {
  const f = isObj(tc) && isObj(tc.function) ? tc.function : {};
  const a = f.arguments;
  const r = typeof a === "string" ? parseArgs(a) : { value: a, ok: isObj(a), rawReason: undefined, large: [] };
  const empty = a === undefined || a === null || a === "";
  return { id: str(tc && tc.id), name: str(f.name), input: r.ok ? r.value : {}, raw: r.ok || empty ? null : typeof a === "string" ? a : JSON.stringify(a), ...(r.rawReason ? { rawReason: r.rawReason } : {}), ...(r.large.length ? { numbers: r.large } : {}), over };
}
const callsOf = (d) => (isObj(d) && isObj(d.message) && Array.isArray(d.message.tool_calls) ? d.message.tool_calls : []);

export function responseToolCalls(body) {
  return callsOf(body).map((tc) => toCall(tc));
}

// The generated text of /api/generate, scanned report-only (server.mjs → checker.observe): the model's own
// output is never withheld by this proxy (no API's text is), but /api/generate has no structured tool calls,
// so its text is the only place one could be.
const completion = (text) => (text ? [{ kind: "completion", stage: "output", ctx: {}, text }] : []);
export function responseItems(body) {
  return completion(isObj(body) ? str(body.response) : "");
}

export function errorBody(status, message) {
  return { error: message };
}
export function streamError(status, message) {
  return Buffer.from(`${JSON.stringify(errorBody(status, message))}\n`);
}

// One held turn's tool calls. The caller counts every line of the turn against maxHold (blank lines
// included) and calls setOver() past it; from then on no call is kept, so what a turn retains is bounded by
// the held bytes, whatever the mode. At most 128 calls are kept; past that the turn is over the cap too. An
// over-cap turn always yields at least one call marked `over`, so it can never be decided as "no tool call"
// (an empty list is an allow).
export const MAX_CALLS = 128;
export function createCollector() {
  const calls = [];
  let over = false;
  return {
    add(d) {
      const tcs = callsOf(d);
      for (const tc of tcs) { if (over) break; if (calls.length >= MAX_CALLS) { over = true; break; } calls.push(tc); }
      return tcs.length > 0;
    },
    setOver() { over = true; },
    get over() { return over; },
    get count() { return calls.length; },
    list: () => (over && !calls.length ? [toCall({}, true)] : calls.map((tc) => toCall(tc, over)))
  };
}

// The generated text of /api/generate, for the report-only scan, and the response's byte budget: the text
// kept and the bytes of the turn being held share one maxHold. Text past it is not kept (the scan is marked
// `over`, which the checker reports unevaluated); a held turn past it is over the cap.
export function createBudget(maxHold) {
  let text = "", textOver = false;
  return {
    addText(t, held = 0) { if (textOver) return; if (text.length + t.length + held > maxHold) textOver = true; else text += t; },
    over: (held) => text.length + held > maxHold,
    get size() { return text.length; },
    // The generated text once, at the end of the stream.
    take() { const t = text; text = ""; return t ? [{ kind: "completion", stage: "output", ctx: {}, text: t, ...(textOver ? { over: true } : {}) }] : []; }
  };
}

const NOT_JSON = { decision: "deny", denied: [{ name: "stream", reasons: ["a stream line is not JSON; it was not released"] }] };
const OVER_CAP = { decision: "deny", denied: [{ name: "", reasons: ["the tool call's turn is over the hold cap"] }] };

// The streaming state machine. Lines are released as they arrive until the first line that carries
// message.tool_calls; from there every line is held, in order, until the `done: true` line. The turn's calls
// are then decided together: all allowed → the held lines are released byte-identical; any denied →
// refused. Observe mode (report-only) never holds bytes and never awaits a decision. In enforce mode a line
// that is not JSON is refused wherever it is (a lenient parser could read a tool call from it that this one
// cannot), and so is an upstream {error} line inside a held turn.
// BOUNDED. Every line of a held turn, blank ones included, counts against maxHold together with the
// generated text kept so far, in every mode; past it the turn is decided at once as over the cap (refused in
// enforce mode), its lines and calls are freed, and nothing past the cap is kept. Each turn gets its own
// collector, so a stream of many turns never accumulates calls.
export function createStream({ enforce, decide, maxHold, observe = () => {} }) {
  const budget = createBudget(maxHold);
  let hold = null, observed = false;
  const flush = () => { if (observed) return; observed = true; observe(budget.take()); };
  async function release() {
    const h = hold; hold = null;
    const list = h.col.list();
    if (!enforce) { decide(list).catch(() => {}); return { out: [] }; }
    const v = await decide(list);
    if (v.decision === "deny") return { refuse: v };
    return h.col.over ? { refuse: OVER_CAP } : { out: h.raw };
  }
  const firstName = () => hold.col.list().map((c) => c.name).find(Boolean) || "";
  async function onEvent(ev) {
    const blank = !ev.data.trim();
    const d = blank ? null : parse(ev.data);
    if (!blank && !isObj(d)) return enforce ? { refuse: NOT_JSON } : { out: [ev.raw] };
    if (d && d.error !== undefined && hold) {
      const name = firstName();
      if (!enforce) return release();
      await release().catch(() => {});
      return { refuse: { decision: "deny", denied: [{ name, reasons: ["the upstream sent an error inside the tool call's turn"] }] } };
    }
    if (d && typeof d.response === "string") budget.addText(d.response, hold ? hold.bytes : 0);
    if (!hold && !(d && callsOf(d).length)) {
      if (d && d.done === true) flush();
      return { out: [ev.raw] };
    }
    if (!hold) hold = { raw: [], bytes: 0, col: createCollector() };
    hold.bytes += ev.raw.length;
    if (budget.over(hold.bytes)) { hold.raw = []; hold.col.setOver(); if (d && d.done === true) flush(); return release(); }
    if (enforce) hold.raw.push(ev.raw);
    if (d) hold.col.add(d);
    if (d && d.done === true) { flush(); return release(); }
    return { out: [] };
  }
// The upstream ended before the `done` line of a turn that started a call: decided for the report, never
  // released in enforce mode, whatever that decision is.
  async function onEnd() {
    flush();
    if (!hold) return { out: [] };
    const name = firstName();
    const r = await release();
    return enforce ? { refuse: { decision: "deny", denied: [{ name, reasons: ["the stream ended inside the tool call's turn"] }] } } : r;
  }
  // What this response retains right now (tests measure the bound with it): held line bytes, kept calls and
  // kept text characters.
  const retained = () => ({ rawBytes: hold ? hold.raw.reduce((n, b) => n + b.length, 0) : 0, calls: hold ? hold.col.count : 0, textChars: budget.size });
  return { onEvent, onEnd, get holding() { return hold !== null; }, get retained() { return retained(); } };
}
