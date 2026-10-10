// Google Gemini generateContent / streamGenerateContent (POST …/models/{model}:generateContent, and the same
// method shape on Vertex AI), from ai.google.dev/api/generate-content and the Vertex AI REST reference
// (docs.cloud.google.com/vertex-ai/generative-ai/docs/reference/rest/v1/projects.locations.publishers.models/
// streamGenerateContent), read 2026-10-09. What this file knows:
//   request   `contents[]` of Content {role: "user" | "model", parts[]}, and `systemInstruction` ("Currently,
//             text only"). A Part is a union: text, inlineData, functionCall, functionResponse, fileData,
//             executableCode, codeExecutionResult, toolCall, toolResponse. A functionResponse {id, name,
//             response} is "The result output from a FunctionCall" — a tool result fed back to the model.
//             Model turns are the model's own output and are not re-scanned. Proto-JSON parsers take both
//             lowerCamelCase and the proto field names, and Google's Python SDK sends snake_case, so both
//             spellings are read.
//   response  GenerateContentResponse {candidates[], promptFeedback, usageMetadata, modelVersion, responseId};
//             a Candidate {content, finishReason, index, …}. A client tool call is a functionCall part
//             {id, name, args} ("The function parameters and values in JSON object format"). toolCall is "A
//             predicted server-side ToolCall … The client is NOT expected to execute this", and
//             executableCode runs at the provider: neither is decided here.
//   stream    "the response body contains a stream of GenerateContentResponse instances". With alt=sse (the
//             Google Gen AI SDKs always add it) each instance is one `data:` event; without it the body is
//             a JSON array, held whole like a non-streaming body. There is no terminator event: a stream
//             ends when the connection does, with the finishReason on the candidate's last chunk.
//             Vertex AI only: with streamFunctionCallArguments a call arrives as `partialArgs` pieces with
//             `willContinue` ("This field is not supported in Gemini API"). No assembly rule is documented,
//             so such a call is decided as unparsed arguments (refused in enforce mode).
//   errors    {error: {code, message, status}} (google.rpc.Status). Mid-stream there is no `data:` error
//             event: the Python SDK reads a bare JSON object "line by line" and raises on `{"error":`, and
//             the JS SDK raises on a read chunk that parses as an object with `error` (and on a stream that
//             ends with an incomplete segment).
export { replaceResponse, createReplaceStream } from "./gemini-replace.mjs";
export const NAME = "gemini";
// Gemini's retryable status for the proxy's own budget errors (Anthropic answers 529, OpenAI 503).
export const BUSY_STATUS = 503;

export const PATH_RE = /\/(?:models|tunedModels|endpoints)\/[^/]+:(?:generateContent|streamGenerateContent)$/;
// An escaped colon (`%3A`) reaches the same method upstream, so the path is matched decoded.
export function isPath(path) {
  let p = path;
  try { p = decodeURIComponent(path); } catch { p = path.replace(/%3a/gi, ":"); }
  return PATH_RE.test(p);
}

export const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const pick = (o, camel, snake) => (o[camel] !== undefined ? o[camel] : o[snake]);
export const fcOf = (part) => (isObj(part) ? pick(part, "functionCall", "function_call") : undefined);
export const partsOf = (content) => (isObj(content) && Array.isArray(content.parts) ? content.parts : []);
export const candidatesOf = (r) => (isObj(r) && Array.isArray(r.candidates) ? r.candidates : []);
// A candidate's index; absent means 0 (proto3 omits a zero) — the position is the fallback.
export const indexOf = (c, i) => (Number.isInteger(c && c.index) ? c.index : i);
export const finishOf = (c) => (isObj(c) ? pick(c, "finishReason", "finish_reason") : undefined);

const textsOf = (content) => {
  if (typeof content === "string") return [content];
  return partsOf(content).filter((p) => isObj(p) && typeof p.text === "string" && p.thought !== true).map((p) => p.text);
};
// The string leaves of a function response (its `response` object), in order, bounded.
function strings(v, out = [], depth = 0) {
  if (out.length >= 4096 || depth > 32) return out;
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) strings(x, out, depth + 1);
  else if (isObj(v)) for (const x of Object.values(v)) strings(x, out, depth + 1);
  return out;
}

// [{ kind, stage, ctx, text }] — the content this request sends the model that MoorAI scans.
export function outboundItems(body) {
  const out = [];
  if (!isObj(body)) return out;
  const sys = textsOf(pick(body, "systemInstruction", "system_instruction")).join("\n");
  if (sys) out.push({ kind: "system", stage: "prompt", ctx: {}, text: sys });
  const contents = body.contents;
  for (const c of Array.isArray(contents) ? contents : isObj(contents) ? [contents] : []) {
    if (!isObj(c) || c.role === "model") continue;
    const user = c.role == null || c.role === "user";
    for (const p of partsOf(c)) {
      if (!isObj(p)) continue;
      if (typeof p.text === "string" && p.text && p.thought !== true) out.push(user ? { kind: "prompt", stage: "prompt", ctx: {}, text: p.text } : { kind: "tool_result", stage: "output", ctx: { inbound: true }, text: p.text });
      const fr = pick(p, "functionResponse", "function_response");
      if (isObj(fr)) { const t = strings(fr.response).join("\n"); if (t) out.push({ kind: "tool_result", stage: "output", ctx: { inbound: true }, text: t }); }
    }
  }
  return out;
}

// One tool call from a functionCall, as check.mjs takes it. `partial` holds Vertex partialArgs pieces.
export function toCall(e, over = false) {
  if (e.partial) return { id: e.id, name: e.name, input: {}, raw: JSON.stringify({ args: e.args ?? null, partialArgs: e.partial }), rawReason: "streamed partial function-call arguments (partialArgs) are not parsed", over };
  const ok = isObj(e.args);
  return { id: e.id, name: e.name, input: ok ? e.args : {}, raw: ok || e.args === undefined || e.args === null ? null : JSON.stringify(e.args), over };
}
export function entryOf(fc) {
  const partial = pick(fc, "partialArgs", "partial_args");
  const cont = pick(fc, "willContinue", "will_continue") === true;
  return { id: String(fc.id || ""), name: typeof fc.name === "string" ? fc.name : "", args: fc.args, partial: Array.isArray(partial) || cont ? (Array.isArray(partial) ? [...partial] : []) : null, cont };
}

// Accumulates the function calls of a turn across stream chunks (or the elements of a JSON-array body).
// Vertex partialArgs pieces of one call (a functionCall with no name after one with willContinue) join it.
export function createCollector(maxHold) {
  const calls = [], started = new Set(), open = new Set(), cont = new Map();
  let over = false, finished = false;
  function add(r) {
    let starts = false;
    candidatesOf(r).forEach((c, i) => {
      if (!isObj(c)) return;
      const idx = indexOf(c, i);
      for (const p of partsOf(c.content)) {
        const fc = fcOf(p);
        if (!isObj(fc)) continue;
        starts = true;
        started.add(idx); open.add(idx);
        const prev = cont.get(idx);
        const e = entryOf(fc);
        if (prev && !e.name) {
          if (e.partial) prev.partial.push(...e.partial);
          if (JSON.stringify(prev.partial).length > maxHold) over = true;
          if (!e.cont) cont.delete(idx);
          continue;
        }
        if (calls.length >= 128) { over = true; continue; }
        calls.push(e);
        if (e.cont) cont.set(idx, e); else cont.delete(idx);
      }
      if (finishOf(c) && open.has(idx)) { open.delete(idx); finished = true; }
    });
    return starts;
  }
  return {
    add,
    // Every candidate that started a call has sent its finishReason, and no call is mid-way.
    get complete() { return finished && open.size === 0 && cont.size === 0; },
    get started() { return started; },
    setOver() { over = true; },
    list: () => calls.map((e) => toCall(e, over))
  };
}

export function responseToolCalls(body) {
  const c = createCollector(Infinity);
  for (const r of Array.isArray(body) ? body : [body]) c.add(r);
  return c.list();
}

const STATUS = { 400: "INVALID_ARGUMENT", 401: "UNAUTHENTICATED", 403: "PERMISSION_DENIED", 404: "NOT_FOUND", 413: "INVALID_ARGUMENT", 429: "RESOURCE_EXHAUSTED", 500: "INTERNAL", 502: "INTERNAL", 503: "UNAVAILABLE", 504: "DEADLINE_EXCEEDED" };
export function errorBody(status, message) {
  return { error: { code: status, message, status: STATUS[status] || "INTERNAL" } };
}
// A bare JSON object on its own line, the shape both Gen AI SDKs raise on mid-stream. Braces are kept out of
// the message: the Python SDK finds the object's end by counting them.
export function streamError(status, message) {
  return Buffer.from(`${JSON.stringify(errorBody(status, String(message).replace(/[{}]/g, (c) => (c === "{" ? "(" : ")"))))}\n`);
}

const parse = (s) => { try { return JSON.parse(s); } catch { return null; } };

// The streaming state machine (alt=sse). Events are released as they arrive until the first one carrying a
// functionCall part; from there every event is held, in order, until each candidate that started a call has
// sent its finishReason. The turn's calls are then decided together: all allowed → the held events are
// released byte-identical; any denied → refused. Observe mode (report-only) never holds and never awaits.
export function createStream({ enforce, decide, maxHold }) {
  let hold = null;
  async function release() {
    const h = hold; hold = null;
    const list = h.col.list();
    if (!enforce) { decide(list).catch(() => {}); return { out: [] }; }
    const v = await decide(list);
    return v.decision === "deny" ? { refuse: v } : { out: h.raw };
  }
  async function onEvent(ev) {
    const d = parse(ev.data);
    if (!hold) {
      if (!isObj(d) || !candidatesOf(d).some((c) => partsOf(c && c.content).some((p) => isObj(fcOf(p))))) return { out: [ev.raw] };
      hold = { col: createCollector(maxHold), raw: [], bytes: 0 };
    }
    if (enforce) {
      hold.raw.push(ev.raw);
      hold.bytes += ev.raw.length;
      if (hold.bytes > maxHold) { hold.col.add(d); hold.col.setOver(); return release(); }
    }
    if (isObj(d)) hold.col.add(d);
    return hold.col.complete ? release() : { out: [] };
  }
  // The upstream ended before every candidate that started a call sent its finishReason: decided for the
  // report, never released in enforce mode, whatever that decision is.
  async function onEnd() {
    if (!hold) return { out: [] };
    const name = hold.col.list().map((c) => c.name).find(Boolean) || "";
    const r = await release();
    return enforce ? { refuse: { decision: "deny", denied: [{ name, reasons: ["the stream ended inside the tool call's turn"] }] } } : r;
  }
  return { onEvent, onEnd, get holding() { return hold !== null; } };
}
