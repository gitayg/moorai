// OpenAI Chat Completions (POST …/chat/completions), from the official OpenAPI description
// (github.com/openai/openai-openapi, read 2026-10-06; platform.openai.com refuses non-browser fetches).
// What this file knows:
//   request   `messages[]`: system / developer / user content is a string or text parts; a `tool` message
//             {role: "tool", content, tool_call_id} (and the deprecated `function` role) carries a tool's
//             result back to the model. Assistant turns are the model's own output and are not re-scanned.
//   response  choices[].message.tool_calls[] {id, type: "function", function: {name, arguments}} —
//             `arguments` is a JSON string the model wrote, "the model does not always generate valid
//             JSON"; the deprecated choices[].message.function_call has the same {name, arguments}.
//   stream    "data-only server-sent events … terminated by a `data: [DONE]` message"; each chunk is a
//             chat.completion.chunk whose choices[].delta.tool_calls[] are ChatCompletionMessageToolCallChunk
//             {index (required), id, type, function: {name, arguments}} — `arguments` arrives in fragments;
//             a choice is complete at its finish_reason ("tool_calls" when the model called a tool).
//   errors    ErrorResponse {error: {message, type, param, code}}. Mid-stream there is no documented error
//             event; the official SDK (openai-node src/core/streaming.ts) throws on any chunk with `error`.
export const NAME = "openai";

const texts = (content) => {
  if (typeof content === "string") return [content];
  if (!Array.isArray(content)) return [];
  return content.filter((p) => p && p.type === "text" && typeof p.text === "string").map((p) => p.text);
};
const PROMPT_ROLES = new Set(["system", "developer", "user"]);
const RESULT_ROLES = new Set(["tool", "function"]);

export function outboundItems(body) {
  const out = [];
  for (const m of Array.isArray(body && body.messages) ? body.messages : []) {
    if (!m || typeof m !== "object") continue;
    const t = texts(m.content).join("\n");
    if (!t) continue;
    if (PROMPT_ROLES.has(m.role)) out.push({ kind: m.role === "user" ? "prompt" : "system", stage: "prompt", ctx: {}, text: t });
    else if (RESULT_ROLES.has(m.role)) out.push({ kind: "tool_result", stage: "output", ctx: { inbound: true }, text: t });
  }
  return out;
}

const parse = (s) => { try { return JSON.parse(s); } catch { return null; } };
function fromArgs(id, name, args, over = false) {
  const p = typeof args === "string" ? parse(args) : null;
  const ok = p && typeof p === "object" && !Array.isArray(p);
  return { id: String(id || ""), name: String(name || ""), input: ok ? p : {}, raw: ok || !args ? null : String(args), over };
}

export function responseToolCalls(body) {
  const out = [];
  for (const c of Array.isArray(body && body.choices) ? body.choices : []) {
    const m = c && c.message;
    if (!m) continue;
    for (const tc of Array.isArray(m.tool_calls) ? m.tool_calls : []) if (tc && tc.function) out.push(fromArgs(tc.id, tc.function.name, tc.function.arguments));
    if (m.function_call) out.push(fromArgs("", m.function_call.name, m.function_call.arguments));
  }
  return out;
}

const ERROR_TYPES = { 403: "permission_error", 413: "invalid_request_error", 502: "server_error", 529: "server_error", 503: "server_error", 400: "invalid_request_error", 404: "invalid_request_error", 401: "invalid_request_error" };
export function errorBody(status, message) {
  return { error: { message, type: ERROR_TYPES[status] || "server_error", param: null, code: status === 403 ? "moorai_policy_denied" : null } };
}
export function streamError(status, message) {
  return Buffer.from(`data: ${JSON.stringify(errorBody(status, message))}\n\n`);
}

// The streaming state machine. Chunks are released as they arrive until the first chunk that carries a
// tool_calls (or function_call) delta; from there every chunk is held, in order, until each choice that
// started a tool call has sent its finish_reason (or [DONE] / end of stream arrives). The accumulated calls
// are then decided together: all allowed → the held chunks are released byte-identical; any denied →
// refused. Observe mode (report-only) never holds and never awaits a decision.
export function createStream({ enforce, decide, maxHold }) {
  let hold = null;
  async function release(extra = []) {
    const h = hold; hold = null;
    const list = [...h.calls.values()].map((c) => fromArgs(c.id, c.name, c.args, c.over || h.over));
    if (!enforce) { decide(list).catch(() => {}); return { out: [] }; }
    const v = await decide(list);
    return v.decision === "deny" ? { refuse: v } : { out: [...h.raw, ...extra] };
  }
  async function onEvent(ev) {
    if (ev.data === "[DONE]") return hold ? release([ev.raw]) : { out: [ev.raw] };
    const d = parse(ev.data);
    const choices = d && Array.isArray(d.choices) ? d.choices : [];
    const starts = choices.some((c) => c && c.delta && ((Array.isArray(c.delta.tool_calls) && c.delta.tool_calls.length) || c.delta.function_call));
    if (!hold && !starts) return { out: [ev.raw] };
    if (!hold) hold = { calls: new Map(), open: new Set(), finished: false, raw: [], bytes: 0, over: false };
    if (enforce) {
      hold.raw.push(ev.raw);
      hold.bytes += ev.raw.length;
      if (hold.bytes > maxHold) { hold.over = true; return release(); }
    }
    for (const c of choices) {
      if (!c || typeof c !== "object") continue;
      const add = (key, id, name, args) => {
        const e = hold.calls.get(key) || { id: "", name: "", args: "", over: false };
        if (id && !e.id) e.id = String(id);
        if (typeof name === "string" && name && !e.name) e.name = name;
        if (typeof args === "string") { if (e.args.length + args.length > maxHold) e.over = true; else e.args += args; }
        hold.calls.set(key, e);
        hold.open.add(c.index);
      };
      if (hold.calls.size < 128) {
        for (const tc of Array.isArray(c.delta && c.delta.tool_calls) ? c.delta.tool_calls : []) if (tc) add(`${c.index}:${tc.index}`, tc.id, tc.function && tc.function.name, tc.function && tc.function.arguments);
        if (c.delta && c.delta.function_call) add(`${c.index}:fc`, "", c.delta.function_call.name, c.delta.function_call.arguments);
      } else hold.over = true;
      if (c.finish_reason && hold.open.has(c.index)) { hold.open.delete(c.index); hold.finished = true; }
    }
    if (hold.finished && hold.open.size === 0) return release();
    return { out: [] };
  }
  // The upstream ended while a choice's tool call was still open: decided for the report, never released
  // in enforce mode, whatever that decision is.
  async function onEnd() {
    if (!hold) return { out: [] };
    const name = [...hold.calls.values()].map((c) => c.name).find(Boolean) || "";
    const r = await release();
    return enforce ? { refuse: { decision: "deny", denied: [{ name, reasons: ["the stream ended inside the tool call"] }] } } : r;
  }
  return { onEvent, onEnd, get holding() { return hold !== null; } };
}
