// Reply-text fixtures for the response text scanning tests (test/model-proxy-response-scan.test.mjs): per API,
// a request carrying a system prompt, a non-streaming reply with `text`, a streamed reply with `text` cut into
// `step`-character deltas (so a match is split across events, and sendSse / sendNdjson split every event
// across network chunks too), and the text a client reassembles from what it received.
import { anthropicMessage, openaiCompletion, sendJson, sendSse } from "./fake-provider.mjs";
import { geminiResponse, MODEL_VERSION } from "./fake-gemini.mjs";
import { chatResponse, generateResponse, sendNdjson, MODEL } from "./fake-ollama.mjs";
import { responsesBody } from "./responses-fixtures.mjs";

const pieces = (text, step) => { const out = []; for (let i = 0; i < text.length; i += step) out.push(text.slice(i, i + step)); return out; };
const sse = (type, d) => `${type ? `event: ${type}\n` : ""}data: ${JSON.stringify(d)}\n\n`;
const line = (o) => `${JSON.stringify(o)}\n`;
const sseData = (raw) => raw.toString("utf8").split(/\r?\n\r?\n/).filter((b) => b.trim()).map((b) => {
  let event = null; const data = [];
  for (const l of b.split(/\r?\n/)) { if (l.startsWith("event:")) event = l.slice(6).trim(); else if (l.startsWith("data:")) data.push(l.slice(5).replace(/^ /, "")); }
  return { event, data: data.join("\n") };
});
const json = (s) => { try { return JSON.parse(s); } catch { return null; } };
const T0 = "2026-10-12T13:06:51.290328Z";

export const API = {
  anthropic: {
    path: "/anthropic/v1/messages",
    body: (sys, user, stream) => ({ model: "claude-fake", max_tokens: 64, ...(stream ? { stream: true } : {}), system: sys, messages: [{ role: "user", content: user }] }),
    reply: (text) => anthropicMessage({ text }),
    stream(text, step) {
      const out = [sse("message_start", { type: "message_start", message: { id: "msg_t", type: "message", role: "assistant", model: "claude-fake", content: [], stop_reason: null, usage: { input_tokens: 1, output_tokens: 1 } } }),
        sse("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } })];
      for (const p of pieces(text, step)) out.push(sse("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: p } }));
      out.push(sse("content_block_stop", { type: "content_block_stop", index: 0 }), sse("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 9 } }), sse("message_stop", { type: "message_stop" }));
      return out;
    },
    bodyText: (j) => j.content.filter((b) => b.type === "text").map((b) => b.text).join(""),
    streamText: (raw) => sseData(raw).map((e) => json(e.data)).filter(Boolean).map((d) => (d.type === "content_block_delta" && d.delta.type === "text_delta" ? d.delta.text : d.type === "content_block_start" && d.content_block.type === "text" ? d.content_block.text : "")).join(""),
    streamError: (raw) => sseData(raw).some((e) => e.event === "error")
  },
  openai: {
    path: "/openai/chat/completions",
    body: (sys, user, stream) => ({ model: "gpt-fake", ...(stream ? { stream: true } : {}), messages: [{ role: "system", content: sys }, { role: "user", content: user }] }),
    reply: (text) => openaiCompletion({ text }),
    stream(text, step) {
      const c = (choices) => sse(null, { id: "chatcmpl-t", object: "chat.completion.chunk", created: 1759700000, model: "gpt-fake", choices });
      const out = [c([{ index: 0, delta: { role: "assistant", content: "" }, logprobs: null, finish_reason: null }])];
      for (const p of pieces(text, step)) out.push(c([{ index: 0, delta: { content: p }, logprobs: null, finish_reason: null }]));
      out.push(c([{ index: 0, delta: {}, logprobs: null, finish_reason: "stop" }]), "data: [DONE]\n\n");
      return out;
    },
    bodyText: (j) => j.choices[0].message.content,
    streamText: (raw) => sseData(raw).map((e) => json(e.data)).filter((d) => d && Array.isArray(d.choices)).map((d) => d.choices.map((c) => (c.delta && typeof c.delta.content === "string" ? c.delta.content : "")).join("")).join(""),
    streamError: (raw) => sseData(raw).some((e) => { const d = json(e.data); return d && d.error; })
  },
  responses: {
    path: "/openai/responses",
    body: (sys, user, stream) => ({ model: "gpt-fake", ...(stream ? { stream: true } : {}), instructions: sys, input: user }),
    reply: (text) => responsesBody({ text }),
    stream(text, step) {
      let n = 0;
      const e = (d) => sse(d.type, { ...d, sequence_number: n++ });
      const msg = (t, status) => ({ type: "message", id: "msg_t", status, role: "assistant", content: t == null ? [] : [{ type: "output_text", text: t, annotations: [] }] });
      const resp = (status, output) => ({ id: "resp_t", object: "response", created_at: 1759700000, status, model: "gpt-fake", output });
      const out = [e({ type: "response.created", response: resp("in_progress", []) }), e({ type: "response.output_item.added", output_index: 0, item: msg(null, "in_progress") }),
        e({ type: "response.content_part.added", item_id: "msg_t", output_index: 0, content_index: 0, part: { type: "output_text", text: "", annotations: [] } })];
      for (const p of pieces(text, step)) out.push(e({ type: "response.output_text.delta", item_id: "msg_t", output_index: 0, content_index: 0, delta: p, logprobs: [] }));
      out.push(e({ type: "response.output_text.done", item_id: "msg_t", output_index: 0, content_index: 0, text, logprobs: [] }),
        e({ type: "response.content_part.done", item_id: "msg_t", output_index: 0, content_index: 0, part: { type: "output_text", text, annotations: [] } }),
        e({ type: "response.output_item.done", output_index: 0, item: msg(text, "completed") }),
        e({ type: "response.completed", response: resp("completed", [msg(text, "completed")]) }));
      return out;
    },
    bodyText: (j) => j.output.filter((i) => i.type === "message").flatMap((i) => i.content).map((p) => p.text).join(""),
    streamText: (raw) => sseData(raw).map((e) => json(e.data)).filter(Boolean).map((d) => (d.type === "response.output_text.delta" ? d.delta : "")).join(""),
    // Every complete copy of the text the stream repeats (.done, part, item, completed): each must be masked too.
    streamWholes: (raw) => sseData(raw).map((e) => json(e.data)).filter(Boolean).flatMap((d) => d.type === "response.output_text.done" ? [d.text] : d.type === "response.content_part.done" ? [d.part.text] : d.type === "response.output_item.done" ? d.item.content.map((p) => p.text) : d.type === "response.completed" ? d.response.output.flatMap((i) => i.content.map((p) => p.text)) : []),
    streamError: (raw) => sseData(raw).some((e) => e.event === "error")
  },
  gemini: {
    path: (stream) => `/gemini/v1beta/models/gemini-fake:${stream ? "streamGenerateContent?alt=sse" : "generateContent"}`,
    body: (sys, user) => ({ systemInstruction: { parts: [{ text: sys }] }, contents: [{ role: "user", parts: [{ text: user }] }] }),
    reply: (text) => geminiResponse({ text }),
    stream(text, step) {
      const c = (parts, extra = {}) => sse(null, { candidates: [{ content: { role: "model", parts }, index: 0, ...extra }], modelVersion: MODEL_VERSION, responseId: "resp_t" });
      return [...pieces(text, step).map((p) => c([{ text: p }])), c([{ text: "" }], { finishReason: "STOP" })];
    },
    bodyText: (j) => j.candidates[0].content.parts.map((p) => p.text || "").join(""),
    streamText: (raw) => sseData(raw).map((e) => json(e.data)).filter((d) => d && d.candidates).map((d) => d.candidates.flatMap((c) => (c.content ? c.content.parts : [])).map((p) => p.text || "").join("")).join(""),
    streamError: (raw) => /(^|\n)\{"error":/.test(raw.toString("utf8"))
  },
  ollamaChat: {
    path: "/ollama/api/chat",
    lines: true,
    body: (sys, user, stream) => ({ model: MODEL, stream, messages: [{ role: "system", content: sys }, { role: "user", content: user }] }),
    reply: (text) => chatResponse({ text }),
    stream: (text, step) => [...pieces(text, step).map((p) => line({ model: MODEL, created_at: T0, message: { role: "assistant", content: p }, done: false })), line({ model: MODEL, created_at: T0, message: { role: "assistant", content: "" }, done_reason: "stop", done: true })],
    bodyText: (j) => j.message.content,
    streamText: (raw) => raw.toString("utf8").split("\n").filter((l) => l.trim()).map(json).filter(Boolean).map((p) => (p.message ? p.message.content || "" : "")).join(""),
    streamError: (raw) => raw.toString("utf8").split("\n").some((l) => { const p = json(l); return p && p.error; })
  },
  ollamaGenerate: {
    path: "/ollama/api/generate",
    lines: true,
    body: (sys, user, stream) => ({ model: MODEL, stream, system: sys, prompt: user }),
    reply: (text) => generateResponse({ text }),
    stream: (text, step) => [...pieces(text, step).map((p) => line({ model: MODEL, created_at: T0, response: p, done: false })), line({ model: MODEL, created_at: T0, response: "", done: true, done_reason: "stop" })],
    bodyText: (j) => j.response,
    streamText: (raw) => raw.toString("utf8").split("\n").filter((l) => l.trim()).map(json).filter(Boolean).map((p) => p.response || "").join(""),
    streamError: (raw) => raw.toString("utf8").split("\n").some((l) => { const p = json(l); return p && p.error; })
  }
};
export const pathOf = (a, stream) => (typeof a.path === "function" ? a.path(stream) : a.path);

// The fake upstream's answer for one request: the reply for the API the path names, streamed when asked.
export function answer(fp, a, text, { stream, step = 7 }) {
  fp.on((r, res) => {
    if (!stream) return sendJson(res, a.reply(text));
    if (a.lines) return sendNdjson(res, a.stream(text, step), { slice: 5 });
    return sendSse(res, a.stream(text, step), { slice: 5 });
  });
}
