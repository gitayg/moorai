// Where the model's reply TEXT is, per API, for response text scanning (response-scan.mjs, text-guard.mjs).
// Each codec reads a parsed body or stream event and hands back setters, so a masked text goes back into the
// same field of the same object. What is read:
//   Anthropic         body content[] text blocks; stream content_block_delta text_delta (a block is a channel,
//                     ended by its content_block_stop or by message_delta / message_stop), a text
//                     content_block_start's text, and message_start's content.
//   OpenAI chat       body choices[].message.content; stream choices[].delta.content (a choice is a channel,
//                     ended by its finish_reason or by [DONE]).
//   OpenAI Responses  body output[] message items' output_text parts; stream response.output_text.delta (an
//                     item's content part is a channel, ended by .output_text.done / .content_part.done /
//                     .output_item.done / the terminal event), and the complete text the stream repeats in
//                     .output_text.done, .content_part.added / .done, .output_item.added / .done and
//                     response.created / .in_progress / .completed / .incomplete / .failed.
//   Gemini            candidates[].content.parts[].text (not `thought` parts), body or SSE chunk (a candidate is
//                     a channel, ended by its finishReason; a stream has no terminator, so the end of the
//                     connection ends every channel). A JSON-array body (streamGenerateContent without alt=sse)
//                     is read as a body.
//   Ollama            /api/chat message.content, /api/generate response, body or NDJSON line (ended by done).
// Not read: reasoning the model returns beside its answer (Anthropic thinking, Gemini thought parts, Ollama
// thinking, Responses reasoning items), refusal fields, tool-call arguments (decided by check.mjs), Anthropic
// citations[].cited_text, Gemini executableCode / codeExecutionResult parts and OpenAI audio.transcript.
// logprobs(obj) REMOVES the token log-probabilities a client can ask for, which repeat the reply text token by
// token (and their top alternatives): OpenAI Chat choices[].logprobs → null; Responses `logprobs` on text
// deltas, .done events and output_text parts (in parts, items and whole responses) → []; Gemini
// candidates[].logprobsResult → removed (avgLogprobs, one number, stays); Ollama `logprobs` → removed.
// Returns whether anything was removed. Mask / block call it on every event and body (text-guard.mjs), so a
// masked or held secret never leaves through them; report mode never changes a byte.
// flush(ch, text, tmpl) builds the event that carries a channel's held text when the event that ends the
// channel has no text of its own: the API's own delta shape, metadata from the channel's last text event
// (tmpl, or none). A Responses flush repeats that event's sequence_number: a fresh number cannot be made
// without renumbering every later event, which the provider has already numbered. The OpenAI Node SDK reads
// the field only to skip events at or below a resume point (openai 4.104.0, lib/responses/ResponseStream.js:
// `starting_after == null || event.sequence_number > starting_after`), and a resumed stream (GET
// …/responses/{id}?stream=true) is not a parsed path here, so a flush is never skipped by it.
import { candidatesOf, partsOf, indexOf, finishOf } from "./gemini.mjs";

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const piece = (ch, obj, key) => ({ ch, text: obj[key], set: (t) => { obj[key] = t; } });
// Removes o[key] (empty undefined) or sets it to `empty`; true when there was something to remove.
const drop = (o, key, empty) => {
  if (!isObj(o) || o[key] == null || (Array.isArray(o[key]) && o[key].length === 0)) return false;
  if (empty === undefined) delete o[key]; else o[key] = empty;
  return true;
};
const any = (list, f) => list.reduce((acc, x) => f(x) || acc, false);
const arr = (v) => (Array.isArray(v) ? v : []);
const sse = (type, data) => Buffer.from(`${type ? `event: ${type}\n` : ""}data: ${JSON.stringify(data)}\n\n`);

function anthropicBody(b) {
  return (isObj(b) && Array.isArray(b.content) ? b.content : []).filter((x) => isObj(x) && x.type === "text" && typeof x.text === "string").map((x) => piece("", x, "text"));
}
export const anthropic = {
  body: anthropicBody,
  pieces(d) {
    if (d.type === "content_block_delta" && isObj(d.delta) && d.delta.type === "text_delta" && typeof d.delta.text === "string") return [piece(`b${d.index}`, d.delta, "text")];
    if (d.type === "content_block_start" && isObj(d.content_block) && d.content_block.type === "text" && typeof d.content_block.text === "string" && d.content_block.text) return [piece(`b${d.index}`, d.content_block, "text")];
    return [];
  },
  wholes: (d) => (d.type === "message_start" && isObj(d.message) ? anthropicBody(d.message) : []),
  ends(d, ev, open) {
    if (!d) return [];
    if (d.type === "content_block_stop") return [`b${d.index}`];
    return d.type === "message_delta" || d.type === "message_stop" ? open : [];
  },
  flush: (ch, text) => sse("content_block_delta", { type: "content_block_delta", index: Number(ch.slice(1)), delta: { type: "text_delta", text } }),
  logprobs: () => false
};

export const openaiChat = {
  body: (b) => (isObj(b) && Array.isArray(b.choices) ? b.choices : []).filter((c) => isObj(c) && isObj(c.message) && typeof c.message.content === "string").map((c) => piece("", c.message, "content")),
  pieces: (d) => (Array.isArray(d.choices) ? d.choices : []).filter((c) => isObj(c) && isObj(c.delta) && typeof c.delta.content === "string").map((c) => piece(`c${c.index}`, c.delta, "content")),
  wholes: () => [],
  ends(d, ev, open) {
    if (ev.data === "[DONE]") return open;
    return d && Array.isArray(d.choices) ? d.choices.filter((c) => isObj(c) && c.finish_reason).map((c) => `c${c.index}`) : [];
  },
  flush: (ch, text, t) => sse(null, { id: t && t.id, object: "chat.completion.chunk", created: t && t.created, model: t && t.model, choices: [{ index: Number(ch.slice(1)), delta: { content: text }, logprobs: null, finish_reason: null }] }),
  logprobs: (d) => any(isObj(d) ? arr(d.choices) : [], (c) => drop(c, "logprobs", null))
};

const outputTexts = (item) => (isObj(item) && item.type === "message" && Array.isArray(item.content) ? item.content.filter((p) => isObj(p) && p.type === "output_text" && typeof p.text === "string").map((p) => piece("", p, "text")) : []);
const responseTexts = (r) => (isObj(r) && Array.isArray(r.output) ? r.output.flatMap(outputTexts) : []);
const partsLp = (item) => (isObj(item) ? any(arr(item.content), (p) => drop(p, "logprobs", [])) : false);
const responseLp = (r) => (isObj(r) ? any(arr(r.output), partsLp) : false);
const WHOLE_RESPONSE = new Set(["response.created", "response.in_progress", "response.completed", "response.incomplete", "response.failed"]);
const TERMINAL = new Set(["response.completed", "response.incomplete", "response.failed"]);
export const openaiResponses = {
  body: responseTexts,
  pieces: (d) => (d.type === "response.output_text.delta" && typeof d.delta === "string" ? [piece(`${d.item_id}:${d.content_index}`, d, "delta")] : []),
  wholes(d) {
    if (d.type === "response.output_text.done" && typeof d.text === "string") return [piece("", d, "text")];
    if ((d.type === "response.content_part.added" || d.type === "response.content_part.done") && isObj(d.part) && d.part.type === "output_text" && typeof d.part.text === "string") return [piece("", d.part, "text")];
    if (d.type === "response.output_item.added" || d.type === "response.output_item.done") return outputTexts(d.item);
    return WHOLE_RESPONSE.has(d.type) ? responseTexts(d.response) : [];
  },
  ends(d, ev, open) {
    if (!d) return ev.data === "[DONE]" ? open : [];
    if (d.type === "response.output_text.done" || d.type === "response.content_part.done") return [`${d.item_id}:${d.content_index}`];
    if (d.type === "response.output_item.done" && isObj(d.item)) return open.filter((k) => k.startsWith(`${d.item.id}:`));
    return TERMINAL.has(d.type) ? open : [];
  },
  flush(ch, text, t) {
    const i = ch.lastIndexOf(":");
    const { logprobs, ...meta } = isObj(t) ? t : {};
    return sse("response.output_text.delta", { ...meta, type: "response.output_text.delta", item_id: ch.slice(0, i), content_index: Number(ch.slice(i + 1)), delta: text, ...(logprobs !== undefined ? { logprobs: [] } : {}) });
  },
  // A body is a response object; an event carries them on itself, its part, its item or its response.
  logprobs: (d) => isObj(d) && [drop(d, "logprobs", []), isObj(d.part) && drop(d.part, "logprobs", []), partsLp(d.item), responseLp(d.response), responseLp(d)].some(Boolean)
};

const geminiParts = (r, chOf) => candidatesOf(r).flatMap((c, i) => (isObj(c) ? partsOf(c.content).filter((p) => isObj(p) && typeof p.text === "string" && p.thought !== true).map((p) => piece(chOf(c, i), p, "text")) : []));
export const gemini = {
  body: (b) => (Array.isArray(b) ? b : [b]).flatMap((r) => geminiParts(r, () => "")),
  pieces: (d) => geminiParts(d, (c, i) => `g${indexOf(c, i)}`),
  wholes: () => [],
  ends: (d) => (d ? candidatesOf(d).map((c, i) => (isObj(c) && finishOf(c) ? `g${indexOf(c, i)}` : null)).filter(Boolean) : []),
  flush: (ch, text, t) => sse(null, { candidates: [{ index: Number(ch.slice(1)), content: { role: "model", parts: [{ text }] } }], ...(isObj(t) && t.modelVersion ? { modelVersion: t.modelVersion } : {}), ...(isObj(t) && t.responseId ? { responseId: t.responseId } : {}) }),
  logprobs: (b) => any(Array.isArray(b) ? b : [b], (r) => any(candidatesOf(r), (c) => drop(c, "logprobsResult")))
};

const ollamaPieces = (d, prefix) => [
  ...(isObj(d.message) && typeof d.message.content === "string" ? [piece(`${prefix}m`, d.message, "content")] : []),
  ...(typeof d.response === "string" ? [piece(`${prefix}r`, d, "response")] : [])
];
export const ollama = {
  body: (b) => (isObj(b) ? ollamaPieces(b, "") : []),
  pieces: (d) => ollamaPieces(d, ""),
  wholes: () => [],
  ends: (d, ev, open) => (d && d.done === true ? open : []),
  flush: (ch, text, t) => Buffer.from(`${JSON.stringify({ model: isObj(t) ? t.model : undefined, created_at: isObj(t) ? t.created_at : undefined, ...(ch === "m" ? { message: { role: "assistant", content: text } } : { response: text }), done: false })}\n`),
  logprobs: (d) => drop(d, "logprobs")
};
