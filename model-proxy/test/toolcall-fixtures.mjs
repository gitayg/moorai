// Shared by test/model-proxy-toolcall*.test.mjs: streams whose tool calls are split as finely as SSE allows,
// and what an SDK builds from a stream, with the ordering rules it relies on asserted on the way.
import assert from "node:assert/strict";
import { sseEvents } from "./harness.mjs";

export const TEXT = "I will install it now.";
const sse = (type, data) => `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
const chunk = (choices) => `data: ${JSON.stringify({ id: "chatcmpl-tc01", object: "chat.completion.chunk", created: 1759700000, model: "gpt-fake", choices })}\n\n`;

// Streams whose tool-call arguments arrive ONE CHARACTER per delta event; sent in 1-byte slices, the call
// is split across hundreds of SSE events and thousands of TCP writes.
export function anthropicFine({ text = TEXT, tools = [] } = {}) {
  const out = [sse("message_start", { type: "message_start", message: { id: "msg_tc01", type: "message", role: "assistant", model: "claude-fake", content: [], stop_reason: null, usage: { input_tokens: 10, output_tokens: 1 } } }),
    sse("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }),
    sse("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text } }),
    sse("content_block_stop", { type: "content_block_stop", index: 0 })];
  tools.forEach((t, i) => {
    const idx = i + 1, json = JSON.stringify(t.input);
    out.push(sse("content_block_start", { type: "content_block_start", index: idx, content_block: { type: "tool_use", id: `toolu_tc${i}`, name: t.name, input: {} } }));
    out.push(sse("ping", { type: "ping" }));
    for (const ch of json) out.push(sse("content_block_delta", { type: "content_block_delta", index: idx, delta: { type: "input_json_delta", partial_json: ch } }));
    out.push(sse("content_block_stop", { type: "content_block_stop", index: idx }));
  });
  out.push(sse("message_delta", { type: "message_delta", delta: { stop_reason: tools.length ? "tool_use" : "end_turn", stop_sequence: null }, usage: { output_tokens: 42 } }));
  out.push(sse("message_stop", { type: "message_stop" }));
  return out;
}
export function openaiFine({ text = TEXT, tools = [] } = {}) {
  const out = [chunk([{ index: 0, delta: { role: "assistant", content: "" }, logprobs: null, finish_reason: null }]),
    chunk([{ index: 0, delta: { content: text }, logprobs: null, finish_reason: null }])];
  tools.forEach((t, i) => {
    out.push(chunk([{ index: 0, delta: { tool_calls: [{ index: i, id: `call_tc${i}`, type: "function", function: { name: t.name, arguments: "" } }] }, logprobs: null, finish_reason: null }]));
    for (const ch of JSON.stringify(t.input)) out.push(chunk([{ index: 0, delta: { tool_calls: [{ index: i, function: { arguments: ch } }] }, logprobs: null, finish_reason: null }]));
  });
  out.push(chunk([{ index: 0, delta: {}, logprobs: null, finish_reason: tools.length ? "tool_calls" : "stop" }]));
  out.push(`data: ${JSON.stringify({ id: "chatcmpl-tc01", object: "chat.completion.chunk", created: 1759700000, model: "gpt-fake", choices: [], usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 } })}\n\n`);
  out.push("data: [DONE]\n\n");
  return out;
}

// What an SDK builds from a stream, with the ordering rules it relies on asserted on the way.
export function accumulateAnthropic(raw) {
  const evs = sseEvents(raw);
  assert.equal(evs[0].event, "message_start");
  const content = [], open = new Set();
  let stop = null, done = false;
  for (const e of evs) {
    const d = JSON.parse(e.data);
    assert.equal(d.type, e.event, `event name and type agree: ${e.data.slice(0, 120)}`);
    assert.equal(done, false, "nothing after message_stop");
    if (d.type === "content_block_start") { assert.equal(d.index, content.length, "block indexes are contiguous"); content.push({ ...d.content_block, _json: "" }); open.add(d.index); }
    else if (d.type === "content_block_delta") {
      assert.ok(open.has(d.index), `delta for an open block ${d.index}`);
      if (d.delta.type === "text_delta") content[d.index].text += d.delta.text; else if (d.delta.type === "input_json_delta") content[d.index]._json += d.delta.partial_json;
    } else if (d.type === "content_block_stop") { assert.ok(open.delete(d.index), `stop for an open block ${d.index}`); const b = content[d.index]; if (b.type === "tool_use") b.input = JSON.parse(b._json || "{}"); }
    else if (d.type === "message_delta") { assert.equal(open.size, 0, "every block closed before message_delta"); stop = d.delta.stop_reason; }
    else if (d.type === "message_stop") done = true;
  }
  assert.ok(done, "the stream ends with message_stop");
  for (const b of content) delete b._json;
  return { content, stop_reason: stop };
}
export function accumulateOpenAI(raw) {
  const evs = sseEvents(raw);
  assert.equal(evs.at(-1).data, "[DONE]", "the stream ends with [DONE]");
  const choices = new Map();
  for (const e of evs.slice(0, -1)) {
    const d = JSON.parse(e.data);
    assert.ok(!d.error, `an error chunk: ${e.data}`);
    for (const c of d.choices) {
      const s = choices.get(c.index) || { content: "", tool_calls: [], finish_reason: null };
      if (typeof c.delta.content === "string") s.content += c.delta.content;
      for (const tc of c.delta.tool_calls || []) { const x = (s.tool_calls[tc.index] ||= { id: "", name: "", arguments: "" }); if (tc.id) x.id = tc.id; if (tc.function && tc.function.name) x.name = tc.function.name; if (tc.function && tc.function.arguments) x.arguments += tc.function.arguments; }
      if (c.finish_reason) { assert.equal(s.finish_reason, null, "one finish_reason per choice"); s.finish_reason = c.finish_reason; }
      choices.set(c.index, s);
    }
  }
  return choices;
}
// No orphan tool-call ids: the turn's stop reason and its tool calls agree, both ways.
export function assertConsistent(name, r) {
  if (name === "anthropic") {
    const tools = r.content.filter((b) => b.type === "tool_use");
    assert.equal(r.stop_reason === "tool_use", tools.length > 0, `stop_reason ${r.stop_reason} with ${tools.length} tool_use blocks`);
  } else {
    for (const [, c] of r) assert.equal(c.finish_reason === "tool_calls", c.tool_calls.length > 0, `finish_reason ${c.finish_reason} with ${c.tool_calls.length} tool calls`);
  }
}
