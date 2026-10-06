// A fake model provider for the model-proxy tests: the documented Anthropic Messages and OpenAI Chat
// Completions shapes, JSON and SSE, nothing real behind them and no real key anywhere. SSE is written in
// small slices (default 5 bytes) so the proxy's event splitting is exercised across chunk boundaries.
import http from "node:http";

export async function startFakeProvider() {
  const requests = [];
  let handler = (req, res) => { res.writeHead(500); res.end(); };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const r = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) };
      requests.push(r);
      handler(r, res);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    requests,
    on(fn) { handler = fn; },
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); })
  };
}

// Sends `body` (object → JSON) and returns the exact bytes written.
export function sendJson(res, body, { status = 200, headers = {} } = {}) {
  const bytes = Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  res.writeHead(status, { "content-type": "application/json", "content-length": bytes.length, "request-id": "req_fake_0001", ...headers });
  res.end(bytes);
  return bytes;
}

// Writes the SSE text in `slice`-byte pieces. `gateAfter` (event index) + `gate` (a promise) pause the
// stream after that event until the test releases it — to see what the client has received by then.
export async function sendSse(res, events, { slice = 5, gate, gateAfter = -1, status = 200 } = {}) {
  res.writeHead(status, { "content-type": "text/event-stream", "cache-control": "no-cache", "request-id": "req_fake_0002" });
  for (let i = 0; i < events.length; i++) {
    const b = Buffer.from(events[i]);
    for (let j = 0; j < b.length; j += slice) { if (res.destroyed) return; res.write(b.subarray(j, j + slice)); await new Promise((r) => setImmediate(r)); }
    if (i === gateAfter && gate) await gate;
  }
  res.end();
}

// --- Anthropic ----------------------------------------------------------------------------------------
export function anthropicMessage({ text = "Sure.", tools = [] } = {}) {
  return {
    id: "msg_fake01", type: "message", role: "assistant", model: "claude-fake",
    content: [{ type: "text", text }, ...tools.map((t, i) => ({ type: "tool_use", id: `toolu_fake${i}`, name: t.name, input: t.input }))],
    stop_reason: tools.length ? "tool_use" : "end_turn", stop_sequence: null, usage: { input_tokens: 10, output_tokens: 20 }
  };
}
const ev = (type, data) => `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
// The documented flow: message_start, per block start / delta… / stop, message_delta, message_stop, with a ping.
export function anthropicStream({ text = "Let me check that.", tools = [] } = {}) {
  const out = [ev("message_start", { type: "message_start", message: { id: "msg_fake02", type: "message", role: "assistant", model: "claude-fake", content: [], stop_reason: null, usage: { input_tokens: 10, output_tokens: 1 } } })];
  out.push(ev("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }));
  out.push(ev("ping", { type: "ping" }));
  const half = Math.ceil(text.length / 2);
  out.push(ev("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: text.slice(0, half) } }));
  out.push(ev("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: text.slice(half) } }));
  out.push(ev("content_block_stop", { type: "content_block_stop", index: 0 }));
  tools.forEach((t, i) => {
    const idx = i + 1, json = JSON.stringify(t.input);
    out.push(ev("content_block_start", { type: "content_block_start", index: idx, content_block: { type: "tool_use", id: `toolu_fake${i}`, name: t.name, input: {} } }));
    out.push(ev("content_block_delta", { type: "content_block_delta", index: idx, delta: { type: "input_json_delta", partial_json: "" } }));
    for (let j = 0; j < json.length; j += 7) out.push(ev("content_block_delta", { type: "content_block_delta", index: idx, delta: { type: "input_json_delta", partial_json: json.slice(j, j + 7) } }));
    out.push(ev("content_block_stop", { type: "content_block_stop", index: idx }));
  });
  out.push(ev("message_delta", { type: "message_delta", delta: { stop_reason: tools.length ? "tool_use" : "end_turn", stop_sequence: null }, usage: { output_tokens: 42 } }));
  out.push(ev("message_stop", { type: "message_stop" }));
  return out;
}

// --- OpenAI --------------------------------------------------------------------------------------------
export function openaiCompletion({ text = "Sure.", tools = [] } = {}) {
  return {
    id: "chatcmpl-fake01", object: "chat.completion", created: 1759700000, model: "gpt-fake",
    choices: [{ index: 0, message: { role: "assistant", content: tools.length ? null : text, ...(tools.length ? { tool_calls: tools.map((t, i) => ({ id: `call_fake${i}`, type: "function", function: { name: t.name, arguments: JSON.stringify(t.input) } })) } : {}) }, logprobs: null, finish_reason: tools.length ? "tool_calls" : "stop" }],
    usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 }
  };
}
const chunk = (choices) => `data: ${JSON.stringify({ id: "chatcmpl-fake02", object: "chat.completion.chunk", created: 1759700000, model: "gpt-fake", choices })}\n\n`;
// Content deltas, then (if any) tool_calls deltas — id + name first, arguments in fragments — then the
// finish_reason chunk and `data: [DONE]`.
export function openaiStream({ text = "Let me check that.", tools = [] } = {}) {
  const out = [chunk([{ index: 0, delta: { role: "assistant", content: "" }, logprobs: null, finish_reason: null }])];
  const half = Math.ceil(text.length / 2);
  out.push(chunk([{ index: 0, delta: { content: text.slice(0, half) }, logprobs: null, finish_reason: null }]));
  out.push(chunk([{ index: 0, delta: { content: text.slice(half) }, logprobs: null, finish_reason: null }]));
  tools.forEach((t, i) => {
    const json = JSON.stringify(t.input);
    out.push(chunk([{ index: 0, delta: { tool_calls: [{ index: i, id: `call_fake${i}`, type: "function", function: { name: t.name, arguments: "" } }] }, logprobs: null, finish_reason: null }]));
    for (let j = 0; j < json.length; j += 7) out.push(chunk([{ index: 0, delta: { tool_calls: [{ index: i, function: { arguments: json.slice(j, j + 7) } }] }, logprobs: null, finish_reason: null }]));
  });
  out.push(chunk([{ index: 0, delta: {}, logprobs: null, finish_reason: tools.length ? "tool_calls" : "stop" }]));
  out.push("data: [DONE]\n\n");
  return out;
}
