// A fake Ollama native-API upstream for test/model-proxy-ollama*.test.mjs: the documented /api/chat and
// /api/generate shapes (github.com/ollama/ollama docs/api.md, docs/api/streaming.mdx, docs/api/errors.mdx),
// JSON with "stream": false and NDJSON (application/x-ndjson, one JSON object per "\n"-terminated line)
// otherwise, nothing real behind them. The tool call carries `id` and `function.index`, which the docs'
// examples omit but Ollama 0.15.6 sends (measured: {"id":"call_uv3mxz1k","function":{"index":0,"name":…}}).
export const MODEL = "llama-fake:1b";
const T0 = "2026-10-12T13:06:51.290328Z";
const stats = { total_duration: 182242375, load_duration: 41295167, prompt_eval_count: 169, prompt_eval_duration: 24573166, eval_count: 15, eval_duration: 115959084 };
const call = (t, i) => ({ id: `call_fake${i}`, function: { index: i, name: t.name, arguments: t.input } });

export function chatResponse({ text = "", tools = [] } = {}) {
  return { model: MODEL, created_at: T0, message: { role: "assistant", content: text, ...(tools.length ? { tool_calls: tools.map(call) } : {}) }, done_reason: "stop", done: true, ...stats };
}

const line = (o) => `${JSON.stringify(o)}\n`;
const msg = (content, extra = {}) => line({ model: MODEL, created_at: T0, message: { role: "assistant", content, ...extra }, done: false });
const doneLine = () => line({ model: MODEL, created_at: T0, message: { role: "assistant", content: "" }, done_reason: "stop", done: true, ...stats });

// The lines of a streamed chat turn: the text in two pieces, then every tool call in one line (Ollama sends a
// parsed call whole), then the final done line. `split`: each call in a line of its own.
export function chatLines({ text = "Let me check that.", tools = [], split = false, done = true } = {}) {
  const half = Math.ceil(text.length / 2);
  const out = text ? [msg(text.slice(0, half)), msg(text.slice(half))] : [];
  if (tools.length) {
    if (split) tools.forEach((t, i) => out.push(msg("", { tool_calls: [call(t, i)] })));
    else out.push(msg("", { tool_calls: tools.map(call) }));
  }
  if (done) out.push(doneLine());
  return out;
}

export function generateResponse({ text = "The sky is blue." } = {}) {
  return { model: MODEL, created_at: T0, response: text, done: true, done_reason: "stop", context: [1, 2, 3], ...stats };
}
export function generateLines({ text = "The sky is blue because of Rayleigh scattering." } = {}) {
  const words = text.split(/(?<= )/);
  return [...words.map((w) => line({ model: MODEL, created_at: T0, response: w, done: false })), line({ model: MODEL, created_at: T0, response: "", done: true, done_reason: "stop", context: [1, 2, 3], ...stats })];
}

// Writes NDJSON lines in `slice`-byte pieces, so the proxy's line splitting is exercised across chunks.
export async function sendNdjson(res, lines, { slice = 5, status = 200 } = {}) {
  res.writeHead(status, { "content-type": "application/x-ndjson" });
  const b = Buffer.from(lines.join(""));
  for (let j = 0; j < b.length; j += slice) { if (res.destroyed) return; res.write(b.subarray(j, j + slice)); await new Promise((r) => setImmediate(r)); }
  res.end();
}

// What the official clients build from an NDJSON body (ollama-python _client.py: `for line in
// r.iter_lines(): part = json.loads(line); if err := part.get('error'): raise ResponseError(err)`; ollama-js
// src/utils.ts parseJSON + AbortableAsyncIterator: a part with `error` throws, a stream with no `done` part
// throws "Did not receive done or success response in stream."). Returns { parts, error, text, calls, done }.
export function clientRead(raw) {
  const parts = [];
  for (const l of raw.toString("utf8").split("\n")) {
    if (!l.trim()) continue;
    const p = JSON.parse(l);
    if (p.error) return { parts, error: p.error };
    parts.push(p);
  }
  const done = parts.some((p) => p.done === true);
  return {
    parts, done,
    text: parts.map((p) => (p.message ? p.message.content || "" : p.response || "")).join(""),
    calls: parts.flatMap((p) => (p.message && Array.isArray(p.message.tool_calls) ? p.message.tool_calls : []))
  };
}
