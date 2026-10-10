// A fake Gemini upstream for test/model-proxy-gemini*.test.mjs: the documented generateContent /
// streamGenerateContent shapes (ai.google.dev/api/generate-content), JSON, a JSON array (no alt=sse) and SSE
// (alt=sse, events ending "\r\n\r\n"), nothing real behind them and no real key anywhere. And what the
// Google Gen AI SDKs build from a stream, with the rules they rely on asserted on the way.
import assert from "node:assert/strict";

export const MODEL_VERSION = "gemini-fake-001";
const usage = { promptTokenCount: 10, candidatesTokenCount: 20, totalTokenCount: 30 };
const fcPart = (t, i) => ({ functionCall: { id: `fc_fake${i}`, name: t.name, args: t.input }, ...(i === 0 ? { thoughtSignature: "c2lnLWZha2U=" } : {}) });

export function geminiResponse({ text = "Sure.", tools = [] } = {}) {
  return {
    candidates: [{ content: { role: "model", parts: [...(text ? [{ text }] : []), ...tools.map(fcPart)] }, finishReason: "STOP", index: 0 }],
    usageMetadata: usage, modelVersion: MODEL_VERSION, responseId: "resp_fake01"
  };
}

const chunk = (parts, extra = {}) => ({ candidates: [{ content: { role: "model", parts }, index: 0, ...extra }], modelVersion: MODEL_VERSION, responseId: "resp_fake02" });
// The chunks of a streamed turn: the text in two pieces, each function call in a chunk of its own, then a
// last chunk with finishReason STOP and usage. `callWithFinish`: the last call and the finishReason share a
// chunk.
export function geminiChunks({ text = "Let me check that.", tools = [], callWithFinish = false } = {}) {
  const half = Math.ceil(text.length / 2);
  const out = [chunk([{ text: text.slice(0, half) }]), chunk([{ text: text.slice(half) }])];
  tools.forEach((t, i) => {
    const last = i === tools.length - 1;
    out.push(callWithFinish && last ? { ...chunk([fcPart(t, i)], { finishReason: "STOP" }), usageMetadata: usage } : chunk([fcPart(t, i)]));
  });
  if (!(callWithFinish && tools.length)) out.push({ ...chunk([{ text: "" }], { finishReason: "STOP" }), usageMetadata: usage });
  return out;
}
export const sseOf = (chunks) => chunks.map((c) => `data: ${JSON.stringify(c)}\r\n\r\n`);
export const geminiStream = (opts) => sseOf(geminiChunks(opts));
// streamGenerateContent without alt=sse: the stream is one JSON array, written element by element.
export const geminiArray = (opts) => `[${geminiChunks(opts).map((c) => JSON.stringify(c)).join(",\r\n")}]`;

// The JS SDK's stream reader (js-genai src/_api_client.ts processStreamResponse): split on "\n\n", "\r\r" or
// "\r\n\r\n"; an event starting `data:` is one GenerateContentResponse. A read chunk that is a JSON object
// with `error` (code 400-599), or a buffer left over at the end, raises.
export function jsSdkChunks(raw) {
  const s = raw.toString("utf8");
  const tail = s.match(/(?:^|\n)(\{"error":.*\})\n?$/);
  if (tail) { const e = JSON.parse(tail[1]); if (e.error.code >= 400 && e.error.code < 600) return { error: e.error }; }
  const out = [];
  let buf = s;
  for (;;) {
    const m = /\r\n\r\n|\n\n|\r\r/.exec(buf);
    if (!m) break;
    const ev = buf.slice(0, m.index).trim();
    buf = buf.slice(m.index + m[0].length);
    if (ev.startsWith("data:")) out.push(JSON.parse(ev.slice(5).trim()));
  }
  assert.equal(buf.trim(), "", "Incomplete JSON segment at the end");
  return { chunks: out };
}

// What an SDK accumulates from a turn's responses (chunks, an array, or one object): per candidate, its text,
// its function calls and its one finishReason.
export function accumulate(list) {
  const cands = new Map();
  for (const r of list) {
    assert.ok(r && typeof r === "object" && !Array.isArray(r), "each response is an object");
    if (r.candidates !== undefined) assert.ok(Array.isArray(r.candidates), "candidates is an array");
    for (const c of r.candidates || []) {
      const i = c.index ?? 0;
      const s = cands.get(i) || { text: "", calls: [], finishReason: null };
      if (c.content !== undefined) {
        assert.equal(c.content.role, "model");
        assert.ok(Array.isArray(c.content.parts) && c.content.parts.length > 0, "a content has at least one part");
        for (const p of c.content.parts) {
          assert.equal(Object.keys(p).filter((k) => ["text", "inlineData", "functionCall", "functionResponse", "fileData", "executableCode", "codeExecutionResult", "toolCall", "toolResponse"].includes(k)).length, 1, `one data field per part: ${JSON.stringify(p)}`);
          if (typeof p.text === "string") s.text += p.text;
          if (p.functionCall) s.calls.push(p.functionCall);
        }
      }
      if (c.finishReason) { assert.equal(s.finishReason, null, "one finishReason per candidate"); s.finishReason = c.finishReason; }
      cands.set(i, s);
    }
  }
  return cands;
}

// The FinishReason enum, ai.google.dev/api/generate-content#FinishReason.
export const FINISH_REASONS = new Set(["FINISH_REASON_UNSPECIFIED", "STOP", "MAX_TOKENS", "SAFETY", "RECITATION", "LANGUAGE", "OTHER", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "MALFORMED_FUNCTION_CALL", "IMAGE_SAFETY", "IMAGE_PROHIBITED_CONTENT", "IMAGE_OTHER", "NO_IMAGE", "IMAGE_RECITATION", "UNEXPECTED_TOOL_CALL", "TOO_MANY_TOOL_CALLS", "MISSING_THOUGHT_SIGNATURE", "MALFORMED_RESPONSE", "ESCALATION", "PUP_LIMITED_DISABLED"]);
