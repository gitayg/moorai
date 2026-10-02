// SSE framing for the HTTP MCP gateway (mcp-gateway/sse.mjs): every line ending the SSE spec allows,
// events split across arbitrary chunks, the original text kept per event, and the overflow bound.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createSseFramer, sseEvent } from "../mcp-gateway/sse.mjs";

function frame(chunks, maxEventBytes = 1 << 20) {
  const out = [];
  const f = createSseFramer({ maxEventBytes, onEvent: (e) => out.push(["ev", e]), onRaw: (t) => out.push(["raw", t]) });
  for (const c of chunks) f.push(Buffer.from(c, "utf8"));
  f.end();
  return out;
}

test("SSE: LF, CRLF and CR line endings all end events; data lines join with \\n; raw text is kept", () => {
  for (const nl of ["\n", "\r\n", "\r"]) {
    const text = `id: 7${nl}event: message${nl}data: {"a":${nl}data: 1}${nl}${nl}: keepalive${nl}${nl}`;
    const out = frame([...text]); // one character per chunk: every split point
    const evs = out.filter((o) => o[0] === "ev").map((o) => o[1]);
    assert.equal(evs.length, 2, JSON.stringify(nl));
    assert.equal(evs[0].data, '{"a":\n1}');
    assert.equal(evs[0].id, "7");
    assert.equal(evs[1].data, null, "a comment-only event carries no data");
    assert.equal(evs.map((e) => e.raw).join(""), text, `raw text not preserved for ${JSON.stringify(nl)}`);
  }
});

test("SSE: a multi-byte character split across chunks is not corrupted", () => {
  const text = 'data: {"t":"héllo 世界"}\n\n';
  const buf = Buffer.from(text, "utf8");
  const out = [];
  const f = createSseFramer({ maxEventBytes: 1 << 20, onEvent: (e) => out.push(e), onRaw: () => {} });
  for (let i = 0; i < buf.length; i++) f.push(buf.subarray(i, i + 1));
  f.end();
  assert.equal(out[0].raw, text);
});

test("SSE: an event past maxEventBytes streams through raw, and framing resumes after it", () => {
  const big = `data: ${"x".repeat(200)}\n\n`;
  const out = frame([big, 'data: {"ok":1}\n\n'], 64);
  const raw = out.filter((o) => o[0] === "raw").map((o) => o[1]).join("");
  assert.equal(raw, big, "the oversized event must be forwarded intact, unscanned");
  const evs = out.filter((o) => o[0] === "ev");
  assert.equal(evs.length, 1);
  assert.equal(evs[0][1].data, '{"ok":1}');
});

test("SSE: a replacement event keeps the id and is a single data line", () => {
  assert.equal(sseEvent({ a: "x\ny" }, "e2"), 'id: e2\nevent: message\ndata: {"a":"x\\ny"}\n\n');
});
