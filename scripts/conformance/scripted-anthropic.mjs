// A scripted Anthropic Messages endpoint for the live host-conformance tier. A real agent host (Claude
// Code via ANTHROPIC_BASE_URL) is pointed at it instead of a paid model: the host runs its real hook
// pipeline, its real permission layer and its real tools, and only the model's turns are scripted.
//
// Script: the first request that offers the planned tool gets ONE tool_use for it (planned input). Once
// the host sends that tool_use's tool_result back, the reply is a final text turn. Every other request
// (a title or classifier call without the tool, a retry before a result) gets a short text turn.
//
// What it records is booleans and counts only: whether the tool_use went out, whether the tool_result
// was an error, whether it names MoorAI, whether the expected output marker came back, and whether a
// given marker string appeared in any request (used to prove a blocked prompt never reached the model).
// Request bodies are inspected in memory and never stored.
//
// Formats follow the documented Messages API: JSON for "stream": false, and for "stream": true the SSE
// event flow message_start, content_block_start, content_block_delta (input_json_delta for tool input),
// content_block_stop, message_delta, message_stop. POST …/messages/count_tokens answers {input_tokens}.
import http from "node:http";

const blocksOf = (messages) => (Array.isArray(messages) ? messages : []).flatMap((m) => (Array.isArray(m && m.content) ? m.content : []));
const textOf = (content) => (typeof content === "string" ? content : Array.isArray(content) ? content.map((c) => (c && typeof c.text === "string" ? c.text : "")).join("\n") : "");

export async function startScriptedAnthropic({ toolName = null, toolInput = {}, okMarker = null, marker = null, model = "moorai-scripted" } = {}) {
  const st = { requests: 0, toolRequests: 0, auxRequests: 0, toolUsesSent: 0, toolResult: null, markerSeen: false };
  let toolUseId = null;
  let seq = 0;

  function reply(res, stream, block, stopReason) {
    const msg = { id: `msg_moorai_${++seq}`, type: "message", role: "assistant", model, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } };
    if (!stream) {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ ...msg, content: [block], stop_reason: stopReason }));
    }
    const ev = [{ type: "message_start", message: msg }];
    if (block.type === "tool_use") {
      ev.push({ type: "content_block_start", index: 0, content_block: { ...block, input: {} } });
      ev.push({ type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(block.input) } });
    } else {
      ev.push({ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
      ev.push({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: block.text } });
    }
    ev.push({ type: "content_block_stop", index: 0 });
    ev.push({ type: "message_delta", delta: { stop_reason: stopReason, stop_sequence: null }, usage: { output_tokens: 1 } });
    ev.push({ type: "message_stop" });
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
    for (const e of ev) res.write(`event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`);
    res.end();
  }

  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      const path = (req.url || "").split("?")[0];
      if (req.method !== "POST" || !/\/messages(\/count_tokens)?$/.test(path)) { res.writeHead(404, { "content-type": "application/json" }); return res.end('{"type":"error","error":{"type":"not_found_error","message":"not found"}}'); }
      if (marker && body.includes(marker)) st.markerSeen = true;
      if (path.endsWith("/count_tokens")) { res.writeHead(200, { "content-type": "application/json" }); return res.end('{"input_tokens":16}'); }
      st.requests++;
      let j = {};
      try { j = JSON.parse(body); } catch { /* treated as auxiliary */ }
      const offersTool = !!toolName && Array.isArray(j.tools) && j.tools.some((t) => t && t.name === toolName);
      if (!offersTool) { st.auxRequests++; return reply(res, j.stream === true, { type: "text", text: "ok" }, "end_turn"); }
      st.toolRequests++;
      const result = toolUseId ? blocksOf(j.messages).find((b) => b && b.type === "tool_result" && b.tool_use_id === toolUseId) : null;
      if (result) {
        const text = textOf(result.content);
        st.toolResult = { isError: result.is_error === true, mentionsMoorAI: /MoorAI/.test(text), okMarker: !!okMarker && text.includes(okMarker) };
        return reply(res, j.stream === true, { type: "text", text: "done" }, "end_turn");
      }
      if (toolUseId) return reply(res, j.stream === true, { type: "text", text: "done" }, "end_turn");
      toolUseId = `toolu_01MoorAIConformance${String(Date.now()).slice(-6)}`;
      st.toolUsesSent++;
      return reply(res, j.stream === true, { type: "tool_use", id: toolUseId, name: toolName, input: toolInput }, "tool_use");
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    stats: () => ({ ...st, toolUseSent: st.toolUsesSent > 0, toolResult: st.toolResult ? { ...st.toolResult } : null }),
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); })
  };
}
