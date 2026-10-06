// Anthropic Messages API (POST …/v1/messages), as documented at platform.claude.com/docs/en/api/messages,
// …/build-with-claude/streaming and …/api/errors (read 2026-10-06). What this file knows:
//   request   `system` (string | text blocks) and `messages[]`; a user turn's content is a string or blocks:
//             text, tool_result {tool_use_id, content: string | blocks, is_error}, document (source text /
//             content). Assistant turns are the model's own output and are not re-scanned.
//   response  `content[]` blocks; a client tool call is {type: "tool_use", id, name, input}. server_tool_use
//             and mcp_tool_use run at the provider, not in the agent, so they are not decided here.
//   stream    message_start → per block content_block_start / content_block_delta… / content_block_stop →
//             message_delta… → message_stop, plus "any number of `ping` events". A tool_use block's input
//             arrives as input_json_delta "partial JSON strings", complete at its content_block_stop.
//   errors    {"type":"error","error":{"type","message"}}; mid-stream, `event: error` with the same body.
export const NAME = "anthropic";

const texts = (content) => {
  if (typeof content === "string") return [content];
  if (!Array.isArray(content)) return [];
  return content.filter((b) => b && b.type === "text" && typeof b.text === "string").map((b) => b.text);
};

// [{ kind, stage, ctx, text }] — the content this request sends the model that MoorAI scans.
export function outboundItems(body) {
  const out = [];
  for (const t of texts(body && body.system)) out.push({ kind: "system", stage: "prompt", ctx: {}, text: t });
  for (const m of Array.isArray(body && body.messages) ? body.messages : []) {
    if (!m || m.role !== "user") continue;
    if (typeof m.content === "string") { out.push({ kind: "prompt", stage: "prompt", ctx: {}, text: m.content }); continue; }
    for (const b of Array.isArray(m.content) ? m.content : []) {
      if (!b || typeof b !== "object") continue;
      if (b.type === "text" && typeof b.text === "string") out.push({ kind: "prompt", stage: "prompt", ctx: {}, text: b.text });
      else if (b.type === "tool_result") { const t = texts(b.content).join("\n"); if (t) out.push({ kind: "tool_result", stage: "output", ctx: { inbound: true }, text: t }); }
      else if (b.type === "document" && b.source && typeof b.source === "object") {
        const t = b.source.type === "text" && typeof b.source.data === "string" ? b.source.data : b.source.type === "content" ? texts(b.source.content).join("\n") : "";
        if (t) out.push({ kind: "document", stage: "output", ctx: { inbound: true }, text: t });
      }
    }
  }
  return out;
}

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);

// [{ id, name, input, raw }] — the client tool calls in a non-streaming response. An input that is not a
// JSON object comes back as `raw` text (content-scanned; refused in enforce mode), as in a stream.
export function responseToolCalls(body) {
  const blocks = Array.isArray(body && body.content) ? body.content : [];
  return blocks.filter((b) => b && b.type === "tool_use").map((b) => ({ id: String(b.id || ""), name: String(b.name || ""), input: isObj(b.input) ? b.input : {}, raw: isObj(b.input) ? null : typeof b.input === "string" ? b.input : JSON.stringify(b.input ?? null) }));
}

const ERROR_TYPES = { 403: "permission_error", 413: "request_too_large", 502: "api_error", 529: "overloaded_error", 400: "invalid_request_error", 404: "not_found_error", 401: "authentication_error" };
export function errorBody(status, message) {
  return { type: "error", error: { type: ERROR_TYPES[status] || "api_error", message } };
}
export function streamError(status, message) {
  return Buffer.from(`event: error\ndata: ${JSON.stringify(errorBody(status, message))}\n\n`);
}

// The streaming state machine. Every event outside a tool_use block is released as it arrives. A tool_use
// block is held from its content_block_start to its content_block_stop (the documented point where its
// input is complete), then decided: allowed → released byte-identical, in order; denied → refused.
// In observe mode (report-only) nothing is held: the caller has already forwarded the bytes, and the
// decision is made without awaiting it, so this function never delays the stream.
//   onEvent(ev) → { out: Buffer[] } | { refuse: verdict }
export function createStream({ enforce, decide, maxHold }) {
  let hold = null;
  const parse = (s) => { try { return JSON.parse(s); } catch { return null; } };
  function call(h) {
    let input = h.input, raw = null;
    if (h.args) { const p = parse(h.args); if (isObj(p)) input = p; else raw = h.args; }
    return { id: h.id, name: h.name, input: isObj(input) ? input : {}, raw, over: h.over };
  }
  async function settle(h) {
    if (!enforce) { decide([call(h)]).catch(() => {}); return { out: [] }; }
    const v = await decide([call(h)]);
    return v.decision === "deny" ? { refuse: v } : { out: h.raw };
  }
  async function onEvent(ev) {
    const d = parse(ev.data);
    const type = (d && d.type) || ev.event;
    if (!hold) {
      if (type === "content_block_start" && d && d.content_block && d.content_block.type === "tool_use") {
        hold = { index: d.index, id: String(d.content_block.id || ""), name: String(d.content_block.name || ""), input: d.content_block.input, args: "", over: false, raw: enforce ? [ev.raw] : null, bytes: ev.raw.length };
        return { out: [] };
      }
      return { out: [ev.raw] };
    }
    if (enforce) {
      hold.raw.push(ev.raw);
      hold.bytes += ev.raw.length;
      if (hold.bytes > maxHold) { const h = hold; hold = null; h.over = true; return settle(h); }
    }
    if (type === "content_block_delta" && d && d.index === hold.index && d.delta && d.delta.type === "input_json_delta" && typeof d.delta.partial_json === "string") {
      if (hold.args.length + d.delta.partial_json.length > maxHold) hold.over = true;
      else hold.args += d.delta.partial_json;
    }
    if (type === "content_block_stop" && d && d.index === hold.index) { const h = hold; hold = null; return settle(h); }
    return { out: [] };
  }
  // The upstream ended inside a tool_use block: decide what arrived (a truncated input fails to parse and
  // is content-scanned instead), so a cut-off stream is never a way around the check. Enforce never
  // releases the unfinished block, whatever that decision is, and says why.
  async function onEnd() {
    if (!hold) return { out: [] };
    const h = hold; hold = null;
    const r = await settle(h);
    return enforce ? { refuse: { decision: "deny", denied: [{ name: h.name, reasons: ["the stream ended inside the tool call"] }] } } : r;
  }
  return { onEvent, onEnd, get holding() { return hold !== null; } };
}
