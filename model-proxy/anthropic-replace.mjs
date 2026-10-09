// --denied-tool-call replace, Anthropic Messages: a turn with a denied client tool call is delivered with
// every `tool_use` block of that turn withheld and ONE text block in its place, explaining the refusal; the
// stop_reason "tool_use" becomes "end_turn". The response stays what the SDK expects: no tool_use id is
// left without its block, no block index is skipped, and the turn ends the way a text-only turn ends.
// Allowed turns are delivered byte-identical. server_tool_use / mcp_tool_use blocks run at the provider
// and are left alone (anthropic.mjs).
import { replacementText } from "./report.mjs";

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const sse = (type, data) => Buffer.from(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);

// Non-streaming: the response body with the tool_use blocks replaced (a new object; `body` is untouched).
export function replaceResponse(body, verdict) {
  const content = Array.isArray(body.content) ? body.content : [];
  const total = content.filter((b) => b && b.type === "tool_use").length;
  const out = [];
  let placed = false;
  for (const b of content) {
    if (b && b.type === "tool_use") { if (!placed) { out.push({ type: "text", text: replacementText(verdict, total) }); placed = true; } continue; }
    out.push(b);
  }
  return { ...body, content: out, stop_reason: body.stop_reason === "tool_use" ? "end_turn" : body.stop_reason };
}

// Streaming. Events before the first tool_use block are released as they arrive. From that block's
// content_block_start, every event of the turn is held until its message_delta (the event that carries
// stop_reason, after the last block), and all of the turn's tool calls are decided together:
//   allowed → the held events are released byte-identical, in order;
//   denied  → the held events are dropped and replaced by one text block at the first tool_use block's
//             index (content_block_start / text_delta / content_block_stop) and the message_delta with
//             stop_reason "end_turn"; message_stop follows as sent.
// Holding the whole tail of the turn (not one block at a time) is what lets an allowed call that precedes
// a denied one in the same turn be withheld too. Held bytes are capped at maxHold: past it the turn's calls
// are decided as over the cap (denied in enforce mode), and the held events are freed.
//   onEvent(ev) → { out: Buffer[], replaced?: verdict } | { refuse: verdict }
export function createReplaceStream({ decide, maxHold }) {
  let hold = null;
  const parse = (s) => { try { return JSON.parse(s); } catch { return null; } };
  function calls(h) {
    return [...h.blocks.values()].map((b) => {
      let input = b.input, raw = null;
      if (b.args) { const p = parse(b.args); if (isObj(p)) input = p; else raw = b.args; }
      // A block the turn ended without closing is a truncated input: decided as such, never released.
      return { id: b.id, name: b.name, input: isObj(input) ? input : {}, raw: raw ?? (b.closed ? null : b.args || "{"), over: b.over || h.over };
    });
  }
  async function finish(ev, d, type) {
    const h = hold; hold = null;
    const list = calls(h);
    const v = await decide(list);
    if (v.decision !== "deny" && !h.over) return { out: [...h.raw, ev.raw] };
    const out = [
      sse("content_block_start", { type: "content_block_start", index: h.start, content_block: { type: "text", text: "" } }),
      sse("content_block_delta", { type: "content_block_delta", index: h.start, delta: { type: "text_delta", text: replacementText(v.decision === "deny" ? v : { denied: list.map((c) => ({ name: c.name, reasons: ["over the hold cap"] })) }, list.length) } }),
      sse("content_block_stop", { type: "content_block_stop", index: h.start })
    ];
    if (type === "message_delta") {
      const md = isObj(d) ? { ...d, delta: { ...(isObj(d.delta) ? d.delta : {}) } } : { type: "message_delta", delta: {} };
      if (md.delta.stop_reason === "tool_use" || md.delta.stop_reason == null) md.delta.stop_reason = "end_turn";
      out.push(sse("message_delta", md));
    } else {
      // message_stop with no message_delta before it: the turn still needs its stop_reason.
      out.push(sse("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null } }), ev.raw);
    }
    return { out, replaced: v };
  }
  async function onEvent(ev) {
    const d = parse(ev.data);
    const type = (d && d.type) || ev.event;
    const toolStart = type === "content_block_start" && d && d.content_block && d.content_block.type === "tool_use";
    if (!hold) {
      if (!toolStart) return { out: [ev.raw] };
      hold = { start: d.index, blocks: new Map(), raw: [], bytes: 0, over: false };
    }
    if (type === "message_delta" || type === "message_stop") return finish(ev, d, type);
    // The upstream's own error event ends the stream: passed on; the held calls are never released.
    if (type === "error") { hold = null; return { out: [ev.raw] }; }
    if (!hold.over) {
      hold.raw.push(ev.raw);
      hold.bytes += ev.raw.length;
      if (hold.bytes > maxHold) { hold.over = true; hold.raw = []; }
    }
    if (toolStart) {
      if (hold.blocks.size < 128) hold.blocks.set(d.index, { id: String(d.content_block.id || ""), name: String(d.content_block.name || ""), input: d.content_block.input, args: "", over: false, closed: false });
      else hold.over = true;
    } else if (type === "content_block_delta" && d && hold.blocks.has(d.index) && d.delta && d.delta.type === "input_json_delta" && typeof d.delta.partial_json === "string") {
      const b = hold.blocks.get(d.index);
      if (b.args.length + d.delta.partial_json.length > maxHold) b.over = true;
      else b.args += d.delta.partial_json;
    } else if (type === "content_block_stop" && d && hold.blocks.has(d.index)) hold.blocks.get(d.index).closed = true;
    return { out: [] };
  }
  // The upstream ended inside the held turn: decided for the report, never released, and said why.
  async function onEnd() {
    if (!hold) return { out: [] };
    const h = hold; hold = null;
    await decide(calls(h)).catch(() => {});
    const name = [...h.blocks.values()].map((b) => b.name).find(Boolean) || "";
    return { refuse: { decision: "deny", denied: [{ name, reasons: ["the stream ended inside the tool call"] }] } };
  }
  return { onEvent, onEnd, get holding() { return hold !== null; } };
}
