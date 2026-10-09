// --denied-tool-call replace, OpenAI Chat Completions: a response with a denied tool call is delivered with
// every tool call of the response withheld (`tool_calls` and the deprecated `function_call` removed) and the
// refusal as the assistant's text; finish_reason "tool_calls" / "function_call" becomes "stop". No tool call
// id is left without its call, and the message is a plain text completion the SDK already knows how to read.
// Allowed responses are delivered byte-identical.
import { replacementText } from "./report.mjs";
import { parseEvent } from "./sse.mjs";

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const TOOL_FINISH = new Set(["tool_calls", "function_call"]);
const join = (content, text) => (typeof content === "string" && content ? `${content}\n\n${text}` : text);

// Non-streaming: a new body; `body` is untouched.
export function replaceResponse(body, verdict) {
  const choices = Array.isArray(body.choices) ? body.choices : [];
  const total = choices.reduce((n, c) => n + (c && c.message ? (Array.isArray(c.message.tool_calls) ? c.message.tool_calls.length : 0) + (c.message.function_call ? 1 : 0) : 0), 0);
  const text = replacementText(verdict, total);
  return {
    ...body,
    choices: choices.map((c) => {
      const m = c && c.message;
      if (!m || !((Array.isArray(m.tool_calls) && m.tool_calls.length) || m.function_call)) return c;
      const { tool_calls, function_call, ...rest } = m;
      return { ...c, message: { ...rest, content: join(m.content, text) }, finish_reason: TOOL_FINISH.has(c.finish_reason) ? "stop" : c.finish_reason };
    })
  };
}

const hasCall = (c) => c && c.delta && ((Array.isArray(c.delta.tool_calls) && c.delta.tool_calls.length) || c.delta.function_call);

// Streaming. Chunks are released as they arrive until the first chunk carrying a tool_calls (or
// function_call) delta; from there every chunk is held until each choice that started a tool call has sent
// its finish_reason (or [DONE] arrives), and the response's calls are decided together:
//   allowed → the held chunks are released byte-identical;
//   denied  → each held chunk is re-sent with its tool_calls / function_call deltas removed (a chunk left
//             with nothing in it is dropped), and the refusal text goes in the delta of the chunk that
//             carries the choice's finish_reason, which becomes "stop". A choice that never sent one gets a
//             final chunk with the text and finish_reason "stop" before [DONE].
// Held bytes are capped at maxHold: past it the calls are decided as over the cap (denied in enforce mode)
// and the held chunks are freed; only the replacement chunks are then sent.
export function createReplaceStream({ decide, maxHold }) {
  let hold = null;
  const parse = (s) => { try { return JSON.parse(s); } catch { return null; } };
  const fromArgs = (c, over) => {
    const p = parse(c.args);
    const ok = isObj(p);
    return { id: c.id, name: c.name, input: ok ? p : {}, raw: ok || !c.args ? null : c.args, over };
  };
  function rewrite(raw, text, started, finished) {
    const d = parse(parseEvent(raw).data);
    if (!d || !Array.isArray(d.choices)) return raw;
    const keep = d.usage != null;
    const choices = [];
    for (const c of d.choices) {
      if (!isObj(c)) continue;
      const { tool_calls, function_call, ...delta } = isObj(c.delta) ? c.delta : {};
      const out = { ...c, delta };
      if (TOOL_FINISH.has(c.finish_reason) || (c.finish_reason && started.has(c.index))) {
        out.finish_reason = TOOL_FINISH.has(c.finish_reason) ? "stop" : c.finish_reason;
        delta.content = join(delta.content, text);
        finished.add(c.index);
      }
      if (Object.keys(delta).length || out.finish_reason) choices.push(out);
    }
    if (!choices.length && !keep) return null;
    return Buffer.from(`data: ${JSON.stringify({ ...d, choices })}\n\n`);
  }
  async function release(extra = []) {
    const h = hold;
    const list = [...h.calls.values()].map((c) => fromArgs(c, c.over || h.over));
    const v = await decide(list);
    hold = null;
    if (v.decision !== "deny" && !h.over) return { out: [...h.raw, ...extra] };
    const text = replacementText(v.decision === "deny" ? v : { denied: list.map((c) => ({ name: c.name, reasons: ["over the hold cap"] })) }, list.length);
    const finished = new Set(), out = [];
    for (const r of h.raw) { const b = rewrite(r, text, h.started, finished); if (b) out.push(b); }
    for (const i of h.started) {
      if (finished.has(i)) continue;
      out.push(Buffer.from(`data: ${JSON.stringify({ ...h.meta, object: "chat.completion.chunk", choices: [{ index: i, delta: { content: text }, logprobs: null, finish_reason: "stop" }] })}\n\n`));
    }
    return { out: [...out, ...extra], replaced: v };
  }
  async function onEvent(ev) {
    if (ev.data === "[DONE]") return hold ? release([ev.raw]) : { out: [ev.raw] };
    const d = parse(ev.data);
    const choices = d && Array.isArray(d.choices) ? d.choices : [];
    if (!hold && !choices.some(hasCall)) return { out: [ev.raw] };
    if (!hold) hold = { calls: new Map(), open: new Set(), started: new Set(), finished: false, raw: [], bytes: 0, over: false, meta: { id: d.id, created: d.created, model: d.model } };
    if (!hold.over) {
      hold.raw.push(ev.raw);
      hold.bytes += ev.raw.length;
      if (hold.bytes > maxHold) { hold.over = true; hold.raw = []; }
    }
    for (const c of choices) {
      if (!isObj(c)) continue;
      const add = (key, id, name, args) => {
        const e = hold.calls.get(key) || { id: "", name: "", args: "", over: false };
        if (id && !e.id) e.id = String(id);
        if (typeof name === "string" && name && !e.name) e.name = name;
        if (typeof args === "string") { if (e.args.length + args.length > maxHold) e.over = true; else e.args += args; }
        hold.calls.set(key, e);
        hold.open.add(c.index);
        hold.started.add(c.index);
      };
      if (hold.calls.size < 128) {
        for (const tc of Array.isArray(c.delta && c.delta.tool_calls) ? c.delta.tool_calls : []) if (tc) add(`${c.index}:${tc.index}`, tc.id, tc.function && tc.function.name, tc.function && tc.function.arguments);
        if (c.delta && c.delta.function_call) add(`${c.index}:fc`, "", c.delta.function_call.name, c.delta.function_call.arguments);
      } else hold.over = true;
      if (c.finish_reason && hold.open.has(c.index)) { hold.open.delete(c.index); hold.finished = true; }
    }
    if (hold.finished && hold.open.size === 0) return release();
    return { out: [] };
  }
  async function onEnd() {
    if (!hold) return { out: [] };
    const h = hold; hold = null;
    const list = [...h.calls.values()].map((c) => fromArgs(c, c.over || h.over));
    await decide(list).catch(() => {});
    return { refuse: { decision: "deny", denied: [{ name: list.map((c) => c.name).find(Boolean) || "", reasons: ["the stream ended inside the tool call"] }] } };
  }
  return { onEvent, onEnd, get holding() { return hold !== null; } };
}
