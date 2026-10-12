// --denied-tool-call replace, Ollama native /api/chat: a response with a denied tool call is delivered with
// every tool call of the turn withheld (`message.tool_calls` removed) and the refusal as the assistant's
// content, after any text the model wrote. `done_reason` is left as sent: Ollama ends a tool-call turn with
// "stop" already. Allowed responses are delivered byte-identical.
import { replacementText } from "./report.mjs";
import { isObj, createCollector, createBudget } from "./ollama.mjs";

const join = (content, text) => (typeof content === "string" && content ? `${content}\n\n${text}` : text);
const parse = (s) => { try { return JSON.parse(s); } catch { return null; } };
const line = (o) => Buffer.from(`${JSON.stringify(o)}\n`);

// Non-streaming: a new body; `body` is untouched.
export function replaceResponse(body, verdict) {
  const m = isObj(body.message) ? body.message : {};
  const total = Array.isArray(m.tool_calls) ? m.tool_calls.length : 0;
  const { tool_calls, ...rest } = m;
  return { ...body, message: { role: "assistant", ...rest, content: join(m.content, replacementText(verdict, total)) } };
}

// Streaming. Lines are released as they arrive until the first line carrying message.tool_calls; from there
// every line is held until the `done: true` line, and the turn's calls are decided together:
//   allowed → the held lines and the done line are released byte-identical;
//   denied  → each held line is re-sent without `message.tool_calls` (a line left with no content and no
//             thinking is dropped), and the refusal text is appended to the done line's message content.
// Held bytes are capped at maxHold: every line of the held turn counts, blank ones and the done line
// included, together with the /api/generate text kept so far. Past it the calls are decided as over the cap
// (denied), the held lines and calls are freed and nothing more of the turn is kept, only counted; the done
// line, with the text, is then sent. A line that is not JSON, an {error} line inside the held turn, or an
// upstream that ends before `done` refuses, as in refuse mode.
export function createReplaceStream({ decide, maxHold, observe = () => {} }) {
  let hold = null, observed = false;
  // /api/generate text, for the report-only scan (ollama.mjs createStream does the same in refuse mode).
  const budget = createBudget(maxHold);
  const flush = () => { if (observed) return; observed = true; observe(budget.take()); };
  const refuseWith = (name, reason) => ({ refuse: { decision: "deny", denied: [{ name, reasons: [reason] }] } });
  function rewrite(raw) {
    const d = parse(raw.toString("utf8"));
    if (!isObj(d) || !isObj(d.message)) return raw;
    const { tool_calls, ...m } = d.message;
    if (!m.content && !m.thinking) return null;
    return line({ ...d, message: m });
  }
  async function release(doneRaw, done) {
    const h = hold;
    const list = h.col.list();
    const v = await decide(list);
    hold = null;
    if (v.decision !== "deny" && !h.col.over) return { out: [...h.raw, doneRaw] };
    const text = replacementText(v.decision === "deny" ? v : { denied: list.map((c) => ({ name: c.name, reasons: ["over the hold cap"] })) }, list.length);
    const out = [];
    for (const r of h.raw) { const b = rewrite(r); if (b) out.push(b); }
    const m = isObj(done.message) ? done.message : { role: "assistant", content: "" };
    const { tool_calls, ...rest } = m;
    out.push(line({ ...done, message: { ...rest, content: join(m.content, text) } }));
    return { out, replaced: v };
  }
  async function onEvent(ev) {
    const blank = !ev.data.trim();
    const d = blank ? null : parse(ev.data);
    if (!blank && !isObj(d)) return refuseWith("stream", "a stream line is not JSON; it was not released");
    if (d && typeof d.response === "string") budget.addText(d.response, hold ? hold.bytes : 0);
    if (d && d.done === true) flush();
    const calls = Boolean(d) && isObj(d.message) && Array.isArray(d.message.tool_calls) && d.message.tool_calls.length > 0;
    if (d && d.error !== undefined && hold) {
      const name = hold.col.list().map((c) => c.name).find(Boolean) || "";
      const h = hold; hold = null;
      await decide(h.col.list()).catch(() => {});
      return refuseWith(name, "the upstream sent an error inside the tool call's turn");
    }
    if (!hold && !calls) return { out: [ev.raw] };
    if (!hold) hold = { col: createCollector(), raw: [], bytes: 0 };
    hold.bytes += ev.raw.length;
    if (!hold.col.over && budget.over(hold.bytes)) { hold.raw = []; hold.col.setOver(); }
    if (!hold.col.over) {
      if (d) hold.col.add(d);
      if (!(d && d.done === true)) hold.raw.push(ev.raw);
    }
    if (d && d.done === true) return release(ev.raw, d);
    return { out: [] };
  }
  async function onEnd() {
    flush();
    if (!hold) return { out: [] };
    const h = hold; hold = null;
    const list = h.col.list();
    await decide(list).catch(() => {});
    return refuseWith(list.map((c) => c.name).find(Boolean) || "", "the stream ended inside the tool call's turn");
  }
  // What this response retains right now (tests measure the bound with it): held line bytes, kept calls and
  // kept text characters.
  const retained = () => ({ rawBytes: hold ? hold.raw.reduce((n, b) => n + b.length, 0) : 0, calls: hold ? hold.col.count : 0, textChars: budget.size });
  return { onEvent, onEnd, get holding() { return hold !== null; }, get retained() { return retained(); } };
}
