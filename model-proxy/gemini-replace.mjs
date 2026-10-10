// --denied-tool-call replace, Gemini generateContent: a turn with a denied function call is delivered with
// every functionCall part of the turn withheld and ONE text part, explaining the refusal, at the first
// call's place in each candidate that had calls. The candidate's finishReason stays (or becomes) "STOP", the
// reason a function-call turn already carries, so the turn ends the way a text answer ends. A chunk left
// with nothing in it is dropped. Allowed turns are delivered byte-identical. A functionCall part's
// thoughtSignature goes with it.
import { replacementText } from "./report.mjs";
import { parseEvent } from "./sse.mjs";
import { isObj, fcOf, partsOf, candidatesOf, indexOf, finishOf, createCollector } from "./gemini.mjs";

// finishReason values a rewritten candidate gets "STOP" in place of: none yet, or one about tool calls.
const TOOLISH = new Set(["FINISH_REASON_UNSPECIFIED", "UNEXPECTED_TOOL_CALL", "TOO_MANY_TOOL_CALLS", "MALFORMED_FUNCTION_CALL"]);

// [response] → [response | null] (null: nothing left to send). `started` is the candidate indexes that had
// calls in the turn. With `finalize` a candidate that never sent a finishReason gets "STOP" where the text
// went (a whole non-streaming turn).
export function rewriteTurn(list, text, started, { finalize = false } = {}) {
  const placed = new Map(), ended = new Set();
  const out = list.map((r) => {
    if (!isObj(r) || !Array.isArray(r.candidates)) return r;
    const candidates = [];
    r.candidates.forEach((c, i) => {
      if (!isObj(c)) { candidates.push(c); return; }
      const idx = indexOf(c, i);
      if (!started.has(idx)) { candidates.push(c); return; }
      const next = { ...c };
      const parts = partsOf(c.content);
      if (parts.some((p) => isObj(fcOf(p)))) {
        const kept = [];
        for (const p of parts) {
          if (!isObj(fcOf(p))) { kept.push(p); continue; }
          if (!placed.has(idx)) { kept.push({ text }); placed.set(idx, next); }
        }
        if (kept.length) next.content = { ...c.content, parts: kept }; else delete next.content;
      }
      const fr = finishOf(c);
      if (fr) {
        ended.add(idx);
        const key = c.finishReason !== undefined ? "finishReason" : "finish_reason";
        if (TOOLISH.has(fr)) next[key] = "STOP";
      }
      if (next.content || finishOf(next) || Object.keys(next).some((k) => k !== "index" && k !== "content")) candidates.push(next);
    });
    const res = { ...r, candidates };
    if (!candidates.length) {
      delete res.candidates;
      if (!Object.keys(res).some((k) => k === "usageMetadata" || k === "usage_metadata" || k === "promptFeedback" || k === "prompt_feedback")) return null;
    }
    return res;
  });
  if (finalize) for (const [idx, c] of placed) if (!ended.has(idx)) c.finishReason = "STOP";
  return out;
}

// Non-streaming (an object, or the JSON array streamGenerateContent sends without alt=sse): a new body;
// `body` is untouched.
export function replaceResponse(body, verdict) {
  const list = Array.isArray(body) ? body : [body];
  const col = createCollector(Infinity);
  for (const r of list) col.add(r);
  const text = replacementText(verdict, col.list().length);
  const out = rewriteTurn(list, text, col.started, { finalize: true });
  return Array.isArray(body) ? out.filter((r) => r !== null) : out[0] ?? { ...body, candidates: [] };
}

const serialize = (obj, raw) => Buffer.from(`data: ${JSON.stringify(obj)}${raw.toString("latin1").endsWith("\r\n\r\n") ? "\r\n\r\n" : "\n\n"}`);

// Streaming (alt=sse). Events are released as they arrive until the first one carrying a functionCall part;
// from there every event is held until each candidate that started a call has sent its finishReason, and
// the turn's calls are decided together:
//   allowed → the held events are released byte-identical;
//   denied  → each held event is re-sent with its functionCall parts removed, the refusal text in the
//             first call's place, finishReason "STOP" (an event left empty is dropped).
// Held bytes are capped at maxHold: past it the calls are decided as over the cap (a deny), the held events
// are freed, and one event per candidate carries the text and finishReason "STOP".
export function createReplaceStream({ decide, maxHold }) {
  let hold = null;
  const parse = (s) => { try { return JSON.parse(s); } catch { return null; } };
  async function release() {
    const h = hold; hold = null;
    const list = h.col.list();
    const v = await decide(list);
    if (v.decision !== "deny" && !h.over) return { out: h.raw };
    const verdict = v.decision === "deny" ? v : { denied: list.map((c) => ({ name: c.name, reasons: ["over the hold cap"] })) };
    const text = replacementText(verdict, list.length);
    if (h.over) {
      const out = [...h.col.started].map((index) => serialize({ candidates: [{ content: { role: "model", parts: [{ text }] }, finishReason: "STOP", index }], ...h.meta }, h.first));
      return { out, replaced: verdict };
    }
    const parsed = h.raw.map((raw) => { const d = parse(parseEvent(raw).data); return isObj(d) ? d : null; });
    const rewritten = rewriteTurn(parsed.map((d) => d ?? {}), text, h.col.started);
    const out = [];
    h.raw.forEach((raw, i) => { if (!parsed[i]) out.push(raw); else if (rewritten[i]) out.push(serialize(rewritten[i], raw)); });
    return { out, replaced: verdict };
  }
  async function onEvent(ev) {
    const d = parse(ev.data);
    if (!hold) {
      if (!isObj(d) || !candidatesOf(d).some((c) => partsOf(c && c.content).some((p) => isObj(fcOf(p))))) return { out: [ev.raw] };
      hold = { col: createCollector(maxHold), raw: [], bytes: 0, over: false, first: ev.raw, meta: { ...(d.modelVersion ? { modelVersion: d.modelVersion } : {}), ...(d.responseId ? { responseId: d.responseId } : {}) } };
    }
    if (!hold.over) {
      hold.raw.push(ev.raw);
      hold.bytes += ev.raw.length;
      if (hold.bytes > maxHold) { hold.over = true; hold.raw = []; hold.col.setOver(); }
    }
    if (isObj(d)) hold.col.add(d);
    return hold.col.complete ? release() : { out: [] };
  }
  // The upstream ended inside the held turn: decided for the report, never released, and said why.
  async function onEnd() {
    if (!hold) return { out: [] };
    const h = hold; hold = null;
    const list = h.col.list();
    await decide(list).catch(() => {});
    return { refuse: { decision: "deny", denied: [{ name: list.map((c) => c.name).find(Boolean) || "", reasons: ["the stream ended inside the tool call's turn"] }] } };
  }
  return { onEvent, onEnd, get holding() { return hold !== null; } };
}
