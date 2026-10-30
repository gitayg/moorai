// The tool results a request sends upstream, masked before they reach the provider (cli/result-mask.mjs: #39 by
// default, and any data-tier threat the signed policy sets to "mask"). Enforce mode only: in report mode the proxy
// forwards the client's bytes. Each result is masked on its own (the rewrite budget is per result), and only the
// fields outboundItems scans as a tool result are touched:
//   anthropic         user turn → tool_result.content: a string, or its text blocks' `text`
//   openai-chat       a `tool` / `function` message's content: a string, or its text parts' `text`
//   ollama            a `tool` message's content: a string, or its parts' `text`
//   openai-responses  function_call_output (and the other *_call_output items) → output: a string, or its text
//                     parts' `text`; shell_call_output → each entry's stdout / stderr
//   gemini            functionResponse.response: every string in it
// A request re-sends the whole conversation each turn, so a result's outcome is kept in a bounded in-memory map
// keyed by a keyed hash of the text: the same result is masked to the same bytes every time (the provider's prompt
// cache still matches) and is not re-scanned.
import { createHmac, randomBytes } from "node:crypto";
import { maskResult } from "../cli/result-mask.mjs";

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const TEXT_PARTS = new Set(["text", "input_text", "output_text"]);
const RESPONSES_OUT = new Set(["function_call_output", "custom_tool_call_output", "local_shell_call_output", "apply_patch_call_output"]);

// [{ obj, key }]: obj[key] is a string (or, for gemini, an object) that a tool returned.
function textSlots(content, obj, key, parts = TEXT_PARTS) {
  if (typeof content === "string") return [{ obj, key }];
  if (!Array.isArray(content)) return [];
  return content.filter((p) => isObj(p) && (p.type === undefined || parts.has(p.type)) && typeof p.text === "string").map((p) => ({ obj: p, key: "text" }));
}
export function resultSlots(kind, body) {
  const out = [];
  if (!isObj(body)) return out;
  if (kind === "anthropic") {
    for (const m of Array.isArray(body.messages) ? body.messages : []) {
      if (!isObj(m) || m.role !== "user" || !Array.isArray(m.content)) continue;
      for (const b of m.content) if (isObj(b) && b.type === "tool_result") out.push(textSlots(b.content, b, "content"));
    }
  } else if (kind === "openai-chat" || kind === "ollama") {
    for (const m of Array.isArray(body.messages) ? body.messages : []) {
      if (isObj(m) && (m.role === "tool" || (kind === "openai-chat" && m.role === "function"))) out.push(textSlots(m.content, m, "content"));
    }
  } else if (kind === "openai-responses") {
    for (const m of Array.isArray(body.input) ? body.input : []) {
      if (!isObj(m)) continue;
      if (RESPONSES_OUT.has(m.type)) out.push(textSlots(m.output, m, "output"));
      else if (m.type === "shell_call_output" && Array.isArray(m.output)) out.push(m.output.filter(isObj).flatMap((o) => ["stdout", "stderr"].filter((k) => typeof o[k] === "string").map((k) => ({ obj: o, key: k }))));
    }
  } else if (kind === "gemini") {
    const contents = Array.isArray(body.contents) ? body.contents : isObj(body.contents) ? [body.contents] : [];
    for (const c of contents) {
      if (!isObj(c) || c.role === "model" || !Array.isArray(c.parts)) continue;
      for (const p of c.parts) {
        const k = isObj(p) ? (p.functionResponse !== undefined ? "functionResponse" : p.function_response !== undefined ? "function_response" : null) : null;
        if (k && isObj(p[k]) && p[k].response !== undefined) out.push([{ obj: p[k], key: "response" }]);
      }
    }
  }
  return out.filter((s) => s.length);
}

export const RESULT_CACHE_SIZE = 4096;

// The masker for one proxy process. mask(kind, body, { engine, policy, policyId }) rewrites `body` in place and
// returns { changed, masked: [{ ids, count, fresh }], failed: [{ ids, fallback }] } (fresh: first seen by this process). `hash` makes the placeholder (the
// install-token keyed hash); the cache key is an HMAC under a key of this process only.
export function createResultMasker({ hash, size = RESULT_CACHE_SIZE } = {}) {
  const cache = new Map();
  const ck = randomBytes(32);
  const remember = (k, v) => { cache.set(k, v); if (cache.size > size) cache.delete(cache.keys().next().value); return v; };
  function one(slots, engine, policy, policyId) {
    const value = slots.length === 1 ? slots[0].obj[slots[0].key] : slots.map((s) => s.obj[s.key]);
    const k = createHmac("sha256", ck).update(`${policyId || ""}\0${JSON.stringify(value)}`).digest("hex");
    if (cache.has(k)) return { r: cache.get(k), fresh: false };
    return { r: remember(k, maskResult(engine, policy, value, { stage: "output", hash })), fresh: true };
  }
  function mask(kind, body, { engine, policy, policyId } = {}) {
    const out = { changed: false, masked: [], failed: [] };
    for (const slots of resultSlots(kind, body)) {
      const { r, fresh } = one(slots, engine, policy, policyId);
      if (!r) continue;
      if (r.failed) { out.failed.push({ ids: r.ids, fallback: r.fallback }); continue; }
      if (slots.length === 1) slots[0].obj[slots[0].key] = r.value;
      else slots.forEach((s, i) => { s.obj[s.key] = r.value[i]; });
      out.changed = true;
      out.masked.push({ ids: r.ids, count: r.count, fresh });
    }
    return out;
  }
  return { mask };
}
