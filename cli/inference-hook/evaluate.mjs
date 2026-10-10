// One verdict per Inference hooks frame, decided by the MoorAI runtime (packages/agent-sdk/src/runtime.mjs:
// buildEngine / decideText from cli/hook-core.mjs, the verified policy, content-free reporting), so a
// verdict here is the verdict moorai-serve's /v1/scan reaches for the same text.
//
// CONTENT ONLY. A tool call frame describes a call that runs on the user's machine or in Anthropic's
// sandbox, not on this server, so tool calls are judged by their content (a shell command, a URL, else
// the argument JSON) and never by the hook's file-reading branches (Read of a credential file, MCP file
// arguments, local secret egress): those would read THIS server's files at paths a model chose.
//
// A prompt frame re-sends the whole conversation every turn, so each item is judged once per
// conversation: an HMAC of (policy id, session_id or request_id, stage, ctx, text) → verdict in a bounded
// LRU. A repeat is neither re-scanned nor re-reported, and a denied item stays denied.
//
// What could not be judged is returned as `unevaluated` (an item past the scan cap — its prefix is still
// judged —, more new items than one frame scans, the evaluation deadline); the caller applies --fail.
import { createHmac, randomBytes } from "node:crypto";
import { mapTool } from "../../model-proxy/check.mjs";
import { promptItems, toolCalls } from "./transcript.mjs";

export const ITEM_CAP = 524288;
export const MAX_NEW_ITEMS = 512;
export const CACHE_SIZE = 8192;
export const safeName = (s) => String(s || "").replace(/[^A-Za-z0-9_.:\-]/g, "_").slice(0, 64);

function toolItem(c) {
  const name = safeName(c.name) || "tool";
  const m = c.raw == null ? mapTool(c.name, c.input) : null;
  if (m && (m.tool === "Bash" || m.tool === "PowerShell") && typeof m.input.command === "string") return { kind: "tool_call", name, stage: "prompt", ctx: {}, text: m.input.command };
  if (m && m.tool === "WebFetch") return { kind: "tool_call", name, stage: "prompt", ctx: { egress: true }, text: `${m.input.url || ""}\n${m.input.prompt || ""}` };
  return { kind: "tool_call", name, stage: "prompt", ctx: {}, text: c.raw != null ? String(c.raw) : JSON.stringify(c.input) };
}

export function createEvaluator(rt, { itemCap = ITEM_CAP, maxItems = MAX_NEW_ITEMS, cacheSize = CACHE_SIZE, now = () => Date.now() } = {}) {
  const cache = new Map();
  const remember = (k, v) => { cache.delete(k); cache.set(k, v); if (cache.size > cacheSize) cache.delete(cache.keys().next().value); return v; };
  // A per-process random key, never the runtime's content hash: that one is a constant on an unenrolled
  // server (cli/content-hash.mjs NO_KEY), which would make every item a cache hit of the first.
  const cacheKey = randomBytes(32);
  const keyOf = (s) => createHmac("sha256", cacheKey).update(s, "utf8").digest("base64");

  // frame: a parsed prompt or tool_call frame. → { denied: [{kind, name?, reasons}], unevaluated: [{kind, why}] }
  async function evaluate(frame, { deadline = Infinity, session } = {}) {
    const s = await rt.ready();
    const isPrompt = frame.type === "prompt";
    const items = isPrompt ? promptItems(frame) : toolCalls(frame).map(toolItem);
    const event = isPrompt ? "ModelRequest" : "PreToolUse";
    const scope = session ? `s:${session}` : `r:${frame.request_id}`;
    const denied = [], unevaluated = [];
    let fresh = 0;
    for (const it of items) {
      const key = keyOf(`${s.policyId}\0${scope}\0${it.stage}\0${JSON.stringify(it.ctx)}\0${it.text}`);
      let v = cache.get(key);
      if (v) remember(key, v);
      else {
        if (now() > deadline) { unevaluated.push({ kind: it.kind, why: "timeout" }); break; }
        if (fresh >= maxItems) { unevaluated.push({ kind: "request", why: "items" }); break; }
        fresh++;
        const over = it.text.length > itemCap;
        if (over) unevaluated.push({ kind: it.kind, why: "size" });
        const r = await rt.scan(over ? it.text.slice(0, itemCap) : it.text, it.stage, it.ctx, { tool: it.name || it.kind, event, ...(session ? { session } : {}) });
        v = { decision: r.decision, reasons: r.reasons };
        if (!over) remember(key, v);
      }
      if (v.decision === "deny") denied.push({ kind: it.kind, ...(it.name ? { name: it.name } : {}), reasons: v.reasons });
    }
    return { denied, unevaluated };
  }

  return { evaluate, cacheSize: () => cache.size };
}
