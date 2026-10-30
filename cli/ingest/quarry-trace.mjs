// One transcript file → the ordered conversation a Quarry trace is built from (cli/ingest/quarry.mjs).
// The hook-input parsers (claude-code.mjs, codex.mjs, gemini.mjs) keep only what the replay judges; this
// keeps the turn order, the assistant text and every tool call under the HOST's own tool name, with its
// result. Items:
//   { role: "user", text }
//   { role: "assistant", text, calls: [{ hostId, name, input, rawArgs? }] }
//   { role: "tool", hostId, text, isError, call? }   call: the call object itself, where the format nests results
// hostId joins a call to the replay verdict the hook-input parser produced for it (its toolUseId).
// Record shapes are the ones those parsers document; the result records read here (Codex
// function_call_output / custom_tool_call_output, Claude tool_result, Gemini ToolCallRecord.result) are
// their sibling records in the same formats.
import { partsText } from "./gemini.mjs";

const obj = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : null);
const blocksText = (v) => (typeof v === "string" ? v : Array.isArray(v) ? v.map((b) => (b && typeof b.text === "string" ? b.text : "")).filter(Boolean).join("\n") : "");

class Items {
  constructor() { this.items = []; this.open = null; this.sessionId = ""; this.agentId = ""; }
  user(text) { this.close(); this.items.push({ role: "user", text }); }
  text(text) {
    if (this.open && this.open.calls.length) this.close();
    if (!this.open) this.open = { role: "assistant", text: "", calls: [] };
    this.open.text = this.open.text ? `${this.open.text}\n${text}` : text;
  }
  call(c) { if (!this.open) this.open = { role: "assistant", text: "", calls: [] }; this.open.calls.push(c); }
  tool(hostId, text, isError, call) { this.close(); this.items.push({ role: "tool", hostId, text, isError: !!isError, ...(call ? { call } : {}) }); }
  close() { if (this.open) this.items.push(this.open); this.open = null; }
  end() { this.close(); return this.items; }
}

export class ClaudeCodeTrace extends Items {
  push(rec) {
    if (typeof rec.sessionId === "string" && rec.sessionId && !this.sessionId) this.sessionId = rec.sessionId;
    if (typeof rec.agentId === "string" && rec.agentId && !this.agentId) this.agentId = rec.agentId;
    const msg = obj(rec.message);
    if (!msg) return;
    if (rec.type === "assistant" && Array.isArray(msg.content)) {
      for (const b of msg.content) {
        if (!b) continue;
        if (b.type === "text" && typeof b.text === "string" && b.text) this.text(b.text);
        else if (b.type === "tool_use" && typeof b.name === "string" && b.name) this.call({ hostId: typeof b.id === "string" ? b.id : "", name: b.name, input: obj(b.input) || {} });
      }
      return;
    }
    if (rec.type !== "user") return;
    const results = Array.isArray(msg.content) ? msg.content.filter((b) => b && b.type === "tool_result") : [];
    if (results.length) { for (const r of results) this.tool(typeof r.tool_use_id === "string" ? r.tool_use_id : "", blocksText(r.content), r.is_error === true); return; }
    if (rec.isMeta === true || rec.isCompactSummary === true || msg.role !== "user") return;
    const t = blocksText(msg.content);
    if (t.trim()) this.user(t);
  }
}

function codexOutput(v) {
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return blocksText(v);
  const o = obj(v);
  if (o && typeof o.content === "string") return o.content;
  return o && Array.isArray(o.content) ? blocksText(o.content) : "";
}

export class CodexTrace extends Items {
  push(rec) {
    const p = obj(rec.payload);
    if (!p) return;
    if (rec.type === "session_meta") {
      const sid = typeof p.session_id === "string" && p.session_id ? p.session_id : typeof p.id === "string" ? p.id : "";
      if (sid && !this.sessionId) this.sessionId = sid;
      return;
    }
    if (rec.type === "event_msg") {
      let t = null;
      if (p.type === "user_message" && typeof p.message === "string") t = p.message;
      else if (p.type === "item_completed" && obj(p.item) && p.item.type === "UserMessage" && Array.isArray(p.item.content)) t = blocksText(p.item.content);
      if (t != null && t.trim()) this.user(t);
      return;
    }
    if (rec.type !== "response_item") return;
    const id = typeof p.call_id === "string" ? p.call_id : "";
    if (p.type === "message" && p.role === "assistant") { const t = blocksText(p.content); if (t) this.text(t); return; }
    if (p.type === "function_call" && typeof p.name === "string" && p.name) {
      const ns = typeof p.namespace === "string" ? p.namespace : "";
      const mcp = ns.startsWith("mcp__") || p.name.startsWith("mcp__");
      const joined = ns ? `${ns.replace(/_+$/, "")}__${p.name.replace(/^_+/, "")}` : p.name;
      const name = mcp ? (joined.startsWith("mcp__") ? joined : `mcp__${joined}`) : p.name;
      let input = null;
      try { const a = JSON.parse(typeof p.arguments === "string" ? p.arguments : "{}"); input = obj(a) || { input: a }; } catch { input = null; }
      this.call({ hostId: id, name, input });
      return;
    }
    if (p.type === "custom_tool_call" && typeof p.name === "string" && p.name) { this.call({ hostId: id, name: p.name, input: { input: typeof p.input === "string" ? p.input : "" } }); return; }
    if (p.type === "local_shell_call") {
      const argv = obj(p.action) && p.action.command;
      this.call({ hostId: id, name: "local_shell", input: Array.isArray(argv) ? { command: argv } : {} });
      return;
    }
    if ((p.type === "function_call_output" || p.type === "custom_tool_call_output") && id) this.tool(id, codexOutput(p.output), false);
  }
}

// Gemini CLI: a call is recorded inside its message and can be patched later, so messages and calls are
// collected by id and rendered at end of file in first-seen order.
export class GeminiTrace extends Items {
  constructor() { super(); this.msgs = []; this.byId = new Map(); this.calls = new Map(); this.anon = 0; }
  addCalls(m, list) {
    for (const tc of Array.isArray(list) ? list : []) {
      if (!obj(tc)) continue;
      const key = typeof tc.id === "string" && tc.id ? tc.id : `#${++this.anon}`;
      const prev = this.calls.get(key);
      if (prev) { prev.tc = { ...prev.tc, ...tc }; continue; }
      this.calls.set(key, { tc });
      m.callIds.push(key);
    }
  }
  message(id, type, content) {
    let m = id ? this.byId.get(id) : null;
    if (!m) { m = { type, content, callIds: [] }; this.msgs.push(m); if (id) this.byId.set(id, m); }
    else if (content !== undefined) m.content = content;
    return m;
  }
  push(rec) {
    if (Array.isArray(rec.messages) && typeof rec.sessionId === "string") { this.meta(rec); for (const m of rec.messages) if (obj(m)) this.push(m); return; }
    if ("$set" in rec || "$rewindTo" in rec) return;
    if ("$patch" in rec) { const p = obj(rec.$patch); if (p) this.addCalls(this.message(typeof p.id === "string" ? p.id : "", "gemini", p.content), p.toolCalls); return; }
    if (typeof rec.sessionId === "string" && typeof rec.projectHash === "string") { this.meta(rec); return; }
    if (typeof rec.id !== "string") return;
    if (rec.type === "gemini") { this.addCalls(this.message(rec.id, "gemini", rec.content), rec.toolCalls); return; }
    if (rec.type === "user") this.message(rec.id, "user", rec.content);
  }
  meta(rec) { if (typeof rec.sessionId === "string" && rec.sessionId && !this.sessionId) this.sessionId = rec.sessionId; }
  end() {
    for (const m of this.msgs) {
      if (m.type === "user") { const t = partsText(m.content); if (t.trim()) this.user(t); continue; }
      const t = partsText(m.content);
      if (t) this.text(t);
      const done = [];
      for (const key of m.callIds) {
        const tc = this.calls.get(key).tc;
        if (typeof tc.name !== "string" || !tc.name) continue;
        const hostId = key.startsWith("#") ? "" : key;
        const call = { hostId, name: tc.name, input: tc.args === undefined ? {} : obj(tc.args) };
        this.call(call);
        if (tc.result != null || tc.status === "error" || tc.status === "success") done.push({ call, tc });
      }
      for (const { call, tc } of done) this.tool(call.hostId, tc.result != null ? partsText(tc.result) : "", tc.status === "error", call);
    }
    return super.end();
  }
}

export const TRACES = { "claude-code": ClaudeCodeTrace, codex: CodexTrace, gemini: GeminiTrace };
