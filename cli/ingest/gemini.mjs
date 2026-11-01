// Gemini CLI session (~/.gemini/tmp/<project_hash>/chats/session-*.jsonl, or the legacy whole-file .json)
// → the hook inputs the live Gemini hook would have received.
//
// Format, from google-gemini/gemini-cli packages/core/src/services/chatRecordingTypes.ts and
// chatRecordingService.ts (read 2026-10-21; not checked against a session on disk, as no Gemini CLI is
// installed here):
//   file name   `session-` + ISO time + `-` + the first 8 characters of the session id + `.jsonl`; a
//               sub-agent's session is `<sessionId>.jsonl` in a folder named after its parent session; a
//               legacy `.json` path holds one ConversationRecord.
//   JSONL lines a metadata line { sessionId, projectHash, startTime, lastUpdated, kind?: main|subagent,
//               directories?, summary? }; message lines { id, timestamp, type: user|gemini|info|error|warning,
//               content (string or Part[]), toolCalls? }; and update lines { $set: {...} },
//               { $rewindTo: <messageId> } and { $patch: { id?, content?, toolCalls?, ... } }.
//   ToolCallRecord { id, name, args, result? (Part[]), status, timestamp, ... }
//   ConversationRecord (legacy .json) { sessionId, projectHash, startTime, lastUpdated, messages[], kind? }
// A tool call can be recorded before it finishes and updated later (a $patch carrying toolCalls, or the
// message rewritten), so calls are collected by id, merged, and emitted once at end of file. A rewound
// call still ran, so $rewindTo removes nothing. Each call is translated by the SAME adapter the live Gemini
// hook uses (cli/agent-hooks/gemini.mjs toClaude, BeforeTool); the result of web_fetch, the one tool MoorAI
// registers both before and after, is replayed as the AfterTool scan. google_web_search is registered
// after the call only, which the ingest loop cannot replay without a before-call, so it counts as
// unsupported. Gemini CLI does not record hook runs, so a session's hook coverage is unknown.
import { toClaude } from "../agent-hooks/gemini.mjs";

const obj = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : null);

// Part[] / string → text. A function response is { functionResponse: { response: { output | content | ... } } }.
export function partsText(v) {
  if (typeof v === "string") return v;
  if (!Array.isArray(v)) v = v == null ? [] : [v];
  const out = [];
  for (const p of v) {
    if (typeof p === "string") { out.push(p); continue; }
    if (!obj(p)) continue;
    if (typeof p.text === "string") out.push(p.text);
    const r = obj(p.functionResponse) && p.functionResponse.response;
    if (typeof r === "string") out.push(r);
    else if (obj(r)) {
      for (const k of ["output", "content", "llmContent", "result", "error"]) if (typeof r[k] === "string") out.push(r[k]);
    }
  }
  return out.join("\n");
}

export class GeminiParser {
  constructor() {
    this.agent = "gemini";
    this.sessions = new Map();
    this.sessionId = "";
    this.cwd = "";
    this.subagent = false;
    this.unsupported = 0;
    this.malformedArgs = 0;
    this.calls = new Map();
    this.anon = 0;
  }

  meta(rec) {
    if (typeof rec.sessionId === "string" && rec.sessionId) this.sessionId = rec.sessionId;
    if (Array.isArray(rec.directories)) { const d = rec.directories.find((x) => typeof x === "string" && x); if (d) this.cwd = d; }
    if (rec.kind === "subagent") this.subagent = true;
    if (this.sessionId && !this.sessions.has(this.sessionId)) this.sessions.set(this.sessionId, { hookEvidence: false, moorai: false });
  }

  addCalls(list, ts) {
    for (const tc of Array.isArray(list) ? list : []) {
      if (!obj(tc)) continue;
      const key = typeof tc.id === "string" && tc.id ? tc.id : `#${++this.anon}`;
      const prev = this.calls.get(key);
      if (prev) prev.tc = { ...prev.tc, ...tc };
      else this.calls.set(key, { tc, ts: typeof tc.timestamp === "string" ? tc.timestamp : ts, sessionId: this.sessionId, cwd: this.cwd });
    }
  }

  push(rec) {
    const out = [];
    if ("$set" in rec || "$rewindTo" in rec) {
      if (obj(rec.$set) && Array.isArray(rec.$set.directories)) this.meta({ directories: rec.$set.directories });
      return out;
    }
    if ("$patch" in rec) { const p = obj(rec.$patch); if (p) this.addCalls(p.toolCalls, typeof p.timestamp === "string" ? p.timestamp : ""); return out; }
    if (typeof rec.sessionId === "string" && typeof rec.projectHash === "string") { this.meta(rec); return out; }
    if (typeof rec.id !== "string") return out;
    const ts = typeof rec.timestamp === "string" ? rec.timestamp : "";
    if (rec.type === "gemini") { this.addCalls(rec.toolCalls, ts); return out; }
    // A sub-agent session's user turns are its parent's delegation (scanned on the parent's call), not a person.
    if (rec.type !== "user" || this.subagent) return out;
    const prompt = partsText(rec.content);
    if (!prompt.trim()) return out;
    const mapped = toClaude({ hook_event_name: "BeforeAgent", prompt, session_id: this.sessionId, ...(this.cwd ? { cwd: this.cwd } : {}) });
    if (mapped) out.push({ kind: "prompt", agent: this.agent, sessionId: this.sessionId, ts, input: mapped });
    return out;
  }

  // A legacy .json session: one ConversationRecord.
  pushDocument(doc) {
    const out = [];
    if (!obj(doc)) return out;
    this.meta(doc);
    for (const m of Array.isArray(doc.messages) ? doc.messages : []) if (obj(m)) out.push(...this.push(m));
    return out;
  }

  end() {
    const out = [];
    for (const [id, c] of this.calls) {
      const tc = c.tc;
      if (typeof tc.name !== "string" || !tc.name) { this.unsupported++; continue; }
      if (tc.args !== undefined && !obj(tc.args)) { this.malformedArgs++; continue; }
      const base = { session_id: c.sessionId, ...(c.cwd ? { cwd: c.cwd } : {}) };
      const mapped = toClaude({ hook_event_name: "BeforeTool", tool_name: tc.name, tool_input: tc.args || {}, ...base });
      if (!mapped) { this.unsupported++; continue; }
      const ev = { kind: "call", agent: this.agent, sessionId: c.sessionId, ts: c.ts, toolUseId: id.startsWith("#") ? "" : id, input: mapped };
      if (tc.name === "web_fetch" && tc.status === "success" && tc.result != null) {
        const text = partsText(tc.result);
        if (text) { ev.response = text; ev.isError = false; }
      } else if (tc.status === "error") ev.isError = true;
      out.push(ev);
    }
    this.calls.clear();
    return out;
  }
}
