// Claude Code transcript (<session>.jsonl) → the hook inputs the live hook would have received.
//
// Record shapes, read off real transcripts (structure only, never content):
//   assistant  { type:"assistant", sessionId, timestamp, cwd, entrypoint, isSidechain, agentId?,
//                message:{ role:"assistant", content:[{ type:"tool_use", id, name, input }, …] } }
//   tool result{ type:"user", message:{ role:"user", content:[{ type:"tool_result", tool_use_id,
//                content, is_error? }] }, toolUseResult }   — toolUseResult is the structured tool
//                response (Read: { file:{ content } }, Bash: { stdout, stderr, isImage }, …)
//   prompt     { type:"user", message:{ role:"user", content: string | [{ type:"text", text }] },
//                isMeta?, isCompactSummary?, isSidechain }
//   hook trace { type:"system", subtype:"stop_hook_summary", hookInfos:[{ command }] } and
//              { type:"attachment", attachment:{ hookEvent, hookName, command } }
//
// A call is emitted when its result arrives (or at end of file without one), so the replay sees the
// PreToolUse input and the PostToolUse response together.
const MOORAI_HOOK = /moorai-(?:agent-)?hook/;

function text(v) {
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return v.map((b) => (b && typeof b.text === "string" ? b.text : "")).filter(Boolean).join("\n");
  return "";
}

// Read's tool_result text is `cat -n` style ("     1\t…" or "     1→…"). The structured
// toolUseResult.file.content is the raw file and is preferred; this strips the prefix otherwise.
export function stripLineNumbers(s) {
  const lines = String(s).split("\n");
  const re = /^\s*\d+(?:\t|→)/;
  if (!lines.filter((l) => l).every((l) => re.test(l))) return String(s);
  return lines.map((l) => l.replace(re, "")).join("\n");
}

export class ClaudeCodeParser {
  constructor() {
    this.agent = "claude-code";
    this.pending = new Map();
    this.sessions = new Map(); // sessionId -> { hookEvidence, moorai }
    this.sessionId = "";
    this.cwd = "";
    this.source = undefined;
  }

  evidence(sid, command) {
    const s = this.sessions.get(sid) || { hookEvidence: false, moorai: false };
    s.hookEvidence = true;
    if (MOORAI_HOOK.test(command)) s.moorai = true;
    this.sessions.set(sid, s);
  }

  touch(sid) { if (sid && !this.sessions.has(sid)) this.sessions.set(sid, { hookEvidence: false, moorai: false }); }

  push(rec) {
    const out = [];
    if (typeof rec.sessionId === "string" && rec.sessionId) this.sessionId = rec.sessionId;
    if (typeof rec.cwd === "string" && rec.cwd) this.cwd = rec.cwd;
    if (typeof rec.entrypoint === "string") this.source = rec.entrypoint.startsWith("sdk") ? "sdk" : undefined;
    const sid = this.sessionId;
    this.touch(sid);
    const ts = typeof rec.timestamp === "string" ? rec.timestamp : "";
    for (const h of Array.isArray(rec.hookInfos) ? rec.hookInfos : []) if (h && typeof h.command === "string") this.evidence(sid, h.command);
    if (rec.attachment && typeof rec.attachment.command === "string") this.evidence(sid, rec.attachment.command);

    const msg = rec.message;
    if (!msg || typeof msg !== "object") return out;
    if (rec.type === "assistant" && Array.isArray(msg.content)) {
      for (const b of msg.content) {
        if (!b || b.type !== "tool_use" || typeof b.name !== "string") continue;
        this.pending.set(b.id, { tool: b.name, toolInput: b.input && typeof b.input === "object" ? b.input : {}, ts, sessionId: sid, cwd: this.cwd, agentId: typeof rec.agentId === "string" ? rec.agentId : "", toolUseId: typeof b.id === "string" ? b.id : "" });
      }
      return out;
    }
    if (rec.type !== "user") return out;
    const blocks = Array.isArray(msg.content) ? msg.content : null;
    const results = blocks ? blocks.filter((b) => b && b.type === "tool_result") : [];
    if (results.length) {
      for (const r of results) {
        const p = this.pending.get(r.tool_use_id);
        if (!p) continue;
        this.pending.delete(r.tool_use_id);
        const structured = results.length === 1 && rec.toolUseResult !== undefined ? rec.toolUseResult : undefined;
        out.push(this.call(p, { response: structured !== undefined ? structured : r.content, resultText: text(r.content), structured, isError: r.is_error === true }));
      }
      return out;
    }
    // A prompt the person typed into the top-level session. A sub-agent's first message is its parent's
    // delegation (scanned on the Task call), and meta / compaction records are not prompts.
    if (rec.isSidechain === true || rec.isMeta === true || rec.isCompactSummary === true || msg.role !== "user") return out;
    const prompt = text(msg.content);
    if (!prompt.trim()) return out;
    out.push({ kind: "prompt", agent: this.agent, sessionId: sid, ts, input: { hook_event_name: "UserPromptSubmit", prompt, session_id: sid, cwd: this.cwd, ...(this.source ? { source: this.source } : {}) } });
    return out;
  }

  call(p, result) {
    let readText;
    if (p.tool === "Read") {
      const f = result && result.structured && result.structured.file;
      readText = f && typeof f.content === "string" ? f.content : result ? stripLineNumbers(result.resultText) : "";
    }
    return {
      kind: "call", agent: this.agent, sessionId: p.sessionId, ts: p.ts, toolUseId: p.toolUseId,
      input: { hook_event_name: "PreToolUse", tool_name: p.tool, tool_input: p.toolInput, session_id: p.sessionId, cwd: p.cwd, ...(p.agentId ? { agent_id: p.agentId } : {}) },
      ...(readText !== undefined ? { readText } : {}),
      ...(result ? { response: result.response, isError: result.isError } : {})
    };
  }

  end() {
    const out = [];
    for (const p of this.pending.values()) out.push(this.call(p, null));
    this.pending.clear();
    return out;
  }
}
