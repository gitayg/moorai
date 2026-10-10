// Codex rollout (rollout-<ts>-<id>.jsonl) → the hook inputs the live hook would have received.
//
// Format, from codex-rs (history/src/rollout_payload.rs RolloutItemWire, protocol/src/models.rs
// ResponseItem, protocol/src/protocol.rs EventMsg) and checked against a real rollout's structure:
//   { timestamp, type:"session_meta",  payload:{ session_id?, id, cwd, … } }   session_id = root thread
//   { timestamp, type:"turn_context",  payload:{ cwd, … } }
//   { timestamp, type:"response_item", payload:{ type:"function_call", name, namespace?, arguments:"<json>", call_id } }
//   { timestamp, type:"response_item", payload:{ type:"custom_tool_call", name, input, call_id } }
//   { timestamp, type:"response_item", payload:{ type:"local_shell_call", action:{ type:"exec", command:[…] } } }
//   { timestamp, type:"event_msg",     payload:{ type:"user_message", message } }            (legacy history)
//   { timestamp, type:"event_msg",     payload:{ type:"item_completed", item:{ type:"UserMessage", content:[{ type:"text", text }] } } }
// Each call is turned into the payload Codex hands a PreToolUse hook (tool names from
// codex-rs/core/src/tools/hook_names.rs and handlers/: Bash for exec_command — tool_input
// { command: cmd } — apply_patch, view_image, spawn_agent, mcp__<namespace>__<tool>) and then
// translated by the SAME adapter the live Codex hook uses (cli/agent-hooks/codex.mjs toClaude).
// MoorAI registers only PreToolUse and UserPromptSubmit with Codex, so there is no result replay.
// Codex does not persist hook runs to the rollout (rollout/src/policy.rs drops HookStarted /
// HookCompleted), so a Codex session's hook coverage cannot be told from its transcript.
import { toClaude } from "../agent-hooks/codex.mjs";

const SHELLS = new Set(["bash", "sh", "zsh", "/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash", "/usr/bin/zsh"]);

// A legacy argv (["bash","-lc","<script>"]) as the command string the hook judges.
export function argvCommand(argv) {
  if (!Array.isArray(argv) || !argv.every((a) => typeof a === "string")) return null;
  if (argv.length >= 3 && SHELLS.has(argv[0]) && /^-l?c$/.test(argv[1])) return argv.slice(2).join(" ");
  return argv.join(" ");
}

function mcpName(namespace, name) {
  const joined = namespace ? `${namespace.replace(/_+$/, "")}__${name.replace(/^_+/, "")}` : name;
  return joined.startsWith("mcp__") ? joined : `mcp__${joined}`;
}

// → [codexToolName, codexToolInput] or null for a tool the Codex hook is not registered for.
export function codexHookCall(p) {
  if (p.type === "local_shell_call") {
    const c = argvCommand(p.action && p.action.command);
    return c == null ? null : ["Bash", { command: c }];
  }
  if (p.type === "custom_tool_call") {
    if (p.name === "apply_patch" && typeof p.input === "string") return ["apply_patch", { command: p.input }];
    return null;
  }
  if (p.type !== "function_call" || typeof p.name !== "string") return null;
  let args;
  try { args = JSON.parse(p.arguments || "{}"); } catch { return { malformed: true }; }
  if (!args || typeof args !== "object") args = {};
  const ns = typeof p.namespace === "string" ? p.namespace : "";
  if (ns.startsWith("mcp__") || p.name.startsWith("mcp__")) return [mcpName(ns, p.name), args];
  if (ns) return null;
  switch (p.name) {
    case "exec_command": return typeof args.cmd === "string" ? ["Bash", { command: args.cmd }] : null;
    case "shell_command": return typeof args.command === "string" ? ["Bash", { command: args.command }] : null;
    case "shell": { const c = argvCommand(args.command); return c == null ? null : ["Bash", { command: c }]; }
    case "apply_patch": return typeof args.input === "string" ? ["apply_patch", { command: args.input }] : null;
    case "view_image": return ["view_image", args];
    case "spawn_agent": return ["spawn_agent", args];
    default: return null;
  }
}

const CALL_TYPES = new Set(["function_call", "custom_tool_call", "local_shell_call"]);

export class CodexParser {
  constructor() {
    this.agent = "codex";
    this.sessions = new Map();
    this.sessionId = "";
    this.cwd = "";
    this.unsupported = 0;
    this.malformedArgs = 0;
  }

  push(rec) {
    const out = [];
    const p = rec.payload;
    if (!p || typeof p !== "object") return out;
    const ts = typeof rec.timestamp === "string" ? rec.timestamp : "";
    if (rec.type === "session_meta") {
      const sid = typeof p.session_id === "string" && p.session_id ? p.session_id : typeof p.id === "string" ? p.id : "";
      if (sid) this.sessionId = sid;
      if (typeof p.cwd === "string") this.cwd = p.cwd;
      if (this.sessionId && !this.sessions.has(this.sessionId)) this.sessions.set(this.sessionId, { hookEvidence: false, moorai: false });
      return out;
    }
    if (rec.type === "turn_context") { if (typeof p.cwd === "string") this.cwd = p.cwd; return out; }
    const base = { session_id: this.sessionId, ...(this.cwd ? { cwd: this.cwd } : {}) };
    if (rec.type === "response_item" && CALL_TYPES.has(p.type)) {
      const hc = codexHookCall(p);
      if (hc && hc.malformed) { this.malformedArgs++; return out; }
      const mapped = hc && toClaude({ hook_event_name: "PreToolUse", tool_name: hc[0], tool_input: hc[1], ...base });
      if (!mapped) { this.unsupported++; return out; }
      out.push({ kind: "call", agent: this.agent, sessionId: this.sessionId, ts, toolUseId: typeof p.call_id === "string" ? p.call_id : "", input: mapped });
      return out;
    }
    if (rec.type === "event_msg") {
      let prompt = null;
      if (p.type === "user_message" && typeof p.message === "string") prompt = p.message;
      else if (p.type === "item_completed" && p.item && p.item.type === "UserMessage" && Array.isArray(p.item.content)) {
        prompt = p.item.content.map((c) => (c && typeof c.text === "string" ? c.text : "")).filter(Boolean).join("\n");
      }
      if (prompt == null || !prompt.trim()) return out;
      const mapped = toClaude({ hook_event_name: "UserPromptSubmit", prompt, ...base });
      if (mapped) out.push({ kind: "prompt", agent: this.agent, sessionId: this.sessionId, ts, input: mapped });
    }
    return out;
  }

  end() { return []; }
}
