// Cursor adapter (the IDE agent and the `cursor-agent` CLI). Sources, checked 2026-09-16:
//   docs  https://cursor.com/docs/hooks.md
//   CLI   cursor-agent 2026.05.27-fe9a6e2, bundled 3880.index.js / index.js ("../hooks/dist/index.js")
//
// Cursor's hooks are keyed by EVENT, not by tool, so toClaude branches on hook_event_name:
//   beforeShellExecution {command, cwd, sandbox}                  -> Bash {command}
//   beforeMCPExecution   {tool_name, tool_input: JSON string, mcp_server_name}
//                                                                 -> mcp__<server>__<tool> {parsed args}
//   beforeReadFile       {file_path, content, attachments}        -> Read {file_path}
//   preToolUse           {tool_name, tool_input, cwd}  Write {file_path, content} -> Write
//                                                      Fetch/WebFetch {url}      -> WebFetch
//   postToolUse          {tool_name, tool_input, tool_output: JSON string}
//                                                      Fetch/WebFetch/WebSearch  -> PostToolUse
//   subagentStart        {subagent_type, task}                    -> Task {subagent_type, prompt}
//   afterFileEdit        {file_path, edits[]}                     -> MultiEdit (DETECTION ONLY: the
//                                                                    edit already happened and the
//                                                                    event has no output fields)
// beforeSubmitPrompt, afterShellExecution, afterMCPExecution and the other preToolUse tools (Delete,
// Grep, List, ...) have no MoorAI branch; toClaude returns null for them (allow).
//
// Output. Permission events answer with JSON on stdout and exit 0. Every permission answer is
// written out, allow included: an empty stdout is logged as a hook failure (fail-open), and invalid
// JSON on a permission event BLOCKS the action even without failClosed.
//   beforeShellExecution / beforeMCPExecution  permission allow | deny | ask
//   preToolUse     allow | deny ("ask" is accepted by the schema but not enforced, per the docs)
//   beforeReadFile allow | deny (no ask)
//   subagentStart  allow | deny ("ask" is treated as deny by Cursor)
// Where the event cannot express ask, ask maps to allow plus a stderr note. That follows Cursor's own
// handling of ask on preToolUse, and MoorAI's rule that an unmeasured hard block does not go on a hot path.
import { readFileSync, writeFileSync, mkdirSync, existsSync, renameSync } from "node:fs";
import { join, dirname } from "node:path";

export const id = "cursor";
export const label = "Cursor";

const MARK = "moorai-agent-hook";
const FETCH_TOOLS = new Set(["Fetch", "WebFetch"]);

function parseJson(s) {
  if (s && typeof s === "object") return s;
  if (typeof s !== "string") return {};
  try { const v = JSON.parse(s); return v && typeof v === "object" ? v : {}; } catch { return {}; }
}

function writeInput(ti) {
  const file_path = typeof ti.file_path === "string" ? ti.file_path : (typeof ti.path === "string" ? ti.path : "");
  if (Array.isArray(ti.edits)) return { tool_name: "MultiEdit", tool_input: { file_path, edits: ti.edits } };
  if (typeof ti.new_string === "string") return { tool_name: "Edit", tool_input: { file_path, old_string: ti.old_string || "", new_string: ti.new_string } };
  return { tool_name: "Write", tool_input: { file_path, content: typeof ti.content === "string" ? ti.content : "" } };
}

export function toClaude(p) {
  if (!p || typeof p !== "object") return null;
  const base = { session_id: p.conversation_id || p.session_id || "", cwd: p.cwd || (Array.isArray(p.workspace_roots) ? p.workspace_roots[0] : undefined) };
  const pre = (m) => (m ? { hook_event_name: "PreToolUse", ...m, ...base } : null);
  switch (p.hook_event_name) {
    case "beforeShellExecution":
      return typeof p.command === "string" ? pre({ tool_name: "Bash", tool_input: { command: p.command } }) : null;
    case "beforeMCPExecution": {
      if (typeof p.tool_name !== "string" || !p.tool_name) return null;
      const server = String(p.mcp_server_name || "unknown").replace(/__/g, "_");
      return pre({ tool_name: `mcp__${server}__${p.tool_name}`, tool_input: parseJson(p.tool_input) });
    }
    case "beforeReadFile":
      return typeof p.file_path === "string" ? pre({ tool_name: "Read", tool_input: { file_path: p.file_path } }) : null;
    case "preToolUse": {
      const ti = parseJson(p.tool_input);
      if (p.tool_name === "Write") return pre(writeInput(ti));
      if (FETCH_TOOLS.has(p.tool_name)) return pre({ tool_name: "WebFetch", tool_input: { url: typeof ti.url === "string" ? ti.url : "", prompt: "" } });
      return null;
    }
    case "postToolUse": {
      const ti = parseJson(p.tool_input);
      const tool = FETCH_TOOLS.has(p.tool_name) ? "WebFetch" : p.tool_name === "WebSearch" ? "WebSearch" : null;
      if (!tool) return null;
      const tool_input = tool === "WebFetch" ? { url: ti.url || "", prompt: "" } : { query: ti.query || ti.search_term || "" };
      const out = p.tool_output;
      const parsed = typeof out === "string" ? parseJson(out) : out;
      const tool_response = parsed && typeof parsed === "object" && Object.keys(parsed).length ? parsed : out;
      return { hook_event_name: "PostToolUse", tool_name: tool, tool_input, tool_response, ...base };
    }
    case "subagentStart":
      return pre({ tool_name: "Task", tool_input: { subagent_type: p.subagent_type || "", prompt: typeof p.task === "string" ? p.task : "" } });
    case "afterFileEdit":
      return typeof p.file_path === "string" ? pre({ tool_name: "MultiEdit", tool_input: { file_path: p.file_path, edits: Array.isArray(p.edits) ? p.edits : [] } }) : null;
    default:
      return null;
  }
}

const msg = (v) => `MoorAI: ${v.reason || (v.decision === "deny" ? "blocked by policy" : "needs justification")}`;
const json = (o) => ({ stdout: JSON.stringify(o), exitCode: 0 });

export function fromVerdict(v, p) {
  const decision = v && v.decision ? v.decision : "allow";
  const ev = p && p.hook_event_name;
  switch (ev) {
    case "beforeShellExecution":
    case "beforeMCPExecution":
      if (decision === "allow") return json({ permission: "allow" });
      return json({ permission: decision, user_message: msg(v), agent_message: msg(v) });
    case "preToolUse":
      if (decision === "deny") return json({ permission: "deny", user_message: msg(v), agent_message: msg(v) });
      return { ...json({ permission: "allow" }), ...(decision === "ask" ? { stderr: `${msg(v)} (preToolUse cannot ask; allowed)\n` } : {}) };
    case "beforeReadFile":
    case "subagentStart":
      if (decision === "deny") return json({ permission: "deny", user_message: msg(v) });
      return { ...json({ permission: "allow" }), ...(decision === "ask" ? { stderr: `${msg(v)} (${ev} cannot ask; allowed)\n` } : {}) };
    case "postToolUse": {
      const ctx = v && (v.context || (decision !== "allow" ? msg(v) : ""));
      return ctx ? json({ additional_context: ctx.startsWith("MoorAI:") ? ctx : `MoorAI: ${ctx}` }) : { exitCode: 0 };
    }
    default:
      // afterFileEdit and every unregistered event: nothing can be blocked, so report only.
      return decision === "allow" ? { exitCode: 0 } : { stderr: `${msg(v)} (detected after the fact; not blocked)\n`, exitCode: 0 };
  }
}

// ---- install / uninstall: ~/.cursor/hooks.json ----
const EVENTS = {
  beforeShellExecution: null,
  beforeMCPExecution: null,
  beforeReadFile: null,
  preToolUse: "^(Write|Fetch|WebFetch)$",
  postToolUse: "^(Fetch|WebFetch|WebSearch)$",
  subagentStart: null,
  afterFileEdit: null,
};

const hooksPath = (home) => join(home, ".cursor", "hooks.json");
const isOurs = (e) => !!e && typeof e.command === "string" && e.command.includes(MARK) && /\bcursor\s*$/.test(e.command);

function load(home) {
  const f = hooksPath(home);
  if (!existsSync(f)) return { version: 1, hooks: {} };
  const cfg = JSON.parse(readFileSync(f, "utf8"));
  if (!cfg || typeof cfg !== "object" || Array.isArray(cfg)) throw new Error(`${f} is not a JSON object; not modifying it`);
  if (!cfg.hooks || typeof cfg.hooks !== "object") cfg.hooks = {};
  if (cfg.version === undefined) cfg.version = 1;
  return cfg;
}

function save(home, cfg) {
  const f = hooksPath(home);
  mkdirSync(dirname(f), { recursive: true });
  const tmp = `${f}.moorai-${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(cfg, null, 2) + "\n");
  renameSync(tmp, f);
}

function strip(cfg) {
  for (const ev of Object.keys(cfg.hooks)) {
    if (!Array.isArray(cfg.hooks[ev])) continue;
    cfg.hooks[ev] = cfg.hooks[ev].filter((e) => !isOurs(e));
    if (!cfg.hooks[ev].length) delete cfg.hooks[ev];
  }
}

export function install({ home, command }) {
  const cfg = load(home);
  strip(cfg);
  for (const [ev, matcher] of Object.entries(EVENTS)) {
    const entry = { command, timeout: 30, ...(matcher ? { matcher } : {}) };
    cfg.hooks[ev] = [...(Array.isArray(cfg.hooks[ev]) ? cfg.hooks[ev] : []), entry];
  }
  save(home, cfg);
}

export function uninstall({ home }) {
  if (!existsSync(hooksPath(home))) return;
  const cfg = load(home);
  strip(cfg);
  save(home, cfg);
}
