// GitHub Copilot CLI adapter (@github/copilot; verified against the 1.0.63 JS bundle, the last npm
// release that ships readable JS, and docs.github.com/en/copilot/reference/hooks-configuration).
//
// Hook API: user-level hook files are <COPILOT_HOME or ~/.copilot>/hooks/*.json, each
// { version: 1, hooks: { <event>: [{ type: "command", bash, powershell, timeoutSec }] } }. Repo-level
// .github/hooks/*.json also exist; all sources run. camelCase event names (preToolUse, postToolUse) get
// a camelCase payload on stdin: { sessionId, timestamp, cwd, toolName, toolArgs[, toolResult] }, where
// toolArgs is the model's raw function-arguments JSON STRING (parsed here). PascalCase names get the
// VS Code shape (tool_name mapped to Claude names, tool_input parsed); both are accepted below.
//
// preToolUse answers on stdout: { permissionDecision: "allow"|"deny"|"ask", permissionDecisionReason }.
// "deny" turns the call into a denied tool result the model reads. "ask" opens the CLI's own permission
// prompt; with no interactive user Copilot itself treats it as deny (safe), so ask is passed through.
// postToolUse: { decision: "block", reason } replaces the tool result with "Tool result blocked: …";
// additionalContext is appended to it. Exit 0 is used for every verdict. Failure modes are version-
// dependent: 1.0.63 treats any thrown hook error (non-zero exit, timeout) on preToolUse as a deny
// (fail-closed) but exit 2 as a warning; current docs say exit 2 denies and timeouts fail OPEN.
import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync } from "node:fs";
import { join, isAbsolute, resolve } from "node:path";
import { homedir } from "node:os";

export const id = "copilot";
export const label = "GitHub Copilot CLI";

const MARK = "moorai-agent-hook";
const FILE = "moorai.json";
const TIMEOUT_SEC = 30;

const str = (v) => (typeof v === "string" ? v : "");
const abs = (p, cwd) => (p && cwd && !isAbsolute(p) ? resolve(cwd, p) : p);

// Copilot's own built-in tool names (1.0.63 sZr map plus tools it registers). Anything with a hyphen that
// is not one of these is an MCP tool, named `${server}-${tool}` (jie(), sanitized, capped at 64 chars).
const BUILTIN = new Set(["bash", "powershell", "view", "create", "edit", "str_replace_editor", "apply_patch",
  "grep", "rg", "glob", "web_fetch", "web_search", "ask_user", "update_todo", "task", "report_intent",
  "task_complete", "skill", "write_agent", "read_agent", "list_agents", "read_inbox", "send_inbox",
  "context_board", "exit_plan_mode", "manage_schedule", "fetch_copilot_cli_documentation"]);
// Claude names Copilot substitutes in the PascalCase (VS Code compat) payload.
const FROM_CLAUDE = { Bash: "bash", PowerShell: "powershell", Read: "view", Write: "create", Edit: "edit",
  WebFetch: "web_fetch", WebSearch: "web_search", Agent: "task", Task: "task" };

const sanitize = (s) => String(s).replace(/@/g, "-").replace(/[^a-zA-Z0-9-_]/g, "-");

function copilotHome() { return process.env.COPILOT_HOME || join(homedir(), ".copilot"); }

function knownServers() {
  const names = ["github-mcp-server"];
  try {
    const j = JSON.parse(readFileSync(join(copilotHome(), "mcp-config.json"), "utf8"));
    names.push(...Object.keys(j.mcpServers || {}).map(sanitize));
  } catch { /* no user MCP config */ }
  return names.sort((a, b) => b.length - a.length);
}

function mcpName(name) {
  if (!name.includes("-") || BUILTIN.has(name)) return null;
  const server = knownServers().find((s) => name.startsWith(`${s}-`) && name.length > s.length + 1);
  if (server) return `mcp__${server}__${name.slice(server.length + 1)}`;
  const i = name.indexOf("-");
  return i > 0 && i < name.length - 1 ? `mcp__${name.slice(0, i)}__${name.slice(i + 1)}` : null;
}

function parseArgs(v) {
  if (typeof v !== "string") return v && typeof v === "object" ? v : {};
  try { const j = JSON.parse(v); return j && typeof j === "object" ? j : { input: v }; } catch { return { input: v }; }
}

// apply_patch is a free-form custom tool: "*** Add File: p" / "*** Update File: p" then +/- lines.
function patchEdits(text) {
  let file = "";
  const added = [];
  for (const line of str(text).split("\n")) {
    const m = /^\*\*\* (?:Add|Update) File: (.+)$/.exec(line);
    if (m) { file = file || m[1].trim(); continue; }
    if (line.startsWith("+") && !line.startsWith("+++")) added.push(line.slice(1));
  }
  return { file, content: added.join("\n") };
}

function preTool(name, ti, cwd) {
  switch (name) {
    case "bash":
    case "powershell":
      return ["Bash", { command: str(ti.command) }];
    case "view":
      return ["Read", { file_path: abs(str(ti.path), cwd) }];
    case "create":
      return ["Write", { file_path: abs(str(ti.path), cwd), content: str(ti.file_text) }];
    case "edit":
      return ["Edit", { file_path: abs(str(ti.path), cwd), old_string: str(ti.old_str), new_string: str(ti.new_str) }];
    case "str_replace_editor": {
      const file_path = abs(str(ti.path), cwd);
      if (ti.command === "view") return ["Read", { file_path }];
      if (ti.command === "create") return ["Write", { file_path, content: str(ti.file_text) }];
      if (ti.command === "str_replace" || ti.command === "insert") return ["Edit", { file_path, old_string: str(ti.old_str), new_string: str(ti.new_str) }];
      return null;
    }
    case "apply_patch": {
      const p = patchEdits(ti.input ?? ti.patch);
      return ["MultiEdit", { file_path: abs(p.file, cwd), edits: [{ old_string: "", new_string: p.content }] }];
    }
    case "web_fetch":
      return ["WebFetch", { url: str(ti.url), prompt: "" }];
    case "web_search":
      return ["WebSearch", { query: str(ti.query) }];
    case "task":
      return ["Task", { subagent_type: str(ti.agent_type), prompt: str(ti.prompt), description: str(ti.description) }];
    default: {
      const m = mcpName(name);
      return m ? [m, ti] : null;
    }
  }
}

function isPost(p) { return p.toolResult !== undefined || p.tool_result !== undefined || /^postToolUse$/i.test(str(p.hook_event_name)); }

export function toClaude(payload) {
  if (!payload || typeof payload !== "object") return null;
  const raw = str(payload.toolName) || str(payload.tool_name);
  if (!raw) return null;
  const ti = parseArgs(payload.toolArgs ?? payload.tool_input);
  let name = FROM_CLAUDE[raw] || raw;
  // Compat mode folds str_replace_editor and apply_patch into "Edit"; their argument shapes tell them apart.
  if (raw === "Edit" && typeof ti.command === "string") name = "str_replace_editor";
  else if (raw === "Edit" && (typeof ti.input === "string" || typeof ti.patch === "string")) name = "apply_patch";
  const cwd = str(payload.cwd);
  const session_id = str(payload.sessionId) || str(payload.session_id);
  if (isPost(payload)) {
    const r = payload.toolResult || payload.tool_result || {};
    const text = str(r.textResultForLlm) || str(r.text_result_for_llm);
    if (name === "web_fetch") return { hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: str(ti.url), prompt: "" }, tool_response: text, session_id, cwd };
    if (name === "web_search") return { hook_event_name: "PostToolUse", tool_name: "WebSearch", tool_input: { query: str(ti.query) }, tool_response: text, session_id, cwd };
    return null;
  }
  const t = preTool(name, ti, cwd);
  if (!t) return null;
  return { hook_event_name: "PreToolUse", tool_name: t[0], tool_input: t[1], session_id, cwd };
}

export function fromVerdict(verdict, payload) {
  const v = verdict || {};
  const reason = `MoorAI: ${v.reason || "blocked by policy"}`;
  if (isPost(payload || {})) {
    if (v.decision === "deny") return { stdout: JSON.stringify({ decision: "block", reason }), exitCode: 0 };
    if (v.context) return { stdout: JSON.stringify({ additionalContext: `MoorAI: ${v.context}` }), exitCode: 0 };
    return { exitCode: 0 };
  }
  if (v.decision === "deny" || v.decision === "ask") {
    return { stdout: JSON.stringify({ permissionDecision: v.decision, permissionDecisionReason: reason }), exitCode: 0 };
  }
  if (v.context) return { stdout: JSON.stringify({ additionalContext: `MoorAI: ${v.context}` }), exitCode: 0 };
  return { exitCode: 0 };
}

function hooksFile(home) {
  const base = process.env.COPILOT_HOME && home === homedir() ? process.env.COPILOT_HOME : join(home, ".copilot");
  return join(base, "hooks", FILE);
}

const isOurs = (e) => JSON.stringify(e || {}).includes(MARK) && JSON.stringify(e || {}).includes(` ${id}`);

function readCfg(file) {
  if (!existsSync(file)) return { version: 1, hooks: {} };
  const j = JSON.parse(readFileSync(file, "utf8")); // unparseable: throw rather than overwrite it
  if (!j.hooks || typeof j.hooks !== "object") j.hooks = {};
  return j;
}

function strip(cfg) {
  for (const ev of Object.keys(cfg.hooks)) {
    if (!Array.isArray(cfg.hooks[ev])) continue;
    cfg.hooks[ev] = cfg.hooks[ev].filter((e) => !isOurs(e));
    if (!cfg.hooks[ev].length) delete cfg.hooks[ev];
  }
}

export function install({ home, command }) {
  const file = hooksFile(home);
  const cfg = readCfg(file);
  strip(cfg);
  if (cfg.version === undefined) cfg.version = 1;
  const entry = { type: "command", bash: command, powershell: command, timeoutSec: TIMEOUT_SEC };
  for (const ev of ["preToolUse", "postToolUse"]) cfg.hooks[ev] = [...(cfg.hooks[ev] || []), { ...entry }];
  mkdirSync(join(file, ".."), { recursive: true });
  writeFileSync(file, JSON.stringify(cfg, null, 2) + "\n");
  return file;
}

export function uninstall({ home }) {
  const file = hooksFile(home);
  if (!existsSync(file)) return file;
  const cfg = readCfg(file);
  strip(cfg);
  const others = Object.keys(cfg).filter((k) => k !== "version" && k !== "hooks");
  if (!Object.keys(cfg.hooks).length && !others.length) unlinkSync(file);
  else writeFileSync(file, JSON.stringify(cfg, null, 2) + "\n");
  return file;
}
