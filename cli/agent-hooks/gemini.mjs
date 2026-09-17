// Gemini CLI adapter (@google/gemini-cli, verified against 0.60.0 source).
//
// Hook API: ~/.gemini/settings.json → hooks.{BeforeTool,AfterTool}[] = { matcher (regex on tool name),
// hooks: [{ type:"command", command, name, timeout }] }. The command gets the event JSON on stdin and
// answers with JSON on stdout. BeforeTool: decision "deny"/"block" stops the tool and `reason` goes to
// the model as a tool error; decision "ask" forces the interactive confirmation dialog (systemMessage is
// shown in it). AfterTool: decision "deny" replaces the tool result with `reason`;
// hookSpecificOutput.additionalContext is appended to it. Exit 0 is used for every verdict: exit 2 also
// blocks, but Gemini counts any non-zero exit as a failed hook and shows a warning banner for it.
// A timeout or crash is dropped from aggregation, so the tool runs (fail open).
import { existsSync, readFileSync, writeFileSync, mkdirSync, copyFileSync } from "node:fs";
import { join, dirname, isAbsolute, resolve } from "node:path";

export const id = "gemini";
export const label = "Gemini CLI";

const HOOK_NAME = "moorai";
const PRE_MATCHER = "^(run_shell_command|read_file|read_many_files|write_file|replace|web_fetch|invoke_agent|mcp_.+)$";
const POST_MATCHER = "^(web_fetch|google_web_search)$";

const str = (v) => (typeof v === "string" ? v : "");
const abs = (p, cwd) => (p && cwd && !isAbsolute(p) ? resolve(cwd, p) : p);
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

function mcpName(payload) {
  const m = payload.mcp_context;
  if (m && m.server_name && m.tool_name) return `mcp__${m.server_name}__${m.tool_name}`;
  const x = /^mcp_([^_]+)_(.+)$/.exec(payload.tool_name || "");
  return x ? `mcp__${x[1]}__${x[2]}` : null;
}

function preTool(name, ti, payload) {
  const cwd = str(payload.cwd);
  switch (name) {
    case "run_shell_command":
      return ["Bash", { command: str(ti.command) }];
    case "read_file":
      return ["Read", { file_path: abs(str(ti.file_path), cwd) }];
    case "read_many_files": {
      const list = [].concat(ti.include ?? ti.paths ?? []).filter((p) => typeof p === "string" && p);
      if (!list.length) return null;
      return ["Bash", { command: `cat ${list.map((p) => shq(abs(p, cwd))).join(" ")}` }];
    }
    case "write_file":
      return ["Write", { file_path: abs(str(ti.file_path), cwd), content: str(ti.content) }];
    case "replace":
      return ["Edit", { file_path: abs(str(ti.file_path), cwd), old_string: str(ti.old_string), new_string: str(ti.new_string) }];
    case "web_fetch": {
      const prompt = str(ti.prompt);
      const url = str(ti.url) || (prompt.match(/https?:\/\/[^\s<>"'`)\]]+/) || [""])[0];
      return ["WebFetch", { url, prompt }];
    }
    case "invoke_agent":
      return ["Task", { subagent_type: str(ti.agent_name), prompt: str(ti.prompt) }];
    default: {
      const m = mcpName(payload);
      return m ? [m, ti] : null;
    }
  }
}

const POST_TOOLS = { web_fetch: "WebFetch", google_web_search: "WebSearch" };

export function toClaude(payload) {
  if (!payload || typeof payload !== "object") return null;
  const name = str(payload.tool_name);
  const ti = payload.tool_input && typeof payload.tool_input === "object" ? payload.tool_input : {};
  const base = { session_id: str(payload.session_id), ...(payload.cwd ? { cwd: payload.cwd } : {}) };
  if (payload.hook_event_name === "BeforeTool") {
    const m = preTool(name, ti, payload);
    if (!m) return null;
    return { hook_event_name: "PreToolUse", tool_name: m[0], tool_input: m[1], ...base };
  }
  if (payload.hook_event_name === "AfterTool") {
    const t = POST_TOOLS[name];
    if (!t) return null;
    const r = payload.tool_response || {};
    const tool_response = typeof r.llmContent === "string" ? r.llmContent : r;
    const tool_input = t === "WebFetch" ? preTool(name, ti, payload)[1] : { query: str(ti.query) };
    return { hook_event_name: "PostToolUse", tool_name: t, tool_input, tool_response, ...base };
  }
  return null;
}

const tag = (s) => `MoorAI: ${s || "blocked by policy"}`;

export function fromVerdict(verdict, payload) {
  const v = verdict || {};
  const after = payload?.hook_event_name === "AfterTool";
  if (v.decision === "deny") {
    return { stdout: JSON.stringify({ decision: "deny", reason: tag(v.reason), systemMessage: tag(v.reason) }), exitCode: 0 };
  }
  if (!after && v.decision === "ask") {
    const msg = tag(v.reason || "needs confirmation");
    return { stdout: JSON.stringify({ decision: "ask", reason: msg, systemMessage: msg }), exitCode: 0 };
  }
  if (after && v.context) {
    return { stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: "AfterTool", additionalContext: tag(v.context) } }), exitCode: 0 };
  }
  return { exitCode: 0 };
}

// ---- install / uninstall ----

const settingsPath = (home) => join(home, ".gemini", "settings.json");

// Gemini reads settings.json through strip-json-comments, so a hand-edited file may carry comments.
function stripComments(src) {
  let out = "", i = 0, q = false;
  while (i < src.length) {
    const c = src[i], n = src[i + 1];
    if (q) { out += c; if (c === "\\") { out += n ?? ""; i += 2; continue; } if (c === '"') q = false; i++; continue; }
    if (c === '"') { q = true; out += c; i++; continue; }
    if (c === "/" && n === "/") { while (i < src.length && src[i] !== "\n") i++; continue; }
    if (c === "/" && n === "*") { i += 2; while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i++; i += 2; continue; }
    out += c; i++;
  }
  return out;
}

function load(file) {
  if (!existsSync(file)) return { data: {}, plain: true };
  const raw = readFileSync(file, "utf8");
  if (!raw.trim()) return { data: {}, plain: true };
  try { return { data: JSON.parse(raw), plain: true }; } catch { /* fall through */ }
  return { data: JSON.parse(stripComments(raw)), plain: false };
}

function save(file, data, plain) {
  mkdirSync(dirname(file), { recursive: true });
  if (!plain) copyFileSync(file, `${file}.moorai-bak`);
  writeFileSync(file, JSON.stringify(data, null, 2) + "\n");
}

const isOurs = (h) => h && (h.name === HOOK_NAME || /moorai-agent-hook\.mjs["']?\s+gemini\b/.test(String(h.command || "")));

function strip(list) {
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const def of list) {
    if (!def || !Array.isArray(def.hooks)) { out.push(def); continue; }
    const hooks = def.hooks.filter((h) => !isOurs(h));
    if (hooks.length === def.hooks.length) out.push(def);
    else if (hooks.length) out.push({ ...def, hooks });
  }
  return out;
}

const entry = (matcher, command) => ({ matcher, hooks: [{ type: "command", name: HOOK_NAME, command, timeout: 30000, description: "MoorAI enforcement" }] });

export function install({ home, command }) {
  const file = settingsPath(home);
  const { data, plain } = load(file);
  const hooks = data.hooks && typeof data.hooks === "object" ? data.hooks : {};
  hooks.BeforeTool = [...strip(hooks.BeforeTool), entry(PRE_MATCHER, command)];
  hooks.AfterTool = [...strip(hooks.AfterTool), entry(POST_MATCHER, command)];
  data.hooks = hooks;
  save(file, data, plain);
  if (data.hooksConfig && data.hooksConfig.enabled === false) {
    process.stderr.write(`MoorAI: hooksConfig.enabled is false in ${file}; Gemini CLI will not run the hook until it is enabled.\n`);
  }
}

export function uninstall({ home }) {
  const file = settingsPath(home);
  if (!existsSync(file)) return;
  const { data, plain } = load(file);
  if (!data.hooks || typeof data.hooks !== "object") return;
  for (const ev of ["BeforeTool", "AfterTool"]) {
    if (!Array.isArray(data.hooks[ev])) continue;
    const kept = strip(data.hooks[ev]);
    if (kept.length) data.hooks[ev] = kept; else delete data.hooks[ev];
  }
  if (!Object.keys(data.hooks).length) delete data.hooks;
  save(file, data, plain);
}
