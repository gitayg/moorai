// Windsurf adapter (Cascade, the agent in the Windsurf editor, which its docs now call Devin Desktop; the
// same hooks run in the JetBrains plugin). Built from the Cascade Hooks reference only, fetched 2026-10-21:
// docs.devin.ai/desktop/cascade/hooks. No Windsurf install was run, so data/host-versions.json records no
// tested version.
//
// Hook API. Twelve events; "Only **pre-hooks** (pre_user_prompt, pre_read_code, pre_write_code,
// pre_run_command, pre_mcp_tool_use) can block actions using exit code 2". Exit codes: "0: Success. The
// action proceeds"; "2: Blocking error. The agent sees stderr. For pre-hooks, the action is blocked"; any
// other value is an error and "The action proceeds normally" (fail open). There is no structured output
// and no ask: "Communication is through exit codes and stdout/stderr only". No timeout is documented.
//
// Input (stdin JSON): agent_action_name (the event), trajectory_id (the Cascade conversation), execution_id
// (the agent turn), timestamp, model_name, and tool_info per event:
//   pre_run_command   { command_line, cwd }                                   -> Bash {command}
//   pre_read_code     { file_path } ("may be a directory when read recursively") -> Read {file_path}
//   pre_write_code    { file_path, edits: [{ old_string, new_string }] }       -> MultiEdit
//   pre_mcp_tool_use  { mcp_server_name, mcp_tool_name, mcp_tool_arguments }   -> mcp__<server>__<tool>
//   pre_user_prompt   { user_prompt }                                          -> UserPromptSubmit
// The post_* events cannot block and carry no web content MoorAI scans, so they are not registered.
//
// Answer. A MoorAI deny exits 2 with the reason on stderr (the agent sees it). Windsurf has no ask, so a
// MoorAI ask also exits 2, and its reason tells the agent to get the user's confirmation and have them run
// it (as the Codex adapter does). An allow exits 0 with nothing printed. pre_user_prompt is captured for
// intent alignment and always exits 0: MoorAI never blocks what the user typed.
//
// Config. System hooks.json (macOS /Library/Application Support/Devin/hooks.json, Linux /etc/devin/hooks.json,
// Windows C:\ProgramData\Devin\hooks.json; the legacy Windsurf paths when no Devin file exists), user
// ~/.codeium/windsurf/hooks.json (JetBrains: ~/.codeium/hooks.json), workspace .devin/hooks.json (legacy
// .windsurf/hooks.json); "Hooks are combined per event, not overwritten". Shape: { hooks: { <event>:
// [{ command, powershell?, show_output?, working_directory? }] } }. `command` runs through `bash -c`,
// `powershell` through `powershell -Command` ("Falls back to `command` on Windows if omitted"). The
// installer writes the user file only, with `powershell` set to `& <command>`: PowerShell needs the call
// operator to run a quoted executable path.
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, unlinkSync } from "node:fs";
import { join, dirname } from "node:path";

export const id = "windsurf";
export const label = "Windsurf (Cascade)";

export const EVENTS = ["pre_run_command", "pre_read_code", "pre_write_code", "pre_mcp_tool_use", "pre_user_prompt"];
const OWN = /moorai-agent-hook\.mjs"?\s+windsurf(\s|$)/;

const str = (v) => (typeof v === "string" ? v : "");
const obj = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : null);

export function toClaude(payload) {
  if (!obj(payload)) return null;
  const info = obj(payload.tool_info);
  if (!info) return null;
  const base = { session_id: str(payload.trajectory_id) };
  const pre = (tool_name, tool_input, cwd) => ({ hook_event_name: "PreToolUse", tool_name, tool_input, ...base, ...(cwd ? { cwd } : {}) });
  switch (payload.agent_action_name) {
    case "pre_run_command":
      return typeof info.command_line === "string" ? pre("Bash", { command: info.command_line }, str(info.cwd)) : null;
    case "pre_read_code":
      return typeof info.file_path === "string" && info.file_path ? pre("Read", { file_path: info.file_path }) : null;
    case "pre_write_code": {
      const edits = (Array.isArray(info.edits) ? info.edits : []).map((e) => ({ old_string: str(e && e.old_string), new_string: str(e && e.new_string) }));
      return pre("MultiEdit", { file_path: str(info.file_path), edits });
    }
    case "pre_mcp_tool_use": {
      if (typeof info.mcp_tool_name !== "string" || !info.mcp_tool_name) return null;
      const server = String(info.mcp_server_name || "unknown").replace(/__/g, "_");
      return pre(`mcp__${server}__${info.mcp_tool_name}`, obj(info.mcp_tool_arguments) || {});
    }
    case "pre_user_prompt":
      return typeof info.user_prompt === "string" ? { hook_event_name: "UserPromptSubmit", prompt: info.user_prompt, ...base } : null;
    default:
      return null;
  }
}

const tag = (s, dflt) => `MoorAI: ${String(s || "").trim().replace(/\.+$/, "") || dflt}`;

export function fromVerdict(verdict, payload) {
  // Captured, never judged: the user's prompt always proceeds.
  if (payload && payload.agent_action_name === "pre_user_prompt") return { exitCode: 0 };
  const v = verdict || {};
  if (v.decision === "deny") return { stderr: `${tag(v.reason, "blocked by policy")}\n`, exitCode: 2 };
  if (v.decision === "ask") return { stderr: `${tag(v.reason, "needs confirmation")}. Windsurf hooks cannot prompt, so this action was held: ask the user to confirm and run it themselves if intended.\n`, exitCode: 2 };
  // Coach (unenrolled): the action proceeds; stderr is shown in Cascade's UI when show_output is set.
  if (v.coach) return { stderr: `${v.coach}\n`, exitCode: 0 };
  return { exitCode: 0 };
}

// ---- install / uninstall: ~/.codeium/windsurf/hooks.json ----

export const hooksFile = (home) => join(home, ".codeium", "windsurf", "hooks.json");

function readDoc(file) {
  if (!existsSync(file)) return null;
  const raw = readFileSync(file, "utf8");
  if (!raw.trim()) return {};
  const doc = JSON.parse(raw); // a malformed file is left untouched: throw rather than overwrite it
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new Error(`${file} is not a JSON object; not modifying it`);
  return doc;
}

function writeDoc(file, doc) {
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.moorai-${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(doc, null, 2) + "\n");
  renameSync(tmp, file);
}

const isOwn = (h) => !!h && typeof h.command === "string" && OWN.test(h.command);

function strip(doc) {
  const hooks = obj(doc.hooks);
  if (!hooks) return false;
  let changed = false;
  for (const ev of Object.keys(hooks)) {
    if (!Array.isArray(hooks[ev])) continue;
    const kept = hooks[ev].filter((h) => !isOwn(h));
    if (kept.length === hooks[ev].length) continue;
    changed = true;
    if (kept.length) hooks[ev] = kept; else delete hooks[ev];
  }
  return changed;
}

export function install({ home, command }) {
  const file = hooksFile(home);
  const doc = readDoc(file) || {};
  strip(doc);
  if (!obj(doc.hooks)) doc.hooks = {};
  for (const ev of EVENTS) {
    const entry = { command, powershell: `& ${command}`, ...(ev === "pre_user_prompt" ? {} : { show_output: true }) };
    doc.hooks[ev] = [...(Array.isArray(doc.hooks[ev]) ? doc.hooks[ev] : []), entry];
  }
  writeDoc(file, doc);
  return file;
}

export function uninstall({ home }) {
  const file = hooksFile(home);
  const doc = readDoc(file);
  if (!doc || !strip(doc)) return file;
  if (!Object.keys(doc.hooks).length && Object.keys(doc).length === 1) unlinkSync(file); else writeDoc(file, doc);
  return file;
}
