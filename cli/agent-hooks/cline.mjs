// Cline adapter (file hooks: the VS Code extension, and wherever else Cline runs hook scripts). PARTIAL by
// necessity: Cline's current docs (docs.cline.bot/customization/hooks, fetched 2026-10-21) say only "See
// details under SDK Plugins page"; the file-hook contract is described in the hooks announcement
// (cline.bot/blog/cline-v3-36-hooks) and the hook directories in docs.cline.bot/getting-started/config.
// The changelog shows the file hooks still ship (4.1.11: "Deliver a `PreToolUse` hook's
// `contextModification` to the model again"; 4.1.24: "An MCP server or hook that exits before reading
// all of its input no longer crashes the extension host"). No Cline was run, so data/host-versions.json
// records no tested version.
//
// Hook API (announcement). Hook types PreToolUse, PostToolUse, UserPromptSubmit, TaskStart, TaskResume,
// TaskCancel (later releases add Notification). Each hook is an executable script named exactly after its
// type, with no extension, in a hooks directory; "Hooks are currently supported on macOS and Linux only"
// (3.69.0 later added PowerShell support on Windows, not built here), and they are switched on in Cline's
// settings ("reintroduced feature toggle", 3.72.0). Directories (config page): global `~/.cline/hooks/`,
// also `~/Documents/Cline/Hooks/` "for compatibility", project `.cline/hooks/` (legacy `.clinerules/hooks/`)
// and `$CLINE_HOOKS_DIR`. When a global and a workspace hook both exist, both run and either can cancel.
//
// Input: JSON on stdin with clineVersion, hookName, timestamp, taskId, workspaceRoots, userId, plus a
// per-type object: PreToolUse "tool name and parameters" (`preToolUse: { toolName, parameters }`),
// UserPromptSubmit "prompt text and attachments". Output: JSON on stdout `{ cancel, errorMessage,
// contextModification }`: `cancel: true` stops the operation, errorMessage is shown to the user, and
// contextModification is injected into the conversation (it affects the next model request).
//
// Tool names: the docs' tool page lists ClineCore's built-ins (read_files, search_codebase, run_commands,
// fetch_web_content, apply_patch, editor, ...) and calls read_file, replace_in_file and execute_command
// names from "older docs/examples"; the extension's tool set (write_to_file, use_mcp_tool, web_fetch,
// browser_action) is not in the docs at all. No parameter names are documented, so every tool is read
// tolerantly and a call carrying several different values is judged once per value:
//   execute_command / run_commands  command | commands[]                 -> Bash per command
//   read_file / read_files          path | paths[] | files[]             -> Read per path
//   write_to_file                   path, content                        -> Write
//   replace_in_file                 path, diff (SEARCH/REPLACE blocks)   -> MultiEdit (blocks + whole diff)
//   editor                          command, path, file_text, old_str, new_str -> Write / Edit
//   apply_patch                     input | patch                        -> per-file calls (Codex envelope)
//   use_mcp_tool                    server_name, tool_name, arguments (object or JSON string) -> mcp__s__t
//   web_fetch / fetch_web_content / browser_action  url | urls[]         -> WebFetch
//
// Answer. Deny: { cancel: true, errorMessage, contextModification } with MoorAI's reason in both, so the
// user sees it and the model learns why on its next request. Cline has no ask: a MoorAI ask also cancels,
// with a reason that tells the agent to get the user's confirmation. Allow: { cancel: false }. A coach note
// rides in contextModification on an allow. Exit 0 always; a crash of this process prints nothing (what
// Cline does then is not documented). UserPromptSubmit is captured for intent alignment and always answers
// { cancel: false } with no context.
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, unlinkSync, chmodSync, readdirSync } from "node:fs";
import { join, isAbsolute, resolve } from "node:path";
import { patchCalls } from "./codex.mjs";

export const id = "cline";
export const label = "Cline";

export const HOOK_TYPES = ["PreToolUse", "UserPromptSubmit"];
const OWN = /moorai-agent-hook\.mjs"?\s+cline(\s|$)/;
const MARK = "# moorai: MoorAI enforcement hook (written by moorai-agent-hook cline install; removed by uninstall)";

const str = (v) => (typeof v === "string" ? v : "");
const obj = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : null);
const abs = (p, cwd) => (p && cwd && !isAbsolute(p) ? resolve(cwd, p) : p);
const list = (...vals) => [...new Set(vals.flatMap((v) => (Array.isArray(v) ? v : [v])).map((v) => (obj(v) ? str(v.path) : str(v))).filter(Boolean))];
const each = (vals, mk) => (vals.length ? vals : [""]).map(mk);

function parseArgs(v) {
  if (obj(v)) return v;
  if (typeof v !== "string") return {};
  try { return obj(JSON.parse(v)) || {}; } catch { return {}; }
}

// SEARCH/REPLACE blocks ("------- SEARCH ... ======= ... +++++++ REPLACE", or the older "<<<<<<< SEARCH ...
// >>>>>>> REPLACE"), plus the whole diff once, so a block this parser misreads is still content-scanned.
export function searchReplaceEdits(diff) {
  const edits = [];
  const re = /^(?:-{3,}|<{3,}) SEARCH\r?\n([\s\S]*?)^={3,}\r?\n([\s\S]*?)^(?:\+{3,}|>{3,}) REPLACE/gm;
  for (const m of String(diff).matchAll(re)) edits.push({ old_string: m[1].replace(/\r?\n$/, ""), new_string: m[2].replace(/\r?\n$/, "") });
  edits.push({ old_string: "", new_string: String(diff) });
  return edits;
}

function preTool(name, p, cwd) {
  const paths = () => list(p.path, p.file_path, p.paths, p.files).map((x) => abs(x, cwd));
  switch (name) {
    case "execute_command": case "run_commands": {
      const cmds = list(p.command, p.commands);
      return cmds.length ? cmds.map((c) => ["Bash", { command: c }]) : null;
    }
    case "read_file": case "read_files": {
      const ps = paths();
      return ps.length ? ps.map((f) => ["Read", { file_path: f }]) : null;
    }
    case "write_to_file": {
      const contents = list(p.content, p.file_text);
      return each(paths(), (f) => f).flatMap((f) => each(contents, (c) => ["Write", { file_path: f, content: c }]));
    }
    case "replace_in_file": {
      const diffs = list(p.diff);
      return each(paths(), (f) => ["MultiEdit", { file_path: f, edits: diffs.flatMap(searchReplaceEdits) }]);
    }
    case "editor": {
      const cmd = str(p.command);
      if (cmd === "str_replace") return each(paths(), (f) => ["Edit", { file_path: f, old_string: str(p.old_str ?? p.old_string), new_string: str(p.new_str ?? p.new_string) }]);
      if (cmd === "insert" || cmd === "append") return each(paths(), (f) => ["Edit", { file_path: f, old_string: "", new_string: str(p.new_str ?? p.new_string) }]);
      if (cmd === "view" || cmd === "read") return paths().map((f) => ["Read", { file_path: f }]);
      const contents = list(p.file_text, p.content, p.new_str, p.new_string);
      return each(paths(), (f) => f).flatMap((f) => each(contents, (c) => ["Write", { file_path: f, content: c }]));
    }
    case "apply_patch": {
      const texts = list(p.input, p.patch, p.diff);
      if (!texts.length) return null;
      return texts.flatMap((t) => [...patchCalls(t, (x) => abs(x, cwd)).map((c) => [c.tool_name, c.tool_input]), ["MultiEdit", { file_path: abs("", cwd), edits: [{ old_string: "", new_string: t }] }]]);
    }
    case "use_mcp_tool": {
      if (typeof p.tool_name !== "string" || !p.tool_name) return null;
      const server = String(p.server_name || "unknown").replace(/__/g, "_");
      return [[`mcp__${server}__${p.tool_name}`, parseArgs(p.arguments)]];
    }
    case "web_fetch": case "fetch_web_content": case "browser_action": {
      const urls = list(p.url, p.urls);
      return urls.length ? urls.map((u) => ["WebFetch", { url: u, prompt: "" }]) : null;
    }
    default:
      return null;
  }
}

export function toClaude(payload) {
  if (!obj(payload)) return null;
  const roots = Array.isArray(payload.workspaceRoots) ? payload.workspaceRoots.filter((r) => typeof r === "string" && r) : [];
  const cwd = roots[0] || "";
  const base = { session_id: str(payload.taskId), ...(cwd ? { cwd } : {}) };
  if (payload.hookName === "UserPromptSubmit") {
    const u = obj(payload.userPromptSubmit) || {};
    const prompt = typeof u.prompt === "string" ? u.prompt : typeof payload.prompt === "string" ? payload.prompt : null;
    return prompt == null ? null : { hook_event_name: "UserPromptSubmit", prompt, ...base };
  }
  if (payload.hookName !== "PreToolUse") return null;
  const t = obj(payload.preToolUse);
  if (!t || typeof t.toolName !== "string" || !obj(t.parameters)) return null;
  const m = preTool(t.toolName, t.parameters, cwd);
  if (!m || !m.length) return null;
  const calls = m.map(([tool_name, tool_input]) => ({ hook_event_name: "PreToolUse", tool_name, tool_input, ...base }));
  return calls.length === 1 ? calls[0] : calls;
}

const tag = (s, dflt) => `MoorAI: ${String(s || "").trim().replace(/\.+$/, "") || dflt}`;
const json = (o) => ({ stdout: JSON.stringify(o), exitCode: 0 });

export function fromVerdict(verdict, payload) {
  if (payload && payload.hookName === "UserPromptSubmit") return json({ cancel: false });
  const v = verdict || {};
  if (v.decision === "deny") { const m = tag(v.reason, "blocked by policy"); return json({ cancel: true, errorMessage: m, contextModification: m }); }
  if (v.decision === "ask") {
    const m = `${tag(v.reason, "needs confirmation")}. Cline hooks cannot prompt, so this call was held: ask the user to confirm and run it themselves if intended.`;
    return json({ cancel: true, errorMessage: m, contextModification: m });
  }
  if (v.coach) return json({ cancel: false, contextModification: v.coach });
  return json({ cancel: false });
}

// ---- install / uninstall: executable scripts in ~/.cline/hooks/ (macOS and Linux) ----

export const hooksDir = (home) => join(home, ".cline", "hooks");
const isOwnScript = (text) => text.includes(MARK) || OWN.test(text);
const script = (command) => `#!/bin/sh\n${MARK}\nexec ${command}\n`;

export function install({ home, command }) {
  if (process.platform === "win32") {
    process.stderr.write("MoorAI: the Cline adapter installs POSIX shell hooks only; Cline's PowerShell hooks on Windows are not supported by this adapter.\n");
    process.exitCode = 1;
    return null;
  }
  const dir = hooksDir(home);
  // One script per hook type per directory: a user's own script there is never replaced.
  const taken = HOOK_TYPES.filter((h) => existsSync(join(dir, h)) && !isOwnScript(readFileSync(join(dir, h), "utf8")));
  if (taken.length) {
    process.stderr.write(`MoorAI: ${taken.map((h) => join(dir, h)).join(", ")} already exist${taken.length === 1 ? "s" : ""} and ${taken.length === 1 ? "is" : "are"} not MoorAI's; not replacing. Cline also runs hooks from ~/Documents/Cline/Hooks/ and .cline/hooks/.\n`);
    process.exitCode = 1;
    return null;
  }
  mkdirSync(dir, { recursive: true });
  for (const h of HOOK_TYPES) {
    const f = join(dir, h), tmp = `${f}.moorai-${process.pid}.tmp`;
    writeFileSync(tmp, script(command), { mode: 0o755 });
    chmodSync(tmp, 0o755);
    renameSync(tmp, f);
  }
  return dir;
}

export function uninstall({ home }) {
  const dir = hooksDir(home);
  for (const h of HOOK_TYPES) {
    const f = join(dir, h);
    if (existsSync(f) && isOwnScript(readFileSync(f, "utf8"))) unlinkSync(f);
  }
  return dir;
}

// The doctor's view (cli/doctor-hosts.mjs reads `{ hooks: { <event>: [entry] } }`): each hook script in
// the directory, by its type, with the line that runs MoorAI as its command.
export function readHooks(home) {
  const dir = hooksDir(home);
  let names;
  try { names = readdirSync(dir); } catch { return { exists: false, data: null }; }
  const hooks = {};
  for (const n of names) {
    if (!/^[A-Z][A-Za-z]+$/.test(n)) continue;
    let text;
    try { text = readFileSync(join(dir, n), "utf8"); } catch { continue; }
    const line = text.split("\n").find((l) => OWN.test(l)) || "";
    hooks[n] = [{ command: line.replace(/^\s*exec\s+/, "") }];
  }
  return { exists: true, data: { hooks } };
}
