// Cline adapter (file hooks, run by both Cline runtimes: the VS Code extension and ClineCore, the SDK the
// `cline` CLI is built on). PARTIAL: Cline's current docs (docs.cline.bot/customization/hooks, fetched
// 2026-10-21) say only "See details under SDK Plugins page", and the hooks announcement
// (cline.bot/blog/cline-v3-36-hooks) shows only the answer { cancel, errorMessage, contextModification }
// and says the input carries the "tool name and parameters". The input key names, the hook directories,
// the parameter encoding and the failure behaviour below are read from Cline's source (github.com/cline/
// cline, main at c441897, extension 4.1.25, read 2026-10-22), cited per point. No Cline was run, so
// data/host-versions.json records no tested version.
//
// Where hooks are read. Each hook is an executable file named after its type (PreToolUse,
// UserPromptSubmit, ...; extensionless on macOS and Linux).
//   - Extension: ~/Documents/Cline/Hooks (getGlobalHooksDir -> ensureHooksDirectoryExists, apps/vscode/src/
//     core/storage/disk.ts; on Linux the XDG documents folder when xdg-user-dir answers, documents-path.ts),
//     each workspace's .clinerules/hooks, and --hooks-dir. It never reads ~/.cline/hooks.
//   - ClineCore: ~/Documents/Cline/Hooks, ~/.cline/hooks (or $CLINE_DIR/hooks), and the workspace's
//     .clinerules/hooks and .cline/hooks (resolveHooksConfigSearchPaths, sdk/packages/shared/src/storage/
//     paths.ts); every file found runs, so a script in both global folders runs twice.
// So install writes ~/Documents/Cline/Hooks only, and removes MoorAI's own scripts from ~/.cline/hooks.
// Hooks are on by default (getHooksEnabledSafe returns the user setting ?? true, apps/vscode/src/core/hooks/
// hooks-utils.ts).
//
// Input: JSON on stdin with clineVersion, hookName, timestamp, taskId, workspaceRoots, userId.
//   - Extension: hookName "PreToolUse" with preToolUse { toolName, parameters }, and "UserPromptSubmit" with
//     userPromptSubmit { prompt, attachments } (apps/vscode/src/sdk/hooks-adapter.ts, hook-factory.ts).
//   - ClineCore: hookName "tool_call" with tool_call { id, name, input } (the raw input) plus the same
//     preToolUse copy, and "prompt_submit" with userPromptSubmit (sdk/packages/core/src/hooks/subprocess.ts,
//     hook-file-hooks.ts). Its prompt hooks run detached, so their answer is never read.
//   - parameters is a Record<string,string>: every value that is not a string arrives JSON-stringified
//     (toStringRecord in the extension, mapParams in the SDK). So list-valued keys (files, paths,
//     file_paths, commands, requests, urls) are decoded from JSON when they hold a JSON array or object;
//     a value that does not decode is kept as typed. tool_call.input, when present, is used as it is.
//
// Tools. The extension now runs on the SDK and names tools as ClineCore does (ctx.toolCall.toolName):
// read_files, run_commands, editor, apply_patch, fetch_web_content, search_codebase, skills, ask_question,
// submit_and_exit (sdk/packages/core/src/extensions/tools/constants.ts), with the input shapes of
// schemas.ts. The older extension names are still mapped.
//   run_commands / execute_command  commands[] (string or {command,args}) | command | cmd -> Bash per command
//   read_files / read_file          files[] ({path} or string) | paths | file_paths | path -> Read per path
//   editor                          path, old_text, new_text, insert_line (ClineCore); command, file_text,
//                                   old_str, new_str (older) -> Edit when old_text or insert_line, else Write
//   write_to_file                   path, content                                         -> Write
//   replace_in_file                 path, diff (SEARCH/REPLACE blocks)  -> MultiEdit (blocks + whole diff)
//   apply_patch                     input | patch                       -> per-file calls (Codex envelope)
//   use_mcp_tool                    server_name, tool_name, arguments (object or JSON string) -> mcp__s__t
//   fetch_web_content               requests[] ({url, prompt})                             -> WebFetch per url
//   web_fetch / browser_action      url | urls[]                                           -> WebFetch
// A call carrying several different values is judged once per value.
//
// Answer: { cancel, errorMessage, contextModification }. On cancel both runtimes stop the call and use
// errorMessage as the reason (a cancelling hook's contextModification is never injected; mapStopControl in
// hooks-adapter.ts, toHookControl in subprocess.ts). Deny: { cancel: true, errorMessage } with MoorAI's
// reason (also in contextModification, the reason's fallback). Cline has no ask: a MoorAI ask also cancels,
// with a reason that tells the agent to get the user's confirmation. Allow: { cancel: false }; a coach note
// rides in contextModification on an allow. Exit 0 always. Failure: both runtimes fail open; the extension
// treats a non-zero exit without JSON as a hook error that "don't block tools" (hook-factory.ts) and its
// beforeTool catch returns no control; ClineCore logs a failed, timed-out or unparseable hook and goes on
// (runBlockingHookCommands, hook-file-hooks.ts). UserPromptSubmit is captured for intent alignment and
// always answers { cancel: false } with no context.
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
const each = (vals, mk) => (vals.length ? vals : [""]).map(mk);

// Only the list-valued keys are ever decoded (Cline JSON-stringifies a list it passes as a string); a
// scalar key (command, cmd, path, url, ...) is judged exactly as typed, because that string is what Cline
// runs, reads or fetches. `_` is ClineCore's non-object tool_call.input, which its schemas accept as a
// string or a list.
const LIST_KEYS = new Set(["_", "files", "paths", "file_paths", "commands", "requests", "urls", "queries"]);
function decoded(v) {
  if (typeof v !== "string" || !/^\s*[[{]/.test(v)) return v;
  try { const j = JSON.parse(v); return j && typeof j === "object" ? j : v; } catch { return v; }
}
const asText = (v) => (typeof v === "string" ? v : v === undefined ? "" : JSON.stringify(v) ?? "");
// Every string field of an object or array, at any depth up to 4.
function leaves(v, out = [], depth = 0) {
  if (typeof v === "string") { if (v) out.push(v); return out; }
  if (depth < 4 && v && typeof v === "object") for (const x of Array.isArray(v) ? v : Object.values(v)) leaves(x, out, depth + 1);
  return out;
}
// The values to judge under `keys` of p: each value as typed and, for a list key holding stringified
// JSON, also its decoded form; arrays are flattened; a string goes through `fromStr`, an object through
// `fromObj` (which judges every string field of it), any other scalar through `fromStr` as its JSON text.
function gather(p, keys, fromStr, fromObj) {
  const out = [];
  const item = (v, depth) => {
    if (v === undefined || v === null) return;
    if (typeof v === "string") { if (v) out.push(fromStr(v)); return; }
    if (Array.isArray(v)) { if (depth < 4) for (const x of v) item(x, depth + 1); return; }
    if (obj(v)) { out.push(...fromObj(v)); return; }
    out.push(fromStr(asText(v)));
  };
  for (const k of keys) {
    const v = p[k];
    item(v, 0);
    if (typeof v === "string" && LIST_KEYS.has(k)) { const d = decoded(v); if (d !== v) item(d, 0); }
  }
  const seen = new Set();
  return out.filter((x) => { const key = JSON.stringify(x); return !seen.has(key) && seen.add(key); });
}
const pathOf = (o) => str(o.path) || str(o.file_path) || str(o.filePath);
// A structured command { command, args } runs its executable with argv, no shell: the line is rebuilt
// with every element quoted as a shell would, whatever its type, and each element is judged on its own.
const SAFE_WORD = /^[A-Za-z0-9_@%+=:,.\/-]+$/;
export const shellQuote = (s) => (SAFE_WORD.test(s) ? s : `'${s.replace(/'/g, "'\\''")}'`);
const argList = (a) => (Array.isArray(a) ? a : a === undefined || a === null ? [] : [a]).map(asText);
function commandsOf(o) {
  const argv = o.command === undefined || o.command === null ? [] : [asText(o.command), ...argList(o.args)];
  return [...(argv.length ? [argv.map(shellQuote).join(" ")] : []), ...argList(o.args), ...leaves(o)];
}
const texts = (...vals) => [...new Set(vals.filter((v) => typeof v === "string" && v))];

// MCP arguments: an object, or a JSON string of one; anything else is carried as { arguments } so its
// content is still judged.
function parseArgs(v) {
  if (obj(v)) return v;
  if (v === undefined || v === null || v === "") return {};
  if (typeof v === "string") { try { const j = obj(JSON.parse(v)); if (j) return j; } catch { /* kept as typed */ } }
  return { arguments: v };
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

// Tools that act on nothing MoorAI judges: they proceed unread.
const INERT = new Set(["ask_question", "submit_and_exit", "ask_followup_question", "attempt_completion", "plan_mode_respond"]);

function preTool(name, p, cwd) {
  const paths = () => gather(p, ["_", "path", "file_path", "files", "paths", "file_paths"], (s) => s, (o) => [pathOf(o), ...leaves(o)]).filter(Boolean).map((x) => abs(x, cwd));
  switch (name) {
    case "execute_command": case "run_commands": {
      const cmds = gather(p, ["_", "commands", "command", "cmd"], (s) => s, commandsOf).filter(Boolean);
      return cmds.length ? cmds.map((c) => ["Bash", { command: c }]) : null;
    }
    case "read_file": case "read_files": {
      const ps = paths();
      return ps.length ? ps.map((f) => ["Read", { file_path: f }]) : null;
    }
    case "write_to_file": {
      const contents = texts(p.content, p.file_text);
      return each(paths(), (f) => f).flatMap((f) => each(contents, (c) => ["Write", { file_path: f, content: c }]));
    }
    case "replace_in_file": {
      const diffs = texts(p.diff);
      return each(paths(), (f) => ["MultiEdit", { file_path: f, edits: diffs.flatMap(searchReplaceEdits) }]);
    }
    case "editor": {
      const cmd = str(p.command);
      const newText = str(p.new_text ?? p.new_str ?? p.new_string);
      if (cmd === "view" || cmd === "read") return paths().map((f) => ["Read", { file_path: f }]);
      if (cmd === "str_replace" || (!cmd && typeof p.old_text === "string" && p.old_text)) return each(paths(), (f) => ["Edit", { file_path: f, old_string: str(p.old_text ?? p.old_str ?? p.old_string), new_string: newText }]);
      if (cmd === "insert" || cmd === "append" || (!cmd && p.insert_line != null && p.insert_line !== "" && p.insert_line !== "null")) return each(paths(), (f) => ["Edit", { file_path: f, old_string: "", new_string: newText }]);
      const contents = texts(p.file_text, p.content, p.new_text, p.new_str, p.new_string);
      return each(paths(), (f) => f).flatMap((f) => each(contents, (c) => ["Write", { file_path: f, content: c }]));
    }
    case "apply_patch": {
      const patches = texts(p._, p.input, p.patch, p.diff);
      if (!patches.length) return null;
      return patches.flatMap((t) => [...patchCalls(t, (x) => abs(x, cwd)).map((c) => [c.tool_name, c.tool_input]), ["MultiEdit", { file_path: abs("", cwd), edits: [{ old_string: "", new_string: t }] }]]);
    }
    case "use_mcp_tool": {
      if (typeof p.tool_name !== "string" || !p.tool_name) return null;
      const server = String(p.server_name || "unknown").replace(/__/g, "_");
      return [[`mcp__${server}__${p.tool_name}`, parseArgs(p.arguments)]];
    }
    case "web_fetch": case "fetch_web_content": case "browser_action": {
      // A request object { url, prompt } is one fetch: its url, and every other string field as the prompt.
      const reqs = gather(p, ["_", "requests", "url", "urls"], (s) => ({ url: s, prompt: "" }), (o) => [{ url: str(o.url), prompt: leaves(o).filter((x) => x !== o.url).join("\n") }]);
      return reqs.length ? reqs.map((r) => ["WebFetch", r]) : null;
    }
    // search_codebase runs regex queries over the workspace: judged as Claude Code's Grep (capability "read").
    case "search_codebase": case "search_files": {
      const qs = gather(p, ["_", "queries", "query", "regex"], (s) => s, (o) => leaves(o));
      return each(qs, (q) => ["Grep", { pattern: q, path: abs(str(p.path), cwd) || cwd }]);
    }
    case "list_files": case "list_code_definition_names":
      return [["LS", { path: abs(str(p.path), cwd) || cwd }]];
    // skills runs a named skill: judged as Claude Code's Skill call.
    case "skills": {
      const skill = asText(p.skill ?? p._);
      return [["Skill", { skill, ...(p.args !== undefined && p.args !== null ? { args: asText(p.args) } : {}) }]];
    }
    default:
      return null;
  }
}
const MAPPED = new Set(["execute_command", "run_commands", "read_file", "read_files", "write_to_file", "replace_in_file", "editor", "apply_patch", "use_mcp_tool", "web_fetch", "fetch_web_content", "browser_action", "search_codebase", "search_files", "list_files", "list_code_definition_names", "skills"]);

const PRE = new Set(["PreToolUse", "tool_call"]);
const PROMPT = new Set(["UserPromptSubmit", "prompt_submit"]);

// The tool's input: ClineCore's raw tool_call.input when present (a non-object input, which its tool
// schemas accept for some tools, is carried as `_`), else the extension's stringified parameters.
function toolInput(payload) {
  const tc = obj(payload.tool_call);
  if (tc && typeof tc.name === "string" && tc.name && tc.input !== undefined && tc.input !== null) {
    return { name: tc.name, params: obj(tc.input) || { _: tc.input } };
  }
  const t = obj(payload.preToolUse);
  if (!t || typeof t.toolName !== "string" || !obj(t.parameters)) return null;
  return { name: t.toolName, params: t.parameters };
}

export function toClaude(payload) {
  if (!obj(payload)) return null;
  const roots = Array.isArray(payload.workspaceRoots) ? payload.workspaceRoots.filter((r) => typeof r === "string" && r) : [];
  const cwd = roots[0] || "";
  const base = { session_id: str(payload.taskId), ...(cwd ? { cwd } : {}) };
  if (PROMPT.has(payload.hookName)) {
    const u = obj(payload.userPromptSubmit) || {};
    const prompt = typeof u.prompt === "string" ? u.prompt : typeof payload.prompt === "string" ? payload.prompt : null;
    return prompt == null ? null : { hook_event_name: "UserPromptSubmit", prompt, ...base };
  }
  if (!PRE.has(payload.hookName)) return null;
  const t = toolInput(payload);
  if (!t) return null;
  const m = preTool(t.name, t.params, cwd);
  if (!m || !m.length) return null;
  const calls = m.map(([tool_name, tool_input]) => ({ hook_event_name: "PreToolUse", tool_name, tool_input, ...base }));
  return calls.length === 1 ? calls[0] : calls;
}

// A PreToolUse / tool_call for a tool name this adapter neither maps nor knows to be inert: MoorAI cannot
// judge it, so it is held (Cline has no ask) rather than allowed unread. Returns the name, or null.
export function unjudgedTool(payload) {
  if (!obj(payload) || !PRE.has(payload.hookName)) return null;
  const tc = obj(payload.tool_call), t = obj(payload.preToolUse);
  const name = (tc && typeof tc.name === "string" && tc.name) || (t && typeof t.toolName === "string" && t.toolName) || "";
  return name && !MAPPED.has(name) && !INERT.has(name) ? name : null;
}

const tag = (s, dflt) => `MoorAI: ${String(s || "").trim().replace(/\.+$/, "") || dflt}`;
const json = (o) => ({ stdout: JSON.stringify(o), exitCode: 0 });

export function fromVerdict(verdict, payload) {
  if (payload && PROMPT.has(payload.hookName)) return json({ cancel: false });
  const unknown = unjudgedTool(payload);
  if (unknown) {
    const m = `MoorAI: Cline tool ${/^[\w.:-]{1,64}$/.test(unknown) ? `"${unknown}"` : "(unnamed)"} is not one MoorAI can judge, so this call was held: ask the user to confirm and run it themselves if intended.`;
    return json({ cancel: true, errorMessage: m, contextModification: m });
  }
  const v = verdict || {};
  if (v.decision === "deny") { const m = tag(v.reason, "blocked by policy"); return json({ cancel: true, errorMessage: m, contextModification: m }); }
  if (v.decision === "ask") {
    const m = `${tag(v.reason, "needs confirmation")}. Cline hooks cannot prompt, so this call was held: ask the user to confirm and run it themselves if intended.`;
    return json({ cancel: true, errorMessage: m, contextModification: m });
  }
  if (v.coach) return json({ cancel: false, contextModification: v.coach });
  return json({ cancel: false });
}

// ---- install / uninstall: executable scripts in ~/Documents/Cline/Hooks (macOS and Linux) ----

export const hooksDir = (home) => join(home, "Documents", "Cline", "Hooks");
// ClineCore's second global folder: the extension never reads it, and a MoorAI script there would run a
// second time under ClineCore, so install and uninstall remove MoorAI's own scripts from it.
export const coreHooksDir = (home) => join(home, ".cline", "hooks");
const isOwnScript = (text) => text.includes(MARK) || OWN.test(text);
const script = (command) => `#!/bin/sh\n${MARK}\nexec ${command}\n`;
const ownIn = (dir, h) => { const f = join(dir, h); try { return isOwnScript(readFileSync(f, "utf8")) ? f : null; } catch { return null; } };
const OTHER_TYPES = ["PreToolUse", "PostToolUse", "UserPromptSubmit", "TaskStart", "TaskResume", "TaskCancel", "TaskComplete", "TaskError", "Notification", "PreCompact", "SessionShutdown"];
function clearCore(home) {
  const dir = coreHooksDir(home);
  let names = [];
  try { names = readdirSync(dir); } catch { return; }
  for (const n of names) if (OTHER_TYPES.some((h) => n === h || n.toLowerCase().startsWith(`${h.toLowerCase()}.`))) { const f = ownIn(dir, n); if (f) unlinkSync(f); }
}

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
    process.stderr.write(`MoorAI: ${taken.map((h) => join(dir, h)).join(", ")} already exist${taken.length === 1 ? "s" : ""} and ${taken.length === 1 ? "is" : "are"} not MoorAI's; not replacing.\n`);
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
  clearCore(home);
  return dir;
}

export function uninstall({ home }) {
  const dir = hooksDir(home);
  for (const h of HOOK_TYPES) { const f = ownIn(dir, h); if (f) unlinkSync(f); }
  clearCore(home);
  return dir;
}

// The doctor's view (cli/doctor-hosts.mjs reads `{ hooks: { <event>: [entry] } }`): each hook script in
// ~/Documents/Cline/Hooks, by its type, with the line that runs MoorAI as its command; `core` lists MoorAI
// scripts left in ~/.cline/hooks.
export function readHooks(home) {
  const dir = hooksDir(home);
  const core = (() => { try { return readdirSync(coreHooksDir(home)).filter((n) => ownIn(coreHooksDir(home), n)); } catch { return []; } })();
  let names;
  try { names = readdirSync(dir); } catch { return core.length ? { exists: true, data: { hooks: {}, core } } : { exists: false, data: null }; }
  const hooks = {};
  for (const n of names) {
    if (!/^[A-Z][A-Za-z]+$/.test(n)) continue;
    let text;
    try { text = readFileSync(join(dir, n), "utf8"); } catch { continue; }
    const line = text.split("\n").find((l) => OWN.test(l)) || "";
    hooks[n] = [{ command: line.replace(/^\s*exec\s+/, "") }];
  }
  return { exists: true, data: { hooks, ...(core.length ? { core } : {}) } };
}
