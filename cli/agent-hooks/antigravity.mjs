// Google Antigravity adapter (the `agy` CLI; the App and the IDE read the same hook files). Built from
// Google's documentation only, fetched 2026-10-21: antigravity.google/docs/hooks ("Lifecycle hooks") and
// /docs/cli/gcli-migration. No agy binary was run (none is installed here), so data/host-versions.json
// records no tested version.
//
// Hook API (antigravity.google/docs/hooks). Events SessionStart, PreToolUse, PostToolUse, PreInvocation,
// PostInvocation, Stop. Config files: workspace `.agents/hooks.json` and global `~/.gemini/config/hooks.json`
// (both for App, CLI and IDE), plus, for the CLI only, a `hooks` entry in ~/.gemini/antigravity-cli/
// settings.json and a hooks.json inside an installed plugin. "Top-level keys are hook names"; each named
// hook may set `enabled` (default true) and lists events; tool events take `matcher` plus a nested `hooks`
// array of handlers `{ type: "command", command, timeout }` (timeout in seconds, default 30). Matcher:
// "" or "*" all tools, "run_command" exact, "run_command|view_file" either, "browser_.*" a regex.
//
// Input (stdin, camelCase): tool events carry `toolCall` {name, args} and `stepIdx`; every event carries
// `conversationId`, `workspacePaths`, `transcriptPath`, `artifactDirectoryPath`, `modelName`. There is NO
// event-name field: a PreToolUse and a PostToolUse payload look alike (PostToolUse adds an optional
// `error`), so MoorAI registers PreToolUse only and treats a tool payload as PreToolUse; a payload that does
// name another event (hookEventName / hook_event_name) is never judged. Documented tool arguments:
//   run_command          CommandLine, Cwd, WaitMsBeforeAsync, RunPersistent?, RequestedTerminalID?  -> Bash
//   view_file            AbsolutePath, StartLine?, EndLine?, IsSkillFile?                            -> Read
//   write_to_file        TargetFile, Overwrite, CodeContent, Description, IsArtifact?, ...            -> Write
//   replace_file_content TargetFile, Instruction, Description, AllowMultiple, TargetContent,
//                        ReplacementContent, StartLine, EndLine, TargetLintErrorIds?                 -> Edit
//   read_url_content     Url                                                                         -> WebFetch
// multi_replace_file_content and invoke_subagent are in the documented tool list without arguments: they
// are read tolerantly, and every string in a multi_replace call is content-scanned whatever its shape.
// MCP tool names are not documented; `mcp_<server>_<tool>` (Gemini CLI's form) and `mcp__<server>__<tool>`
// are read, anything else is not judged.
//
// Output (stdout JSON). PreToolUse: `decision`, `reason` (optional), `overwrite` (merged into the args) and
// `permissionOverrides`. Decisions: "allow" ("Allows the tool call to proceed, delegating to the next hook
// or default policy"), "auto_approve", "deny" ("Hard blocks execution immediately"), "ask" ("Prompts you
// for approval, but respects "Always Allow" settings"), "force_ask" ("Always prompts you for approval,
// ignoring cached permissions") and "deny_unless_prior_grant". MoorAI answers deny, force_ask (so an
// earlier Always Allow cannot turn MoorAI's ask into a silent run) or an explicit allow, which hands the
// call to Antigravity's own policy. It never sends auto_approve, overwrite or permissionOverrides.
// Exit codes and what Antigravity does when a hook fails, times out or prints invalid JSON are NOT
// documented, so every answer is JSON on stdout with exit 0; a crash of this process answers nothing.
// PostToolUse's input carries no tool result and its output is `{}`, so nothing is scanned after a call.
// No event carries the user's prompt, so there is no intent capture.
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, unlinkSync } from "node:fs";
import { join, dirname, isAbsolute, resolve } from "node:path";

export const id = "antigravity";
export const label = "Google Antigravity";

export const HOOK_NAME = "moorai";
export const PRE_MATCHER = "^(run_command|view_file|write_to_file|replace_file_content|multi_replace_file_content|read_url_content|invoke_subagent|mcp_.+)$";
const TIMEOUT_SEC = 30;
const OWN = /moorai-agent-hook\.mjs"?\s+antigravity(\s|$)/;

const str = (v) => (typeof v === "string" ? v : "");
const abs = (p, cwd) => (p && cwd && !isAbsolute(p) ? resolve(cwd, p) : p);
const obj = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : {});

// Every string inside v (bounded), so an undocumented argument shape is still content-scanned.
function strings(v, out = [], depth = 0) {
  if (out.length >= 256 || depth > 8) return out;
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) strings(x, out, depth + 1);
  else if (v && typeof v === "object") for (const x of Object.values(v)) strings(x, out, depth + 1);
  return out;
}

function mcpName(name) {
  if (/^mcp__[^_].*__./.test(name)) return name;
  const m = /^mcp_([^_]+)_(.+)$/.exec(name);
  return m ? `mcp__${m[1]}__${m[2]}` : null;
}

function preTool(name, a, cwd) {
  switch (name) {
    case "run_command":
      return typeof a.CommandLine === "string" ? ["Bash", { command: a.CommandLine }] : null;
    case "view_file":
      return typeof a.AbsolutePath === "string" && a.AbsolutePath ? ["Read", { file_path: abs(a.AbsolutePath, cwd) }] : null;
    case "write_to_file":
      return ["Write", { file_path: abs(str(a.TargetFile), cwd), content: str(a.CodeContent) }];
    case "replace_file_content":
      return ["Edit", { file_path: abs(str(a.TargetFile), cwd), old_string: str(a.TargetContent), new_string: str(a.ReplacementContent) }];
    case "multi_replace_file_content": {
      const chunks = [].concat(a.ReplacementChunks ?? a.Chunks ?? []).map(obj);
      const edits = chunks.map((c) => ({ old_string: str(c.TargetContent), new_string: str(c.ReplacementContent) }));
      if (typeof a.ReplacementContent === "string") edits.push({ old_string: str(a.TargetContent), new_string: a.ReplacementContent });
      const { TargetFile, ...rest } = a;
      edits.push({ old_string: "", new_string: strings(rest).join("\n") });
      return ["MultiEdit", { file_path: abs(str(TargetFile), cwd), edits }];
    }
    case "read_url_content":
      return ["WebFetch", { url: str(a.Url), prompt: "" }];
    case "invoke_subagent":
      return ["Task", { subagent_type: str(a.Name ?? a.AgentName ?? a.SubagentName), prompt: str(a.Prompt ?? a.Task ?? a.Message ?? a.Instructions) }];
    default: {
      const m = mcpName(name);
      return m ? [m, a] : null;
    }
  }
}

export function toClaude(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const ev = payload.hookEventName ?? payload.hook_event_name;
  if (ev !== undefined && ev !== "PreToolUse") return null;
  const tc = payload.toolCall;
  if (!tc || typeof tc !== "object" || typeof tc.name !== "string" || !tc.name) return null;
  const a = obj(tc.args);
  const ws = Array.isArray(payload.workspacePaths) ? payload.workspacePaths.find((p) => typeof p === "string" && p) : "";
  const cwd = (tc.name === "run_command" && typeof a.Cwd === "string" && a.Cwd) || ws || "";
  const m = preTool(tc.name, a, cwd);
  if (!m) return null;
  return { hook_event_name: "PreToolUse", tool_name: m[0], tool_input: m[1], session_id: str(payload.conversationId), ...(cwd ? { cwd } : {}) };
}

const tag = (s, dflt) => `MoorAI: ${String(s || "").trim().replace(/\.+$/, "") || dflt}`;
const json = (o) => ({ stdout: JSON.stringify(o), exitCode: 0 });

export function fromVerdict(verdict) {
  const v = verdict || {};
  if (v.decision === "deny") return json({ decision: "deny", reason: tag(v.reason, "blocked by policy") });
  if (v.decision === "ask") return json({ decision: "force_ask", reason: tag(v.reason, "needs confirmation") });
  // Coach (unenrolled): the call runs. PreToolUse documents no user- or model-visible field for a call it
  // lets through (where `reason` beside "allow" goes is not documented), so the note goes to stderr.
  if (v.coach) return { ...json({ decision: "allow" }), stderr: `${v.coach}\n` };
  return json({ decision: "allow" });
}

// ---- install / uninstall: ~/.gemini/config/hooks.json (global; App, CLI and IDE) ----

export const hooksFile = (home) => join(home, ".gemini", "config", "hooks.json");

function readDoc(file) {
  if (!existsSync(file)) return {};
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

// Remove MoorAI's handlers from every named hook (an older install may have used another name), then the
// `moorai` hook itself. Returns true when it changed something.
function strip(doc) {
  let changed = false;
  if (HOOK_NAME in doc) { delete doc[HOOK_NAME]; changed = true; }
  for (const [name, hook] of Object.entries(doc)) {
    if (!hook || typeof hook !== "object" || Array.isArray(hook)) continue;
    let touched = false;
    for (const [ev, groups] of Object.entries(hook)) {
      if (!Array.isArray(groups)) continue;
      const kept = groups.flatMap((g) => {
        if (isOwn(g)) return [];
        if (!g || !Array.isArray(g.hooks)) return [g];
        const hs = g.hooks.filter((h) => !isOwn(h));
        if (hs.length === g.hooks.length) return [g];
        return hs.length ? [{ ...g, hooks: hs }] : [];
      });
      if (kept.length === groups.length) continue;
      changed = touched = true;
      if (kept.length) hook[ev] = kept; else delete hook[ev];
    }
    if (touched && !Object.keys(hook).some((k) => Array.isArray(hook[k]))) delete doc[name];
  }
  return changed;
}

export function install({ home, command }) {
  const file = hooksFile(home);
  const doc = readDoc(file);
  strip(doc);
  doc[HOOK_NAME] = { PreToolUse: [{ matcher: PRE_MATCHER, hooks: [{ type: "command", command, timeout: TIMEOUT_SEC }] }] };
  writeDoc(file, doc);
  return file;
}

export function uninstall({ home }) {
  const file = hooksFile(home);
  if (!existsSync(file)) return file;
  const doc = readDoc(file);
  if (!strip(doc)) return file;
  if (!Object.keys(doc).length) unlinkSync(file); else writeDoc(file, doc);
  return file;
}

// The doctor's view (cli/doctor-hosts.mjs reads `{ hooks: { <event>: [entry] } }`): every named hook's
// event groups merged per event, and the names of MoorAI hooks switched off with `enabled: false`.
export function eventView(doc) {
  const hooks = {}, disabled = [];
  for (const [name, hook] of Object.entries(obj(doc))) {
    if (!hook || typeof hook !== "object" || Array.isArray(hook)) continue;
    for (const [ev, groups] of Object.entries(hook)) if (Array.isArray(groups)) (hooks[ev] ||= []).push(...groups);
    if (hook.enabled === false && /moorai-agent-hook\.mjs\\?"?\s+antigravity/.test(JSON.stringify(hook))) disabled.push(name);
  }
  return { hooks, disabled };
}
