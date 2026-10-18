// Factory Droid adapter (CLI `droid`, npm package `droid`). Built from Factory's documentation only, fetched
// 2026-10-18 when the release notes' newest Droid CLI was v0.244.0: docs.factory.com/reference/hooks-reference,
// /cli/configuration/hooks-guide.md and /harness/hooks (docs.factory.ai redirects there), plus
// /droid-cli/settings.md and /enterprise/hierarchical-settings-and-org-control.md. No droid binary was run.
// Last-tested version: data/host-versions.json (single source of truth; scripts/host-drift.mjs checks the
// latest release against it nightly). It records none for Droid: the adapter has not been run against one.
//
// Hook API (Claude-style). Events PreToolUse, PostToolUse, UserPromptSubmit, Notification, Stop,
// SubagentStop, PreCompact, SessionStart, SessionEnd. Stdin JSON: session_id, transcript_path, cwd,
// permission_mode ("off", "spec", "auto-low", "auto-medium", "auto-high"), hook_event_name, optional
// message_id; tool events add tool_name and tool_input, PostToolUse adds tool_response ("The exact shape of
// `tool_input` and `tool_response` depends on the tool"). Tool names: Execute, Read, Edit, Create, ApplyPatch,
// LS, Glob, Grep, Task, FetchUrl, WebSearch; MCP tools are `mcp__<server>__<tool>`, already MoorAI's form.
// Only two tool_input shapes are documented: Execute's `.tool_input.command` and Create's
// {file_path, content}. Read, Edit, ApplyPatch, FetchUrl and Task are read tolerantly below (file_path or
// path; old_str or old_string; a Codex-style patch envelope or a unified diff).
//
// Answer. Exit 2 is "Blocking or corrective feedback. `PreToolUse` blocks the tool call", and "A blocking
// script exits `2` and writes the reason to stderr". hookSpecificOutput.permissionDecision is "allow"
// ("can bypass the normal permission prompt"), "deny" ("Blocks the tool call and sends the reason to
// Droid") or "ask" ("Forces a user confirmation prompt"). The docs do not say what Droid does with both an
// exit code and JSON, so a MoorAI deny uses both channels: exit 2 with the reason on stderr AND a JSON
// deny on stdout. Either one blocks under every reading of the docs. "ask" passes through as Droid's own
// ask. MoorAI never answers "allow": that would skip Droid's own approval of the call. PostToolUse:
// `decision: "block"` + reason feeds back to Droid; hookSpecificOutput.additionalContext adds context.
// Fail-open: "Other non-zero: non-blocking error. Droid records stderr and continues where the event
// permits"; a crash of this process, unparseable stdin or a shim failure answers exit 0 with nothing, so
// the call runs, as with the other adapters. What Droid does on a timeout is not documented.
//
// Intent capture (cli/intent-alignment.mjs). UserPromptSubmit input adds `prompt` and `has_images`, and
// "For `UserPromptSubmit` and `SessionStart`, stdout adds context", so the prompt is forwarded as Claude's
// UserPromptSubmit and answered with an EMPTY stdout and exit 0. It is never blocked.
//
// Config. User ~/.factory/hooks.json, project .factory/hooks.json, org-managed settings. "Standalone
// `hooks.json` files are keyed directly by event name"; "If `hooks.json` is absent, Droid also reads hook
// declarations from the `hooks` key in the matching `settings.json`" (the pages disagree on whether that
// is a fallback or a merge); the legacy `.factory/hooks/hooks.json` "Still loads. The next save writes
// `.factory/hooks.json`". The installer writes the user scope only, into the file Droid reads under every
// reading of that: hooks.json if it exists; else the legacy file if it exists; else settings.json if it
// already declares hooks (a new hooks.json could shadow them); else a new hooks.json. Uninstall strips
// MoorAI's entries from all three and deletes a hooks.json it emptied, so an empty file cannot shadow
// settings.json hooks later. Droid "snapshots hooks at startup and warns when they change externally", so
// an install takes effect in the next session, after the user reviews it in `/hooks`. hooksDisabled: true
// in settings switches every hook off; allowManagedHooksOnly (org) ignores user hooks.
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, unlinkSync } from "node:fs";
import { join, dirname, isAbsolute, resolve } from "node:path";
import { patchCalls } from "./codex.mjs";

export const id = "droid";
export const label = "Factory Droid";

export const PRE_MATCHER = "^(Execute|Read|Create|Edit|ApplyPatch|FetchUrl|Task|mcp__.+)$";
export const POST_MATCHER = "^(FetchUrl|WebSearch)$";
const TIMEOUT_SEC = 30;
export const EVENTS = ["PreToolUse", "PostToolUse", "UserPromptSubmit", "Notification", "Stop", "SubagentStop", "PreCompact", "SessionStart", "SessionEnd"];
const OWN = /moorai-agent-hook\.mjs"?\s+droid(\s|$)/;

const str = (v) => (typeof v === "string" ? v : "");
const abs = (p, cwd) => (p && cwd && !isAbsolute(p) ? resolve(cwd, p) : p);

// A unified diff, one entry per file: `+++ b/<path>` names the file (its `--- a/<path>` when the target is
// /dev/null, a deletion) and the `+` lines after it are what gets written there. Every file is returned,
// not only the first, so each one is judged.
function unifiedDiff(text) {
  const files = [];
  let src = "", cur = null;
  for (const line of text.split(/\r?\n/)) {
    const from = /^--- (?:a\/)?(.+?)\s*$/.exec(line);
    if (from) { src = from[1]; continue; }
    const to = /^\+\+\+ (?:b\/)?(.+?)\s*$/.exec(line);
    if (to) { cur = { file: to[1] !== "/dev/null" ? to[1] : src !== "/dev/null" ? src : "", added: [] }; files.push(cur); continue; }
    if (cur && line.startsWith("+")) cur.added.push(line.slice(1));
  }
  return files.filter((f) => f.file);
}

function patchTool(text, cwd) {
  const a = (p) => abs(p, cwd);
  const calls = patchCalls(text, a).map((c) => [c.tool_name, c.tool_input]);
  if (calls.length) return calls;
  // Not an envelope: each file of a unified diff with its added lines, or the whole text when nothing names a file.
  const diff = unifiedDiff(text);
  if (diff.length) return diff.map((f) => ["MultiEdit", { file_path: a(f.file), edits: [{ old_string: "", new_string: f.added.join("\n") }] }]);
  return [["MultiEdit", { file_path: a(""), edits: [{ old_string: "", new_string: text }] }]];
}

// Droid documents only Execute's and Create's tool_input, so the others are read under several plausible
// names. When a call carries more than one of them with different values, MoorAI cannot know which one
// Droid acts on, so every distinct value is judged (each() fans out; the most restrictive verdict wins).
const distinct = (...vals) => [...new Set(vals.map(str).filter(Boolean))];
const each = (vals, mk) => (vals.length ? vals : [""]).map(mk);
const editPair = (e) => {
  const olds = distinct(e && e.old_str, e && e.old_string), news = distinct(e && e.new_str, e && e.new_string);
  const out = [];
  for (const o of olds.length ? olds : [""]) for (const n of news.length ? news : [""]) out.push({ old_string: o, new_string: n });
  return out;
};

function preTool(name, ti, cwd) {
  const paths = () => distinct(ti.file_path, ti.path);
  switch (name) {
    case "Execute":
      return typeof ti.command === "string" ? [["Bash", { command: ti.command }]] : null;
    case "Read": {
      const ps = paths();
      return ps.length ? ps.map((p) => ["Read", { file_path: abs(p, cwd) }]) : null;
    }
    case "Create":
      return each(paths(), (p) => ["Write", { file_path: abs(p, cwd), content: str(ti.content) }]);
    case "Edit": {
      if (Array.isArray(ti.edits)) {
        const edits = ti.edits.flatMap(editPair);
        return each(paths(), (p) => ["MultiEdit", { file_path: abs(p, cwd), edits }]);
      }
      const pairs = editPair(ti);
      return each(paths(), (p) => (pairs.length === 1 ? ["Edit", { file_path: abs(p, cwd), ...pairs[0] }] : ["MultiEdit", { file_path: abs(p, cwd), edits: pairs }]));
    }
    case "ApplyPatch": {
      const texts = distinct(ti.input, ti.patch, ti.patch_text, ti.command);
      return texts.length ? texts.flatMap((t) => patchTool(t, cwd)) : null;
    }
    case "FetchUrl":
      return [["WebFetch", { url: str(ti.url), prompt: str(ti.prompt) }]];
    case "Task":
      return [["Task", { subagent_type: str(ti.subagent_type), prompt: str(ti.prompt), description: str(ti.description) }]];
    default:
      return /^mcp__[^_].*__./.test(name) ? [[name, ti]] : null;
  }
}

const POST_TOOLS = { FetchUrl: "WebFetch", WebSearch: "WebSearch" };

export function toClaude(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const cwd = str(payload.cwd);
  const base = { session_id: str(payload.session_id), ...(cwd ? { cwd } : {}) };
  const ev = payload.hook_event_name;
  if (ev === "UserPromptSubmit") return typeof payload.prompt === "string" ? { hook_event_name: "UserPromptSubmit", prompt: payload.prompt, ...base } : null;
  if (ev !== "PreToolUse" && ev !== "PostToolUse") return null;
  const name = str(payload.tool_name);
  if (!name) return null;
  const ti = payload.tool_input && typeof payload.tool_input === "object" && !Array.isArray(payload.tool_input) ? payload.tool_input : {};
  if (ev === "PostToolUse") {
    const t = POST_TOOLS[name];
    if (!t) return null;
    const tool_input = t === "WebFetch" ? { url: str(ti.url), prompt: str(ti.prompt) } : { query: str(ti.query) };
    return { hook_event_name: "PostToolUse", tool_name: t, tool_input, tool_response: payload.tool_response, ...base };
  }
  const m = preTool(name, ti, cwd);
  if (!m || !m.length) return null;
  const calls = m.map(([tool_name, tool_input]) => ({ hook_event_name: "PreToolUse", tool_name, tool_input, ...base }));
  return calls.length === 1 ? calls[0] : calls;
}

const tag = (s, dflt) => `MoorAI: ${String(s || "").trim().replace(/\.+$/, "") || dflt}`;
const json = (o, exitCode = 0) => ({ stdout: JSON.stringify(o), exitCode });

export function fromVerdict(verdict, payload) {
  const ev = payload && payload.hook_event_name;
  // Captured, never judged; stdout on this event is added to the model's context.
  if (ev === "UserPromptSubmit") return { exitCode: 0 };
  const v = verdict || {};
  if (ev === "PostToolUse") {
    if (v.coach) return { ...json({ hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: v.context || v.coach } }), stderr: `${v.coach}\n` };
    if (v.decision === "deny") return json({ decision: "block", reason: tag(v.reason, "blocked by policy") });
    if (v.context) return json({ hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: tag(v.context, "") } });
    return { exitCode: 0 };
  }
  // Coach (unenrolled): the call runs. PreToolUse documents no user- or model-visible field for a call it
  // lets through other than permissionDecisionReason beside "allow", which MoorAI never sends; the note
  // goes to stderr. An allow's `context` has no documented PreToolUse channel and is not sent.
  if (v.coach) return { stderr: `${v.coach}\n`, exitCode: 0 };
  if (v.decision === "deny") {
    const reason = tag(v.reason, "blocked by policy");
    return { ...json({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } }, 2), stderr: `${reason}\n` };
  }
  if (v.decision === "ask") {
    return json({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: tag(v.reason, "needs confirmation") } });
  }
  return { exitCode: 0 };
}

// ---- install / uninstall ----

const factoryDir = (home) => join(home, ".factory");
const hooksJson = (home) => join(factoryDir(home), "hooks.json");
const legacyJson = (home) => join(factoryDir(home), "hooks", "hooks.json");
const settingsJson = (home) => join(factoryDir(home), "settings.json");

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

const hasEvents = (o) => !!o && typeof o === "object" && EVENTS.some((e) => Array.isArray(o[e]));
const wrapped = (o) => !!o && !hasEvents(o) && !!o.hooks && typeof o.hooks === "object" && !Array.isArray(o.hooks);

// The event map inside a document: hooks.json and the legacy file are keyed by event name (a `hooks`
// wrapper is tolerated); settings.json holds it under `hooks`.
export function eventMap(doc, kind) {
  if (!doc || typeof doc !== "object") return {};
  if (kind === "settings") return doc.hooks && typeof doc.hooks === "object" && !Array.isArray(doc.hooks) ? doc.hooks : {};
  return wrapped(doc) ? doc.hooks : doc;
}

// Which user-scope file MoorAI's entries belong in (see the header).
export function configTarget(home) {
  if (existsSync(hooksJson(home))) return { file: hooksJson(home), kind: "hooks" };
  if (existsSync(legacyJson(home))) return { file: legacyJson(home), kind: "legacy" };
  try {
    const s = readDoc(settingsJson(home));
    if (s && s.hooks && typeof s.hooks === "object" && !Array.isArray(s.hooks)) return { file: settingsJson(home), kind: "settings" };
  } catch { /* unreadable settings.json: never written; hooks.json is used */ }
  return { file: hooksJson(home), kind: "hooks" };
}

const isOwn = (h) => !!h && typeof h.command === "string" && OWN.test(h.command);

function strip(groups) {
  return (Array.isArray(groups) ? groups : []).flatMap((g) => {
    const hooks = Array.isArray(g?.hooks) ? g.hooks : [];
    const kept = hooks.filter((h) => !isOwn(h));
    if (kept.length === hooks.length) return [g];
    return kept.length ? [{ ...g, hooks: kept }] : [];
  });
}

// Returns true when it removed something.
function stripMap(map) {
  let changed = false;
  for (const ev of Object.keys(map)) {
    if (!Array.isArray(map[ev])) continue;
    const kept = strip(map[ev]);
    if (JSON.stringify(kept) === JSON.stringify(map[ev])) continue;
    changed = true;
    if (kept.length) map[ev] = kept; else delete map[ev];
  }
  return changed;
}

const group = (matcher, command) => ({ ...(matcher ? { matcher } : {}), hooks: [{ type: "command", command, timeout: TIMEOUT_SEC }] });

const FILES = (home) => [[hooksJson(home), "hooks"], [legacyJson(home), "legacy"], [settingsJson(home), "settings"]];

// Remove MoorAI's entries from one file; a hooks.json left empty is deleted. One unreadable file does not
// stop the others from being cleaned, and is never rewritten.
function stripFile(file, kind) {
  let doc;
  try { doc = readDoc(file); } catch { return; }
  if (!doc) return;
  const map = eventMap(doc, kind);
  if (!stripMap(map)) return;
  if (kind === "hooks" && !Object.keys(doc).length) { unlinkSync(file); return; }
  writeDoc(file, doc);
}

export function install({ home, command }) {
  const { file, kind } = configTarget(home);
  const doc = readDoc(file) || {};
  if (kind === "settings" && (!doc.hooks || typeof doc.hooks !== "object" || Array.isArray(doc.hooks))) doc.hooks = {};
  const map = eventMap(doc, kind);
  stripMap(map);
  const add = (ev, matcher) => { map[ev] = [...(Array.isArray(map[ev]) ? map[ev] : []), group(matcher, command)]; };
  add("PreToolUse", PRE_MATCHER);
  add("PostToolUse", POST_MATCHER);
  add("UserPromptSubmit", null);
  writeDoc(file, doc);
  // An entry an earlier install left in another of the three files would run the hook twice.
  for (const [f, k] of FILES(home)) if (f !== file) stripFile(f, k);
  return file;
}

export function uninstall({ home }) {
  for (const [f, k] of FILES(home)) stripFile(f, k);
  return hooksJson(home);
}
