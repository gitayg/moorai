// OpenAI Codex CLI adapter (github.com/openai/codex, verified against tag rust-v0.154.0).
//
// Codex runs Claude-style lifecycle hooks (feature key `hooks`, stable, on by default —
// codex-rs/features/src/lib.rs). A PreToolUse command hook gets JSON on stdin and blocks the call with
// `hookSpecificOutput.permissionDecision: "deny"` + a non-empty reason (or exit 2 + stderr).
// codex-rs/hooks/src/engine/output_parser.rs rejects `permissionDecision: "ask"` and "allow" as
// unsupported; an invalid output, a non-0/2 exit, or a timeout marks the hook Failed and the tool RUNS
// (fail-open). There is no way for a PreToolUse hook to prompt the user, so MoorAI's "ask" is sent as a
// deny whose reason tells the model to get the user's confirmation (see fromVerdict).
//
// Config: hooks are read from `hooks.json` next to each config layer's config.toml (user layer =
// $CODEX_HOME or ~/.codex), and also from `[hooks]` tables inside config.toml. We write hooks.json only,
// so no TOML is ever edited. User-layer hooks are NOT run until the user trusts them in Codex's hook
// review (startup prompt or /hooks) — trust is a hash in config.toml `[hooks.state]` that this adapter
// deliberately does not forge. Trust keys embed the group index, so MoorAI's group is always appended
// last to avoid shifting (and un-trusting) the user's existing hooks.
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { join, dirname, isAbsolute, resolve } from "node:path";

export const id = "codex";
export const label = "OpenAI Codex CLI";

// Canonical tool names Codex serializes to hook stdin (codex-rs/core/src/tools/hook_names.rs,
// handlers/unified_exec/exec_command.rs, handlers/apply_patch.rs, handlers/mcp.rs, tools/registry.rs).
export const MATCHER = "^(Bash|apply_patch|view_image|spawn_agent|mcp__.+)$";
const STATUS = "MoorAI security check";
const OWN = /moorai-agent-hook\.mjs"?\s+codex(\s|$)/;

// Parse a Codex apply_patch envelope into per-file operations.
export function parsePatch(text) {
  const files = [];
  let cur = null;
  let hunk = null;
  const flush = () => { if (cur && hunk && (hunk.old.length || hunk.new.length)) cur.hunks.push(hunk); hunk = null; };
  for (const line of String(text).split(/\r?\n/)) {
    const m = /^\*\*\* (Add|Update|Delete) File: (.+)$/.exec(line);
    if (m) { flush(); cur = { op: m[1], path: m[2].trim(), lines: [], hunks: [] }; files.push(cur); continue; }
    if (!cur || /^\*\*\* (Begin|End) Patch/.test(line)) continue;
    if (/^\*\*\* Move to: /.test(line)) { cur.moveTo = line.slice(13).trim(); continue; }
    if (cur.op === "Add") { if (line.startsWith("+")) cur.lines.push(line.slice(1)); continue; }
    if (cur.op !== "Update") continue;
    if (line.startsWith("@@")) { flush(); continue; }
    if (line === "*** End of File") continue;
    hunk = hunk || { old: [], new: [] };
    const body = line.slice(1);
    if (line.startsWith("+")) hunk.new.push(body);
    else if (line.startsWith("-")) hunk.old.push(body);
    else { hunk.old.push(body); hunk.new.push(body); }
  }
  flush();
  return files;
}

function patchToClaude(patch, cwd) {
  const abs = (p) => (isAbsolute(p) || !cwd ? p : resolve(cwd, p));
  const files = parsePatch(patch).filter((f) => f.op !== "Delete");
  if (!files.length) return null;
  if (files.length === 1 && files[0].op === "Add") {
    return { tool_name: "Write", tool_input: { file_path: abs(files[0].path), content: files[0].lines.join("\n") } };
  }
  // One payload per call: every file's new text goes into one MultiEdit so all of it is scanned.
  // file_path is the first file's (the envelope check sees only that path).
  const edits = [];
  for (const f of files) {
    if (f.op === "Add") edits.push({ old_string: "", new_string: f.lines.join("\n") });
    else for (const h of f.hunks) edits.push({ old_string: h.old.join("\n"), new_string: h.new.join("\n") });
  }
  return { tool_name: "MultiEdit", tool_input: { file_path: abs(files[0].moveTo || files[0].path), edits } };
}

function mapTool(name, input, cwd) {
  const ti = input && typeof input === "object" ? input : {};
  if (name === "Bash") return typeof ti.command === "string" ? { tool_name: "Bash", tool_input: { command: ti.command } } : null;
  if (name === "apply_patch") return typeof ti.command === "string" ? patchToClaude(ti.command, cwd) : null;
  if (name === "view_image") {
    if (typeof ti.path !== "string") return null;
    return { tool_name: "Read", tool_input: { file_path: isAbsolute(ti.path) || !cwd ? ti.path : resolve(cwd, ti.path) } };
  }
  if (name === "spawn_agent") {
    return { tool_name: "Task", tool_input: { prompt: typeof ti.message === "string" ? ti.message : "", subagent_type: ti.agent_type || ti.task_name || "codex" } };
  }
  if (name.startsWith("mcp__")) return { tool_name: name, tool_input: ti };
  return null;
}

export function toClaude(payload) {
  if (!payload || typeof payload !== "object" || payload.hook_event_name !== "PreToolUse") return null;
  if (typeof payload.tool_name !== "string") return null;
  const cwd = typeof payload.cwd === "string" ? payload.cwd : undefined;
  const mapped = mapTool(payload.tool_name, payload.tool_input, cwd);
  if (!mapped) return null;
  return { hook_event_name: "PreToolUse", ...mapped, session_id: String(payload.session_id || ""), ...(cwd ? { cwd } : {}) };
}

export function fromVerdict(verdict, payload) {
  const v = verdict || {};
  const out = (o) => ({ stdout: JSON.stringify(o), exitCode: 0 });
  const reason = String(v.reason || "").trim().replace(/\.+$/, "");
  if (v.decision === "deny") {
    return out({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `MoorAI: ${reason || "blocked by policy"}` } });
  }
  if (v.decision === "ask") {
    const msg = `MoorAI: ${reason || "needs confirmation"}. Codex hooks cannot prompt, so this call was held: ask the user to confirm and run it themselves if intended.`;
    return out({ systemMessage: msg, hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: msg } });
  }
  if (v.context) return out({ hookSpecificOutput: { hookEventName: "PreToolUse", additionalContext: `MoorAI: ${v.context}` } });
  return { exitCode: 0 };
}

function hooksPath(home, codexHome) {
  return join(codexHome || process.env.CODEX_HOME || join(home, ".codex"), "hooks.json");
}

function load(file) {
  if (!existsSync(file)) return { hooks: {} };
  const raw = readFileSync(file, "utf8");
  if (!raw.trim()) return { hooks: {} };
  const doc = JSON.parse(raw); // a malformed file is left untouched: throw rather than overwrite it
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new Error(`${file} is not a JSON object`);
  if (!doc.hooks || typeof doc.hooks !== "object") doc.hooks = {};
  return doc;
}

function save(file, doc) {
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.moorai-tmp`;
  writeFileSync(tmp, JSON.stringify(doc, null, 2) + "\n");
  renameSync(tmp, file);
}

const isOwn = (h) => h && typeof h.command === "string" && OWN.test(h.command);

// Drop MoorAI handlers; drop a group only if MoorAI's handlers were all it held.
function strip(groups) {
  return (Array.isArray(groups) ? groups : []).flatMap((g) => {
    const hooks = Array.isArray(g?.hooks) ? g.hooks : [];
    const kept = hooks.filter((h) => !isOwn(h));
    if (kept.length === hooks.length) return [g];
    return kept.length ? [{ ...g, hooks: kept }] : [];
  });
}

export function install({ home, command, codexHome }) {
  const file = hooksPath(home, codexHome);
  const doc = load(file);
  const entry = { type: "command", command, timeout: 30, statusMessage: STATUS };
  const pre = Array.isArray(doc.hooks.PreToolUse) ? doc.hooks.PreToolUse : [];
  const at = pre.findIndex((g) => Array.isArray(g?.hooks) && g.hooks.some(isOwn));
  if (at >= 0) {
    // Update in place: moving the group would shift the trust keys of hooks listed after it.
    const rest = strip(pre.slice(at + 1));
    pre.splice(at, pre.length - at, { ...pre[at], matcher: MATCHER, hooks: pre[at].hooks.flatMap((h, i, a) => (!isOwn(h) ? [h] : a.findIndex(isOwn) === i ? [entry] : [])) }, ...rest);
  } else {
    pre.push({ matcher: MATCHER, hooks: [entry] });
  }
  doc.hooks.PreToolUse = pre;
  save(file, doc);
  return file;
}

export function uninstall({ home, codexHome }) {
  const file = hooksPath(home, codexHome);
  if (!existsSync(file)) return file;
  const doc = load(file);
  for (const ev of Object.keys(doc.hooks)) {
    const kept = strip(doc.hooks[ev]);
    if (kept.length) doc.hooks[ev] = kept; else delete doc.hooks[ev];
  }
  save(file, doc);
  return file;
}
