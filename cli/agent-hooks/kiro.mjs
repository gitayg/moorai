// Kiro adapter (the Kiro IDE and `kiro-cli`). Built from documentation only, fetched 2026-10-21; no Kiro
// install was run, so data/host-versions.json records no tested version. Sources:
//   kiro.dev/docs/hooks (+ /types, /actions), /docs/ide/whats-new-v1/hooks, /docs/cli/v3/hooks-migration,
//   /docs/cli/2x-reference, /docs/reference/built-in-tools, and the hooks reference and tool schemas of
//   Kiro CLI's open-source predecessor (github.com/aws/amazon-q-developer-cli docs/hooks.md and
//   crates/chat-cli/src/cli/chat/tools/tool_index.json), which kiro.dev no longer reproduces.
//
// Hook API. V3 (CLI V3 and IDE 1.0) hook files: workspace `.kiro/hooks/*.json`, and "Kiro CLI V3 also loads
// global Hooks from `~/.kiro/hooks/`". A file is { version: "v1", hooks: [{ name, trigger (PascalCase:
// PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, Stop, ...), matcher?, action: { type: "command",
// command } | { type: "agent", prompt }, timeout?, enabled? }] }. Command actions default to a 60 s timeout.
// Matchers in hook JSON files take wildcards (`*` any characters); `@mcp`, `@builtin`, `@<server>` and
// `@<server>/<tool>` select by source. CLI 2.x embedded hooks in agent configs (`"hooks": { "preToolUse":
// [{ "command", "matcher" }] }`), which V3 still accepts as compatibility input; the installer does not
// edit agent configs.
//
// Input: "JSON via STDIN". The predecessor's reference shows { "hook_event_name": "preToolUse", "cwd",
// "tool_name", "tool_input" } (the fs_read example is test/fixtures/agent-hooks/kiro/), postToolUse adds
// `tool_response`, userPromptSubmit carries `prompt`; kiro.dev confirms that tool hooks "receive
// `tool_tags` with `tool_name` and `tool_input`" and that the IDE also passes the prompt in USER_PROMPT.
// Both camelCase and PascalCase event names are accepted. Tools, under both generations of names:
//   execute_bash / shell / execute_cmd   { command }                                   -> Bash
//   fs_read / read                       { operations: [{ mode, path, image_paths }] } -> Read per path
//   fs_write / write                     { command: create|str_replace|insert|append, path, file_text,
//                                          old_str, new_str }                         -> Write / Edit
//   web_fetch                            { url } (field name not documented; read tolerantly) -> WebFetch
//   use_aws / aws                        { service_name, operation_name, region, profile_name?, parameters }
//                                        -> Bash `aws <service> <operation> --region ... --<k> <v>`, the
//                                           equivalent CLI line, so MoorAI's shell checks judge it
//   use_subagent / subagent / delegate   { task | prompt }                             -> Task
//   MCP: `@<server>/<tool>` (CLI) and `mcp_<server>_<tool>` (the IDE's internal id)   -> mcp__<server>__<tool>
// V3's input field names for read/write/shell are not documented; they are read under the 2.x names plus
// file_path / content, and a call carrying several different values is judged once per value.
//
// Answer. "Exit code 2: (PreToolUse only) Block tool execution. STDERR is returned to the LLM"; the IDE
// blocks a Pre Tool Use on any non-zero exit and sends stderr to the agent; on exit 0 stdout "is added to
// the agent's context" (IDE) or captured (CLI). So a deny exits 2 with the reason on stderr and an allow
// exits 0 with nothing printed. Kiro has no ask: a MoorAI ask also exits 2, with a reason that tells the
// agent to get the user's confirmation (as the Codex adapter does). A coach note (unenrolled device) is the
// one thing printed on an allow, to stdout, where the IDE hands it to the agent. Other non-zero exits are a
// warning and the tool runs (fail open). UserPromptSubmit is captured for intent alignment and always exits
// 0 with nothing printed (stdout would be added to the agent's context).
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, unlinkSync } from "node:fs";
import { join, dirname, isAbsolute, resolve } from "node:path";

export const id = "kiro";
export const label = "Kiro";

const OWN = /moorai-agent-hook\.mjs"?\s+kiro(\s|$)/;
const str = (v) => (typeof v === "string" ? v : "");
const obj = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : null);
const abs = (p, cwd) => (p && cwd && !isAbsolute(p) ? resolve(cwd, p) : p);
const distinct = (...vals) => [...new Set(vals.map(str).filter(Boolean))];
const each = (vals, mk) => (vals.length ? vals : [""]).map(mk);

const event = (e) => String(e || "").toLowerCase();

const shq = (s) => (/^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);
function awsLine(ti) {
  const parts = ["aws", str(ti.service_name), str(ti.operation_name)];
  if (ti.region) parts.push("--region", str(ti.region));
  if (ti.profile_name) parts.push("--profile", str(ti.profile_name));
  for (const [k, v] of Object.entries(obj(ti.parameters) || {})) parts.push(`--${k}`, typeof v === "string" ? v : JSON.stringify(v));
  return parts.filter(Boolean).map(shq).join(" ");
}

function mcpName(name) {
  const at = /^@([^/]+)\/(.+)$/.exec(name);
  if (at) return `mcp__${at[1].replace(/__/g, "_")}__${at[2]}`;
  if (/^mcp__[^_].*__./.test(name)) return name;
  const m = /^mcp_([^_]+)_(.+)$/.exec(name);
  return m ? `mcp__${m[1]}__${m[2]}` : null;
}

function preTool(name, ti, cwd) {
  const paths = () => distinct(ti.path, ti.file_path).map((p) => abs(p, cwd));
  switch (name) {
    case "execute_bash": case "executeBash": case "shell": case "execute_cmd":
      return typeof ti.command === "string" ? [["Bash", { command: ti.command }]] : null;
    case "fs_read": case "fsRead": case "read": {
      const ps = [];
      for (const op of Array.isArray(ti.operations) ? ti.operations : []) {
        if (!obj(op)) continue;
        if (typeof op.path === "string" && op.path) ps.push(abs(op.path, cwd));
        for (const p of Array.isArray(op.image_paths) ? op.image_paths : []) if (typeof p === "string" && p) ps.push(abs(p, cwd));
      }
      ps.push(...paths());
      return ps.length ? [...new Set(ps)].map((p) => ["Read", { file_path: p }]) : null;
    }
    case "fs_write": case "fsWrite": case "write": {
      const ps = paths();
      const cmd = str(ti.command);
      if (cmd === "str_replace") return each(ps, (p) => ["Edit", { file_path: p, old_string: str(ti.old_str), new_string: str(ti.new_str) }]);
      if (cmd === "insert" || cmd === "append") return each(ps, (p) => ["Edit", { file_path: p, old_string: "", new_string: str(ti.new_str) }]);
      // create, or a command name this adapter does not know: every content field is judged as file content.
      const contents = distinct(ti.file_text, ti.content, ti.new_str);
      return each(ps, (p) => p).flatMap((p) => each(contents, (c) => ["Write", { file_path: p, content: c }]));
    }
    case "web_fetch": {
      const urls = distinct(ti.url, ti.uri);
      return urls.length ? urls.map((u) => ["WebFetch", { url: u, prompt: "" }]) : null;
    }
    case "use_aws": case "aws":
      return ti.service_name && ti.operation_name ? [["Bash", { command: awsLine(ti) }]] : null;
    case "use_subagent": case "subagent": case "delegate": {
      const prompts = distinct(ti.task, ti.prompt, ti.query);
      return prompts.length ? prompts.map((p) => ["Task", { subagent_type: str(ti.agent || ti.agent_name), prompt: p }]) : null;
    }
    default: {
      const m = mcpName(name);
      return m ? [[m, ti]] : null;
    }
  }
}

export function toClaude(payload, env = process.env) {
  if (!obj(payload)) return null;
  const cwd = str(payload.cwd);
  const base = { session_id: str(payload.session_id), ...(cwd ? { cwd } : {}) };
  const ev = event(payload.hook_event_name);
  if (ev === "userpromptsubmit") {
    const prompt = typeof payload.prompt === "string" ? payload.prompt : typeof env.USER_PROMPT === "string" ? env.USER_PROMPT : null;
    return prompt == null ? null : { hook_event_name: "UserPromptSubmit", prompt, ...base };
  }
  if (ev && ev !== "pretooluse") return null;
  const name = str(payload.tool_name);
  const ti = obj(payload.tool_input);
  if (!name || !ti) return null;
  const m = preTool(name, ti, cwd);
  if (!m || !m.length) return null;
  const calls = m.map(([tool_name, tool_input]) => ({ hook_event_name: "PreToolUse", tool_name, tool_input, ...base }));
  return calls.length === 1 ? calls[0] : calls;
}

const tag = (s, dflt) => `MoorAI: ${String(s || "").trim().replace(/\.+$/, "") || dflt}`;

export function fromVerdict(verdict, payload) {
  // Captured, never judged: the prompt always proceeds, and stdout here would reach the agent's context.
  if (payload && event(payload.hook_event_name) === "userpromptsubmit") return { exitCode: 0 };
  const v = verdict || {};
  if (v.decision === "deny") return { stderr: `${tag(v.reason, "blocked by policy")}\n`, exitCode: 2 };
  if (v.decision === "ask") return { stderr: `${tag(v.reason, "needs confirmation")}. Kiro hooks cannot prompt, so this call was held: ask the user to confirm and run it themselves if intended.\n`, exitCode: 2 };
  if (v.coach) return { stdout: `${v.coach}\n`, exitCode: 0 };
  return { exitCode: 0 };
}

// ---- install / uninstall: ~/.kiro/hooks/moorai.json (a V3 global hook file) ----

export const hookFile = (home) => join(home, ".kiro", "hooks", "moorai.json");

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

const isOwn = (h) => !!h && !!h.action && typeof h.action.command === "string" && OWN.test(h.action.command);

export function install({ home, command }) {
  const file = hookFile(home);
  const doc = readDoc(file) || {};
  const kept = (Array.isArray(doc.hooks) ? doc.hooks : []).filter((h) => !isOwn(h));
  doc.version = doc.version || "v1";
  doc.hooks = [
    ...kept,
    { name: "moorai-pre-tool-use", trigger: "PreToolUse", matcher: "*", action: { type: "command", command } },
    { name: "moorai-user-prompt", trigger: "UserPromptSubmit", action: { type: "command", command } }
  ];
  writeDoc(file, doc);
  return file;
}

export function uninstall({ home }) {
  const file = hookFile(home);
  const doc = readDoc(file);
  if (!doc || !Array.isArray(doc.hooks)) return file;
  const kept = doc.hooks.filter((h) => !isOwn(h));
  if (kept.length === doc.hooks.length) return file;
  if (!kept.length) { unlinkSync(file); return file; }
  doc.hooks = kept;
  writeDoc(file, doc);
  return file;
}

// The doctor's view (cli/doctor-hosts.mjs reads `{ hooks: { <event>: [entry] } }`): hooks by trigger, and
// the MoorAI hooks switched off with `enabled: false`.
export function eventView(doc) {
  const hooks = {}, disabled = [];
  for (const h of Array.isArray(doc && doc.hooks) ? doc.hooks : []) {
    if (!obj(h) || typeof h.trigger !== "string") continue;
    (hooks[h.trigger] ||= []).push({ ...(typeof h.matcher === "string" ? { matcher: h.matcher } : {}), command: str(h.action && h.action.command) });
    if (h.enabled === false && isOwn(h)) disabled.push(str(h.name) || h.trigger);
  }
  return { hooks, disabled };
}
