// Claude Code's HTTP hook transport for the MoorAI hook (moorai-hookd). Claude Code POSTs the event JSON a
// command hook would read on stdin; a warm hook worker (cli/hook-warm-pool.mjs) runs cli/moorai-hook.mjs on it
// unchanged, and its exit code, stdout and stderr become the HTTP answer below. The hooks reference
// (code.claude.com/docs/en/hooks, "HTTP response handling"): "2xx with an empty body: success, equivalent to exit
// code 0 with no output"; "2xx with a JSON object body: parsed using the same JSON output schema as command hooks";
// "Non-2xx status: non-blocking error"; "Connection failure: non-blocking error". And "Exit code 2": "The message
// that comes with the block is your hook's stderr. If your hook also printed JSON that makes a blocking decision,
// Claude Code uses that decision's reason instead." An HTTP hook has no exit code, so a run that exited 2 is
// answered with the JSON that blocks the same event the same way (mapHookResult).
import { statSync } from "node:fs";
import { basename, dirname, isAbsolute } from "node:path";
import os from "node:os";

export const HOOK_PATH = "/v1/hook/claude-code";
// The environment values a command hook gets from Claude Code that the hook reads: AI_AGENT (Claude Code's
// version on alerts, cli/agent-names.mjs), CLAUDE_PROJECT_DIR and CLAUDE_CONFIG_DIR (which settings files can
// set environment variables, cli/server-mode.mjs settingsEnvHits), CLAUDE_CODE_REMOTE (the web host, server
// mode). Claude Code puts them in headers through the hook entry's allowedEnvVars ("Values support environment
// variable interpolation ... Only variables listed in allowedEnvVars are resolved"); an unset one arrives empty.
// Claude Code 2.1.295 sends AI_AGENT and CLAUDE_CONFIG_DIR; CLAUDE_PROJECT_DIR arrives empty (projectDirFor).
export const FORWARDED_ENV = Object.freeze(["AI_AGENT", "CLAUDE_PROJECT_DIR", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_REMOTE"]);
export const envHeader = (name) => `x-moorai-env-${name.toLowerCase().replace(/_/g, "-")}`;
// The marker header every MoorAI http entry carries: install, converge and uninstall find their own entries by
// the "moorai-hook" text in them, as they do for the command entry.
export const MARKER_HEADER = "x-moorai-hook";

const PRINTABLE = /^[\x20-\x7e]{1,256}$/;
const absPath = (v) => typeof v === "string" && v.length <= 4096 && isAbsolute(v) && !/[\0\r\n]/.test(v);
const isDir = (p) => { try { return statSync(p).isDirectory(); } catch { return false; } };

// The forwarded values from the request headers. A value that is not well formed is dropped (unset), never
// passed on: a path must be absolute, the others printable ASCII.
export function forwardedEnv(headers) {
  const out = {};
  for (const name of FORWARDED_ENV) {
    const v = headers[envHeader(name)];
    if (typeof v !== "string" || !v) continue;
    if (name === "CLAUDE_PROJECT_DIR" || name === "CLAUDE_CONFIG_DIR" ? absPath(v) : PRINTABLE.test(v)) out[name] = v;
  }
  return out;
}

// The project directory, CLAUDE_PROJECT_DIR for a command hook ("the project root where the session started").
// Claude Code sets it for the hook processes it starts, not in its own environment, so it does not arrive in a
// header (measured, Claude Code 2.1.295: AI_AGENT and CLAUDE_CONFIG_DIR are interpolated, CLAUDE_PROJECT_DIR is
// empty). Claude Code names a session's transcript directory after the project directory with every character
// that is not a letter or digit turned into "-", so it is the event's cwd or the nearest ancestor of it whose
// path encodes to that name; else a header value, if one came; else the cwd, the value the hook itself falls
// back to (cli/server-mode.mjs: `env.CLAUDE_PROJECT_DIR || cwd`).
export const encodeProjectDir = (p) => String(p).replace(/[^A-Za-z0-9]/g, "-");
export function projectDirFor(event, env) {
  const cwd = absPath(event && event.cwd) ? event.cwd : "";
  const tp = event && typeof event.transcript_path === "string" ? event.transcript_path : "";
  if (cwd && tp) {
    const want = basename(dirname(tp));
    for (let d = cwd, i = 0; i < 64; i++) {
      if (encodeProjectDir(d) === want) return d;
      const up = dirname(d);
      if (up === d) break;
      d = up;
    }
  }
  if (absPath(env.CLAUDE_PROJECT_DIR)) return env.CLAUDE_PROJECT_DIR;
  return cwd;
}

// Where the worker runs. The reference: "Handlers run in the current directory with Claude Code's environment.
// If the current directory no longer exists ... Claude Code runs command hooks from the first of these that
// still exists: the directory the session started in, the project root, your home directory, or the system
// temp directory."
export function workerCwd(event, projectDir) {
  for (const d of [event && event.cwd, projectDir, os.homedir(), os.tmpdir()]) if (absPath(d) && isDir(d)) return d;
  return os.tmpdir();
}

// The header for one worker run (cli/hook-warm-worker.mjs applyHeader).
export function workerHeader(event, headers, peerPid) {
  const env = forwardedEnv(headers || {});
  const projectDir = projectDirFor(event, env);
  const out = {};
  for (const n of FORWARDED_ENV) out[n] = env[n] || "";
  if (projectDir) out.CLAUDE_PROJECT_DIR = projectDir;
  return { cwd: workerCwd(event, projectDir), env: out, peerPid: Number.isSafeInteger(peerPid) ? peerPid : 0 };
}

// stdout as Claude Code reads it ("Exit code 0"): one JSON object with only whitespace around it is JSON output;
// anything that starts with "{" and ends with "}" and is not valid JSON is a parse failure; the rest is text.
export function readStdout(stdout) {
  const t = String(stdout || "").trim();
  if (!t) return { kind: "empty" };
  if (!(t.startsWith("{") && t.endsWith("}"))) return { kind: "text", text: t };
  try { const v = JSON.parse(t); return v && typeof v === "object" && !Array.isArray(v) ? { kind: "json", value: v, text: t } : { kind: "invalid" }; } catch { return { kind: "invalid" }; }
}

// The reason a JSON output gives for blocking, when it blocks.
function blockingReason(v) {
  if (!v) return "";
  const h = v.hookSpecificOutput;
  if (h && h.permissionDecision === "deny" && typeof h.permissionDecisionReason === "string") return h.permissionDecisionReason;
  if (v.decision === "block" && typeof v.reason === "string") return v.reason;
  return "";
}

// The events whose exit 2 the reference lists as blocking with a top-level decision: "block" (UserPromptSubmit,
// Stop, SubagentStop, PreCompact: "You can also block by returning JSON with "decision": "block""), and
// PostToolUse, where exit 2 "Shows stderr to Claude" and decision "block" "adds the reason next to the tool result".
const TOP_LEVEL_BLOCK = new Set(["UserPromptSubmit", "Stop", "SubagentStop", "PreCompact", "PostToolUse"]);

// One worker run -> { status, body } (body "" for an empty 2xx). r: { code, signal, stdout, stderr }.
export function mapHookResult(event, r) {
  const out = readStdout(r.stdout);
  const ev = event && typeof event.hook_event_name === "string" ? event.hook_event_name : "";
  if (r.code === 0) {
    if (out.kind === "json") return { status: 200, body: out.text };
    if (out.kind === "empty") return { status: 200, body: "" };
    if (out.kind === "invalid") return { status: 502, body: "hook output is not valid JSON" };
    // Plain text: Claude Code adds it to the context on UserPromptSubmit and writes it to the debug log elsewhere.
    if (ev === "UserPromptSubmit") return { status: 200, body: JSON.stringify({ hookSpecificOutput: { hookEventName: ev, additionalContext: out.text } }) };
    return { status: 200, body: "" };
  }
  if (r.code === 2) {
    const v = out.kind === "json" ? out.value : null;
    const reason = blockingReason(v) || String(r.stderr || "").trim() || "blocked by the MoorAI hook";
    if (ev === "PreToolUse") {
      const { updatedInput, ...hso } = (v && v.hookSpecificOutput) || {};
      return { status: 200, body: JSON.stringify({ ...(v || {}), hookSpecificOutput: { ...hso, hookEventName: ev, permissionDecision: "deny", permissionDecisionReason: reason } }) };
    }
    if (TOP_LEVEL_BLOCK.has(ev)) return { status: 200, body: JSON.stringify({ ...(v || {}), decision: "block", reason }) };
    if (ev === "PostToolUseFailure") return { status: 200, body: JSON.stringify({ hookSpecificOutput: { hookEventName: ev, additionalContext: reason } }) };
    return { status: 502, body: "hook exited 2 on an event this transport does not map" };
  }
  // Any other exit (or a signal): JSON that passes validation decides alone, as for a command hook without
  // onFailure; otherwise a non-blocking error, which the entry's onFailure turns into a block when it is "block".
  if (out.kind === "json") return { status: 200, body: out.text };
  return { status: 502, body: "hook failed" };
}

