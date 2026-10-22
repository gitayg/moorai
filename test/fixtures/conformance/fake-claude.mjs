#!/usr/bin/env node
// A stand-in for Claude Code, used only by test/host-conformance.test.mjs to drive the live tier's
// plumbing without the real host. It does the parts of Claude Code's documented hook contract the
// conformance cases touch (code.claude.com/docs/en/hooks): command hooks from $CLAUDE_CONFIG_DIR/
// settings.json get the event JSON on stdin; UserPromptSubmit blocks on exit 2 or {"decision":"block"};
// PreToolUse denies on exit 2 or hookSpecificOutput.permissionDecision "deny", and the reason goes back
// to the model as an error tool_result. The model is whatever ANTHROPIC_BASE_URL points at.
// It never runs a command: an allowed `echo` returns its words, anything else returns a fixed text.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const argv = process.argv.slice(2);
if (argv.includes("--version")) { process.stdout.write("2.1.295 (Claude Code)\n"); process.exit(0); }
const prompt = argv[argv.indexOf("-p") + 1] || "";
const cwd = process.cwd();
let settings = {};
try { settings = JSON.parse(readFileSync(join(process.env.CLAUDE_CONFIG_DIR, "settings.json"), "utf8")); } catch { /* no hooks */ }

function commandsFor(event, tool) {
  const out = [];
  for (const g of (settings.hooks && settings.hooks[event]) || []) {
    const m = g.matcher;
    if (m && m !== "*" && tool && !new RegExp(`^(?:${m})$`).test(tool)) continue;
    for (const h of g.hooks || []) if (h.type === "command") out.push(h.command);
  }
  return [...new Set(out)]; // Claude Code runs identical hook commands once
}
function runHooks(event, input, tool) {
  for (const cmd of commandsFor(event, tool)) {
    const r = spawnSync("/bin/sh", ["-c", cmd], { input: JSON.stringify(input), encoding: "utf8", env: process.env, timeout: 60000 });
    let out = {};
    try { out = JSON.parse(r.stdout || "{}"); } catch { /* plain text */ }
    if (r.status === 2) return { block: true, reason: r.stderr || "blocked" };
    if (event === "UserPromptSubmit" && out.decision === "block") return { block: true, reason: out.reason || "blocked" };
    const hso = out.hookSpecificOutput || {};
    if (event === "PreToolUse" && hso.permissionDecision === "deny") return { block: true, reason: hso.permissionDecisionReason || "denied" };
  }
  return { block: false };
}
const base = { session_id: "fake-session", transcript_path: join(cwd, "transcript.jsonl"), cwd, permission_mode: "dontAsk" };
const tools = [{ name: "Bash", description: "shell", input_schema: { type: "object", properties: { command: { type: "string" } } } }];
async function model(messages) {
  const r = await fetch(`${process.env.ANTHROPIC_BASE_URL}/v1/messages`, { method: "POST", headers: { "content-type": "application/json", "x-api-key": process.env.ANTHROPIC_API_KEY || "" }, body: JSON.stringify({ model: "claude-fake", max_tokens: 64, stream: false, tools, messages }) });
  return r.json();
}

const up = runHooks("UserPromptSubmit", { ...base, hook_event_name: "UserPromptSubmit", prompt });
if (up.block) { process.stdout.write(JSON.stringify({ result: "prompt blocked by hook" }) + "\n"); process.exit(0); }
const messages = [{ role: "user", content: prompt }];
const first = await model(messages);
const use = (first.content || []).find((b) => b.type === "tool_use");
if (use) {
  const pre = runHooks("PreToolUse", { ...base, hook_event_name: "PreToolUse", tool_name: use.name, tool_input: use.input, tool_use_id: use.id }, use.name);
  let result;
  // FAKE_CLAUDE_IGNORE_PRETOOL=1 plays a host that does not honour a PreToolUse deny (the tier must go red).
  if (pre.block && process.env.FAKE_CLAUDE_IGNORE_PRETOOL !== "1") result ={ type: "tool_result", tool_use_id: use.id, is_error: true, content: pre.reason };
  else {
    const c = String((use.input && use.input.command) || "");
    result = { type: "tool_result", tool_use_id: use.id, is_error: false, content: /^echo [\w -]+$/.test(c) ? c.slice(5) + "\n" : "fake host: command accepted, not executed" };
  }
  messages.push({ role: "assistant", content: first.content }, { role: "user", content: [result] });
  await model(messages);
}
process.stdout.write(JSON.stringify({ result: "done" }) + "\n");
