// The agent an alert is about, in the console's vocabulary (`agentName`), and that agent product's own
// version (`agentVersion`, e.g. Claude Code 2.1.295 — never MoorAI's version). Dependency-free: the
// Agent SDK vendors it (packages/agent-sdk/scripts/vendor.mjs).
//
// AGENT_NAMES must stay a subset of the console's list (RAISEME-server server/siem-fields.js
// AGENT_NAMES), or the console stores null for the extra values. test/agent-kind-version.test.mjs
// checks that whenever the console checkout is next to this repo.
//   hosts with a hook adapter   claude-code, codex, cursor, gemini, copilot
//                               (droid, antigravity, windsurf, kiro and cline have adapters too, but are not
//                               here until the console's list has them: their alerts carry no agentName,
//                               like a shim caller this hook cannot name)
//   MCP client hosts            claude-desktop (the stdio MCP proxy's `--host` stamp)
//   MoorAI surfaces             agent-sdk, serve, model-proxy, inference-hook, gateway
export const AGENT_NAMES = Object.freeze(["claude-code", "codex", "cursor", "gemini", "copilot", "claude-desktop", "agent-sdk", "serve", "model-proxy", "inference-hook", "gateway"]);
export const agentNameOf = (v) => (typeof v === "string" && AGENT_NAMES.includes(v) ? v : undefined);

// The same strict shape the console accepts (server/siem-fields.js AGENT_VERSION_RE): a version string
// and nothing else, so no path, email or prompt text can ride in it.
export const AGENT_VERSION_RE = /^[0-9A-Za-z.+-]{1,32}$/;
export const cleanAgentVersion = (v) => (typeof v === "string" && AGENT_VERSION_RE.test(v) ? v : undefined);

// Claude Code's own version, from the AI_AGENT value it puts in the environment of every process its
// harness starts. Only the `_harness` form counts: a process started from Claude Code's Bash tool sees
// `claude-code_<v>_agent`, and an unrelated host's value is left alone by Claude Code, so neither of
// those names the Claude Code that ran this hook or MCP server. Measured live, Claude Code 2.1.295
// against a local fake model (docs/proposals/agent-identity.md §5.3): PreToolUse, SessionStart and stdio
// MCP server env all carry `AI_AGENT=claude-code_2-1-295_harness`; with `AI_AGENT=codex_1-2-3` set by
// the parent, the hook sees `codex_1-2-3`.
export function claudeCodeVersion(env = process.env) {
  const m = /^claude-code_(\d+(?:-\d+){1,3})_harness$/.exec(String((env && env.AI_AGENT) || ""));
  return m ? cleanAgentVersion(m[1].replace(/-/g, ".")) : undefined;
}

// Cursor's version, from CURSOR_VERSION, which Cursor sets for every hook process ("Always",
// cursor.com/docs/hooks; cursor-agent 2026.05.27-fe9a6e2 3880.index.js buildHookEnvironment sets it from
// the same value as the payload's cursor_version). "1.0.0" is cursor-agent's own fallback when it has no
// version, so it names nothing.
export function cursorVersion(env = process.env) {
  const v = cleanAgentVersion(String((env && env.CURSOR_VERSION) || "").trim());
  return v === "1.0.0" ? undefined : v;
}

// The version of the agent that ran this process, only where that agent states it to its children.
// Codex, Gemini CLI, Copilot CLI and Droid put no version in their hook payload or hook environment (their
// hook references; data/host-versions.json), and a PATH probe names whichever binary is on PATH, not
// necessarily the one that made the call, so for them, and for every MoorAI surface, it is undefined.
export function agentVersionFromEnv(kind, env = process.env) {
  if (kind === "claude-code") return claudeCodeVersion(env);
  if (kind === "cursor") return cursorVersion(env);
  return undefined;
}
