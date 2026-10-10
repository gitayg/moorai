// The sub-agent type a #66 delegation alert carries. A user-defined type name (`.claude/agents/<name>.md`,
// a Cursor or Copilot custom agent) is content: `acme-merger-review` says what the user is working on.
// Built-in names describe the product, not the work, so they stay readable on the console; anything else is
// the keyed contentHash, the same value the handoff edge's `to` carries (docs/proposals/agent-identity.md
// §8.1, §9 Q1).
//
// Claude Code's built-in sub-agent types, read off the installed 2.1.295 binary (agent definitions with
// `source:"built-in"`, plus claude-code-guide, defined by constant): general-purpose, Explore, Plan,
// statusline-setup, claude-code-guide, fork, worker, claude, workflow-subagent, comment-thread-analyst.
// output-style-setup is an older build's. "codex" is the Codex adapter's own fallback when spawn_agent names
// no type (cli/agent-hooks/codex.mjs), so it is not the user's.
export const BUILTIN_SUBAGENT_TYPES = Object.freeze([
  "general-purpose", "Explore", "Plan", "statusline-setup", "claude-code-guide", "fork", "worker", "claude",
  "workflow-subagent", "comment-thread-analyst", "output-style-setup",
  "codex"
]);
const BUILTIN = new Set(BUILTIN_SUBAGENT_TYPES);

// undefined when the host named no type (the field is then omitted, as before).
export function subagentTypeField(type, hash) {
  if (typeof type !== "string" || !type) return undefined;
  return BUILTIN.has(type) ? type : hash(type);
}
