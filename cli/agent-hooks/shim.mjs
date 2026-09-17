// Runs MoorAI's Claude Code hook (cli/moorai-hook.mjs) on a payload translated from another agent,
// so every agent gets the same engine, policy, telemetry and verdicts without a second code path.
// The translated payload is Claude Code's hook input shape; the result is reduced to a verdict.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

export const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "moorai-hook.mjs");

// claudePayload: { hook_event_name: "PreToolUse"|"PostToolUse", tool_name, tool_input,
//   tool_response?, session_id?, cwd? }
// returns { decision: "allow"|"ask"|"deny", reason: string, context?: string }
export function evaluate(claudePayload, { env = process.env, timeoutMs = 20000 } = {}) {
  const r = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify(claudePayload),
    env: { ...env, MOORAI_HOOK_HOST: "shim" },
    encoding: "utf8",
    timeout: timeoutMs,
  });
  const out = (r.stdout || "").trim();
  if (!out) return { decision: "allow", reason: "" };
  let j;
  try { j = JSON.parse(out); } catch { return { decision: "allow", reason: "" }; }
  const strip = (s) => String(s || "").replace(/^MoorAI:\s*/, "");
  const h = j.hookSpecificOutput || {};
  if (h.permissionDecision) return { decision: h.permissionDecision === "deny" ? "deny" : "ask", reason: strip(h.permissionDecisionReason) };
  if (j.decision === "block") return { decision: "deny", reason: strip(j.reason), context: strip(h.additionalContext) };
  if (h.additionalContext) return { decision: "allow", reason: "", context: strip(h.additionalContext) };
  return { decision: "allow", reason: "" };
}
