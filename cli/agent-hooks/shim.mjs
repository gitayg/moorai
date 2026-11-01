// Runs MoorAI's Claude Code hook (cli/moorai-hook.mjs) on a payload translated from another agent,
// so every agent gets the same engine, policy, telemetry and verdicts without a second code path.
// The translated payload is Claude Code's hook input shape; the result is reduced to a verdict.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

export const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "moorai-hook.mjs");

// claudePayload: { hook_event_name: "PreToolUse"|"PostToolUse", tool_name, tool_input,
//   tool_response?, session_id?, cwd? }
// returns { decision: "allow"|"ask"|"deny", reason: string, context?: string, coach?: string }
// `coach` is set when the device is not enrolled (data/enforcement.js): the call is allowed and the note
// (what was caught + the safer way) is for the user, and for the agent where the host has a channel.
export function evaluate(claudePayload, { env = process.env, timeoutMs = 20000 } = {}) {
  const r = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify(claudePayload),
    env: { ...env, MOORAI_HOOK_HOST: "shim" },
    encoding: "utf8",
    timeout: timeoutMs,
  });
  const out = (r.stdout || "").trim();
  if (!out) return { decision: "allow", reason: "", ...(r.error && r.error.code === "ETIMEDOUT" ? { timedOut: true } : {}) };
  let j;
  try { j = JSON.parse(out); } catch { return { decision: "allow", reason: "" }; }
  const strip = (s) => String(s || "").replace(/^MoorAI:\s*/, "");
  const h = j.hookSpecificOutput || {};
  if (j.systemMessage && !h.permissionDecision && j.decision !== "block") return { decision: "allow", reason: "", coach: strip(j.systemMessage), ...(h.additionalContext ? { context: strip(h.additionalContext) } : {}) };
  if (h.permissionDecision) return { decision: h.permissionDecision === "deny" ? "deny" : "ask", reason: strip(h.permissionDecisionReason) };
  if (j.decision === "block") return { decision: "deny", reason: strip(j.reason), context: strip(h.additionalContext) };
  if (h.additionalContext) return { decision: "allow", reason: "", context: strip(h.additionalContext) };
  return { decision: "allow", reason: "" };
}

// One host call can map to several Claude calls (a patch touching several files, or two spellings of a
// field that disagree). Each is judged on its own and the most restrictive verdict wins, so no path or
// value the host acts on goes unjudged. A lone payload behaves exactly like evaluate().
// BOUNDED: each call is one hook process, in sequence, inside the host's hook timeout, and a host treats a
// timed-out hook as non-blocking, so an unbounded batch would fail open. Duplicates are judged once; more
// than BATCH_MAX distinct calls, or a batch that outruns deadlineMs or has a call time out, is REFUSED: it
// cannot be fully judged, and an "ask" here would let an agent pad a call (more files, slower checks) to
// turn a would-be deny into a prompt. The reason tells the agent to split the work into smaller calls.
export const BATCH_MAX = 32;
export const BATCH_DEADLINE_MS = 20000;
const RANK = { allow: 0, ask: 1, deny: 2 };
export function batchOf(payloads) {
  const seen = new Set(), out = [];
  for (const p of Array.isArray(payloads) ? payloads : [payloads]) {
    if (!p) continue;
    const k = JSON.stringify([p.tool_name, p.tool_input]);
    if (!seen.has(k)) { seen.add(k); out.push(p); }
  }
  return out;
}
export function evaluateAll(payloads, opts = {}) {
  const list = batchOf(payloads);
  if (!list.length) return { decision: "allow", reason: "" };
  if (list.length === 1) return evaluate(list[0], opts);
  if (list.length > BATCH_MAX) return { decision: "deny", reason: `one call touches too many files to check (${list.length} checks, limit ${BATCH_MAX}); split it into smaller patches` };
  const end = Date.now() + (opts.deadlineMs ?? BATCH_DEADLINE_MS);
  const held = { decision: "deny", reason: "the checks for this call ran out of time; split it into smaller patches" };
  const vs = [];
  for (const c of list) {
    const left = end - Date.now();
    if (left <= 0) return held;
    const v = evaluate(c, { ...opts, timeoutMs: Math.min(opts.timeoutMs ?? 20000, left) });
    if (v.timedOut) return held;
    if (v.decision === "deny") return v;
    vs.push(v);
  }
  let top = vs[0];
  for (const v of vs) if (RANK[v.decision] > RANK[top.decision]) top = v;
  if (top.decision !== "allow") return top;
  const coach = vs.find((v) => v.coach);
  const context = [...new Set(vs.map((v) => v.context).filter(Boolean))].join(" ");
  return { decision: "allow", reason: "", ...(coach ? { coach: coach.coach } : {}), ...(context ? { context } : {}) };
}
