// The hook's fail mode (cli/fail-mode.mjs, surface "hook"): what cli/moorai-hook.mjs does with a
// PreToolUse call it could not decide — it threw, it ran past its own decision budget, its input could
// not be read, or only a capped prefix of what the call reads was scanned.
//
//   open   (the default) the call proceeds, as it always has: an uncaught error exits non-zero, which
//          Claude Code treats as a non-blocking error, and the ledger row says UNEVALUATED.
//   closed the call is denied. Exit code 2 (Claude Code: "Blocks the tool call", whatever stdout says),
//          with the hook's ordinary PreToolUse deny JSON on stdout (read by cli/agent-hooks/shim.mjs for
//          the other agents) and the same content-free reason on stderr (Claude Code's blocking reason
//          on exit 2). One content-free alert, reasonCode FAIL_CLOSED.
//
// WHO DECIDES, AND WHEN. The admin binding (root-owned /etc/moorai/config.json, read without any policy)
// is known from the first line of main(); the signed policy only once loadVerifiedPolicy has verified it.
// An error before main has the policy runs that same verified load (one shared promise, network and all),
// so every PreToolUse call is decided by admin > the policy the decision path enforces > default. Never a
// network-free read of the cache or a last-known-good copy: those are in the user's write scope and may
// be older than the live policy (v1.14.1). No env variable or settings file is consulted.
//
// NO-BRICK. An operator-signed, live break-glass marker (the same one that lets a fail-closed device out
// of the offline default) turns a fail-closed verdict back into an allow, so a hook bug cannot lock a
// managed fleet out of its agents with no way back. Only PreToolUse can be denied; every other event
// (PostToolUse, UserPromptSubmit, Stop, ...) keeps failing open — a non-zero exit there would block a
// prompt or keep a session from stopping, not refuse a tool call.
import { resolveFailMode } from "./fail-mode.mjs";
import { REASON, ENFORCEMENT } from "./provenance.mjs";

// Below cli/agent-hooks/shim.mjs's 20 s child timeout (a timed-out child reads as allow there) and far
// below Claude Code's 600 s command-hook default. A healthy hook decides in well under a second.
export const HOOK_DECISION_BUDGET_MS = 15000;

const WHY = {
  error: "the MoorAI hook failed while evaluating it",
  budget: "the MoorAI hook ran past its decision budget",
  "bad-input": "the MoorAI hook could not read the call",
  "size-cap": "it reads more content than MoorAI scans",
  label: "MoorAI could not read the sensitivity label of a file it reads"
};
const BASIS = {
  error: REASON.UNEVALUATED_HOOK_ERROR,
  budget: REASON.UNEVALUATED_EARLY_EXIT,
  "bad-input": REASON.UNEVALUATED_BAD_INPUT,
  "size-cap": REASON.UNEVALUATED_SIZE_CAP,
  label: REASON.UNEVALUATED_SIZE_CAP
};

export function failReason(why) {
  return `this tool call was not evaluated (${WHY[why] || WHY.error}), and your organization blocks what MoorAI cannot evaluate`;
}

// policy: the verified org policy, or null before it is verified. admin: the parsed admin binding.
export function hookFailMode({ policy = null, admin = null, warn } = {}) {
  return resolveFailMode(policy, "hook", { admin, fallback: "open", ...(warn ? { warn } : {}) });
}

// Only a PreToolUse call can be refused. `raw` is the stdin text, for input that did not parse.
export function failClosedApplies({ event = "", raw = "" } = {}) {
  if (event) return event === "PreToolUse";
  return /"hook_event_name"\s*:\s*"PreToolUse"/.test(String(raw).slice(0, 4096));
}

// → { stdout, stderr, code }. Content-free: a fixed sentence per cause.
export function failClosedOutput(why) {
  const reason = `MoorAI: ${failReason(why)}`;
  return {
    stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } }),
    stderr: `${reason}\n`,
    code: 2
  };
}

// The ledger fields and the alert for a fail-closed deny. Content-free: the cause and where the mode came from.
export function failClosedVerdict(why) {
  return { decision: "deny", reasonCode: REASON.FAIL_CLOSED, basisCode: BASIS[why] || REASON.UNEVALUATED_HOOK_ERROR, enforcement: ENFORCEMENT.STRENGTHENED };
}
export function failClosedAlert(why, source) {
  return {
    threatId: 0, category: "Fail-closed: tool call not evaluated", riskLevel: "Blocked", stage: "policy", tool: "hook:policy",
    decision: "deny", ...failClosedVerdict(why), failMode: "closed", failModeSource: source || "default", failWhy: BASIS[why] ? why : "error",
    contentHash: `fail-closed:${BASIS[why] ? why : "error"}`
  };
}
