// Verdict provenance: which policy decided, which branch decided, and whether the verdict was enforced
// as configured. Stamped onto every alert the hook posts and every row it writes to the local ledgers,
// so a reviewer can tell "allowed because nothing matched" from "allowed because the control never
// ran", and "blocked by the org's rule" from "blocked by a fail-closed floor nobody configured".
//
// Content-free: three short enum/id strings. policyId is derived from the signature envelope and a
// digest of the policy body, never from its contents.

import { policyDigest } from "./hook-core.mjs";

// Stable, short codes. A code names the BRANCH that produced the verdict, not the threat — the threat
// is already in threatId/category. Adding a code is fine; renaming one breaks console filters.
export const REASON = Object.freeze({
  NO_MATCH: "NO_MATCH",                           // every control that applies ran; nothing fired
  DETECTOR_MATCH: "DETECTOR_MATCH",               // an engine detector fired (decideText and kin)
  CONTENT_RULE: "CONTENT_RULE",                   // an org content rule (policy.contentPolicy) fired
  MCP_SERVER_NOT_ALLOWED: "MCP_SERVER_NOT_ALLOWED",
  MCP_ARG_RULE: "MCP_ARG_RULE",
  MCP_REPUTATION: "MCP_REPUTATION",
  MCP_FLOOR: "MCP_FLOOR",                         // fail-closed default: MCP raised to "ask"
  ENVELOPE: "ENVELOPE",                           // entitlement drift (#64)
  JIT_ELEVATION: "JIT_ELEVATION",
  ENDPOINT_NOT_ALLOWED: "ENDPOINT_NOT_ALLOWED",   // model-endpoint allow-list (#63)
  SECRET_EGRESS: "SECRET_EGRESS",                 // local secret value egress (#65)
  INTENT_MISMATCH: "INTENT_MISMATCH",
  DELETION_VOLUME: "DELETION_VOLUME",
  SUBAGENT_POLICY: "SUBAGENT_POLICY",             // #66 delegation resolved by policy
  SESSION_KILL: "SESSION_KILL",
  HEADLESS_ASK: "HEADLESS_ASK",                   // server mode settled an "ask" with no approver
  MASK_APPLIED: "MASK_APPLIED",
  MASK_FALLBACK: "MASK_FALLBACK",                 // a mask could not be applied; the fallback decided
  COACH_UNENROLLED: "COACH_UNENROLLED",           // unenrolled device: coached instead of enforced
  BREAK_GLASS: "BREAK_GLASS",
  POSTURE_FAIL_CLOSED: "POSTURE_FAIL_CLOSED",     // no policy, fail-closed posture: built-in default applied
  POLICY_OFFLINE: "POLICY_OFFLINE",               // enforcing a cached / last-known-good policy
  POLICY_TAMPER: "POLICY_TAMPER",                 // signature, pin, posture or break-glass tamper signal
  BEHAVIOR_SIGNAL: "BEHAVIOR_SIGNAL",             // session-level behaviour (trifecta, autonomy, clipboard, drift)
  HONEYTOKEN: "HONEYTOKEN",
  SKILL_FILE: "SKILL_FILE",
  MODEL_ESCALATION: "MODEL_ESCALATION",
  DESTINATION: "DESTINATION",
  LITERACY: "LITERACY",
  SESSION_SUMMARY: "SESSION_SUMMARY",
  CLAIM_MISMATCH: "CLAIM_MISMATCH",               // agent reported success, the recorded outcomes disagree
  OBSERVATION_ONLY: "OBSERVATION_ONLY",           // an event this hook records but does not judge
  // A control that never ran for this call. Never a pass.
  UNEVALUATED_NO_POLICY: "UNEVALUATED_NO_POLICY",
  UNEVALUATED_HOOK_ERROR: "UNEVALUATED_HOOK_ERROR",
  UNEVALUATED_BAD_INPUT: "UNEVALUATED_BAD_INPUT",
  UNEVALUATED_UNSUPPORTED_TOOL: "UNEVALUATED_UNSUPPORTED_TOOL",
  UNEVALUATED_EMPTY_RESULT: "UNEVALUATED_EMPTY_RESULT",
  UNEVALUATED_SIZE_CAP: "UNEVALUATED_SIZE_CAP",   // only a capped prefix was scanned and nothing fired
  UNEVALUATED_EARLY_EXIT: "UNEVALUATED_EARLY_EXIT"
});

export const ENFORCEMENT = Object.freeze({
  AS_CONFIGURED: "AS_CONFIGURED",
  STRENGTHENED: "STRENGTHENED", // stricter than the org configured: fail-closed default/floor, headless ask -> deny
  LIMITED: "LIMITED",           // weaker than configured: coach, mask fallback, PostToolUse "block" (a message only)
  UNEVALUATED: "UNEVALUATED"    // the control did not run
});

export const BUILTIN_POLICY_ID = "builtin-defaults";
export const OFFLINE_POLICY_ID = "offline-fail-closed-default";

// A stable id for the policy that decided. A signed policy is named by its tenant + issue time + body
// digest; an unsigned one by its digest alone. The two built-in policies have fixed names.
export function policyIdOf(policy, { builtin, offline } = {}) {
  if (!policy) return "none";
  if (policy === builtin) return BUILTIN_POLICY_ID;
  if (policy === offline) return OFFLINE_POLICY_ID;
  let d = "";
  try { d = policyDigest(policy).slice(0, 12); } catch { d = "undigestable"; }
  const s = policy.policySig;
  if (s && typeof s === "object" && s.iat) return `pol:${String(s.tenant ?? "").slice(0, 64)}:${String(s.iat).slice(0, 40)}:${d}`;
  return `pol:unsigned:${d}`;
}

// The reason code for an alert, from the category the posting branch set. Categories are fixed strings
// chosen at each post site, so this is a lookup over the hook's own vocabulary, not a guess at content.
const CATEGORY_REASON = [
  [/^MCP: unapproved server$/, REASON.MCP_SERVER_NOT_ALLOWED],
  [/^MCP: denied tool argument$/, REASON.MCP_ARG_RULE],
  [/^MCP: server reputation$/, REASON.MCP_REPUTATION],
  [/^Agent entitlement drift$/, REASON.ENVELOPE],
  [/^JIT elevation used$/, REASON.JIT_ELEVATION],
  [/^Unapproved model endpoint$/, REASON.ENDPOINT_NOT_ALLOWED],
  [/^Local secret value egress$/, REASON.SECRET_EGRESS],
  [/^Action outside the stated task$/, REASON.INTENT_MISMATCH],
  [/^Unusual deletion volume in session$/, REASON.DELETION_VOLUME],
  [/^Sub-agent \/ A2A delegation$/, REASON.SUBAGENT_POLICY],
  [/^Session terminated \(kill\)$/, REASON.SESSION_KILL],
  [/^Headless approval /, REASON.HEADLESS_ASK],
  [/^Sensitive span masked$/, REASON.MASK_APPLIED],
  [/^Break-glass active/, REASON.BREAK_GLASS],
  [/^Offline: fail-closed default applied$/, REASON.POSTURE_FAIL_CLOSED],
  [/^(Offline: enforcing last-known policy|Enforcing last-known-good verified policy)$/, REASON.POLICY_OFFLINE],
  [/^(Policy signature rejected|Policy key pin|Offline posture|Break-glass marker rejected|Policy: environment set|Server-mode configuration refused)/, REASON.POLICY_TAMPER],
  [/^(Autonomous-agent behavior|Lethal trifecta exposure|Clipboard read then outbound upload|Cross-server toxic flow|Agent behavior: |Agent drift: )/, REASON.BEHAVIOR_SIGNAL],
  [/^Agent destination: /, REASON.DESTINATION],
  [/^Honeytoken canary triggered$/, REASON.HONEYTOKEN],
  [/^Skill-file /, REASON.SKILL_FILE],
  [/^(Model-flagged: |Escalation outcome)/, REASON.MODEL_ESCALATION],
  [/^Literacy: /, REASON.LITERACY],
  [/^Content: /, REASON.CONTENT_RULE],
  [/^MCP tool call$/, REASON.NO_MATCH]
];
export function reasonCodeOf(alert) {
  const c = String((alert && alert.category) || "");
  for (const [re, code] of CATEGORY_REASON) if (re.test(c)) return code;
  return alert && Number(alert.threatId) > 0 ? REASON.DETECTOR_MATCH : REASON.OBSERVATION_ONLY;
}

// Whether this alert records an enforcing outcome (a block, an ask, a mask) rather than a report.
function enforcing(alert) {
  if (alert.enforcing === true) return true;
  const d = alert.decision;
  return alert.riskLevel === "Blocked" || d === "deny" || d === "ask" || d === "mask" || d === "coach";
}

// ctx: { policyId, policySource, coach, event, offline }. Fields the caller already set win.
export function provenanceFor(alert, ctx = {}) {
  const reasonCode = alert.reasonCode || reasonCodeOf(alert);
  let enforcement = alert.enforcement;
  if (!enforcement) {
    if (!enforcing(alert)) enforcement = ENFORCEMENT.AS_CONFIGURED;
    else if (ctx.coach) enforcement = ENFORCEMENT.LIMITED;
    else if (ctx.event === "PostToolUse" && reasonCode !== REASON.MASK_APPLIED) enforcement = ENFORCEMENT.LIMITED;
    else if (ctx.offline) enforcement = ENFORCEMENT.STRENGTHENED;
    else enforcement = ENFORCEMENT.AS_CONFIGURED;
  }
  return { policyId: alert.policyId || ctx.policyId || "unresolved", ...(ctx.policySource ? { policySource: ctx.policySource } : {}), reasonCode, enforcement };
}

// Stamp in place (the same object is often handed to post() and then to recordAction()).
export function stampAlert(alert, ctx) {
  if (!alert || typeof alert !== "object") return alert;
  try {
    const p = provenanceFor(alert, ctx);
    delete alert.enforcing;
    Object.assign(alert, p);
  } catch { /* provenance is metadata; never affects delivery */ }
  return alert;
}
