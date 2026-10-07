// Enrollment decides whether MoorAI may ENFORCE on this device, and every enforcing surface asks here
// so the rule cannot drift between them: the Claude Code hook (and through it the Codex / Copilot /
// Gemini / Cursor adapters), the `claude -p` guard, the Claude Desktop MCP proxy and the desktop app.
// Browser-safe on purpose (no node: imports): the desktop app bundles data/ but not cli/.
//
//   enrolled (an install token)  → today's behaviour: built-in defaults + org policy, which can
//                                   block, ask for sign-off (justify), notify or kill a session.
//   not enrolled                 → COACH: the same detection runs with the same defaults, and the user
//                                   (and, where the host has a channel for it, the agent) is told what
//                                   was caught and the safer way to do it. Nothing is blocked, nothing
//                                   waits for sign-off, no session is killed, and nothing is posted —
//                                   there is no console to post to or to appeal a block to.
//
// `managed` is for evidence of management that outlives the token. The hook passes its durable
// fail-closed posture (an MDM root-owned latch, MOORAI_OFFLINE_MODE, or a posture a verified org
// policy recorded): a device that was put under fail-closed management keeps enforcing if its token is
// removed, so deleting one line from config.json is not a way out of an org's policy.

export function isEnrolled(config) {
  const t = config && config.installToken;
  return typeof t === "string" && t.trim() !== "";
}

export function enforcementAllowed(config, { managed = false } = {}) {
  return isEnrolled(config) || managed === true;
}

// The note shown when a device coaches instead of enforcing. Same "MoorAI:" voice and the same
// "Safer:" line (data/threats.json saferAlternative, per-credential for #55) as a block, so a
// developer who later enrolls sees the same words — only the outcome differs.
export const COACH_TAIL = "Not blocked: this device is not enrolled in a MoorAI console.";

// Enforcement verbs → the coaching verb, and the sign-off marker dropped (nothing waits for one).
export function coachReason(reason) {
  return String(reason || "")
    .replace(/^(?:killed session(?: on)?|blocked|needs justification)\b/, "flagged")
    .replace(/ \(needs sign-off\)/g, "")
    .trim();
}

export function coachMessage(reason, safer) {
  // `(?<!\s)`: the match can only start where whitespace begins (the leftmost start always does); without
  // it a long blank run was retried from each space (60k spaces: 1.7s). See test/data-regex-redos.test.mjs.
  let r = coachReason(reason).replace(/(?<!\s)\s*[—-]\s*$/, "").trimEnd();
  if (r && !/[.!?]$/.test(r)) r += ".";
  const s = typeof safer === "string" && safer.trim() ? ` Safer: ${safer.trim().replace(/\.?$/, ".")}` : "";
  return `MoorAI coach: ${r}${s} ${COACH_TAIL}`.replace(/\s+/g, " ").trim();
}
