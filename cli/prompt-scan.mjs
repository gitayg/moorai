// UserPromptSubmit — which prompts the detection engine scans, and what it may do about one.
//
// A prompt a person types on their own laptop is their instruction, not an attack on them: typing
// "ignore previous instructions" there is not injection. A prompt that arrives any other way can carry a
// third party's text. The hooks reference (code.claude.com/docs/en/hooks.md, UserPromptSubmit input):
//   `source` — How the prompt arrived: "user" for typed input, "sdk" for Agent SDK input, "system" for
//   system messages like idle reminders, "poll_event" for a poll response, "schedule_wakeup" for a
//   scheduled task, or "loop_wakeup" for a background session waking up. Before v2.1.206, "sdk"
//   arrived as "agent_sdk".
// and MoorAI server mode (cli/server-mode.mjs) is `claude -p` fed from an issue, a webhook or a
// schedule, where even a `source` of "user" is whatever the pipeline put there.
//
// policy.promptScan:
//   "untrusted" (default)  scan a prompt whose `source` is present and not "user", and every prompt in
//                          server mode. A prompt with no `source` (older Claude Code, and the Codex /
//                          Cursor / Gemini / Copilot adapters, which do not send one) is a person's.
//   "all"                  scan every prompt.
//   "off"                  scan none.
// policy.promptScanAction:
//   "report" (default)     findings are reported; the prompt goes through and nothing is printed.
//   "block"                a scanned prompt is blocked (`decision: "block"`; per the reference, "Blocks
//                          the prompt, so it never reaches Claude") when a finding is one of the threats
//                          that carry instructions (INSTRUCTION_THREATS), or one whose resolved action is
//                          block / kill. A secret, PII or a legal clause in an issue body is reported, not
//                          blocked: measured, #15 PII alone fired on 56 of 311 benign web pages.
// The scan runs at stage "file" — content the agent ingests, which is the prompt detectors plus the
// directive and rules-poisoning ones (#40, #60). Measured on the corpora against stage "prompt": +9 of 25
// vector-5 and +2 of 45 vector-2 attacks, +1 of 602 benign-v2 prompts.
// Pure: no I/O. The hook supplies the policy, the hook input and whether server mode is on.

// Prompt injection (2, 3, 40, 68, 70, 72, 74), RAG / memory / tool / rules poisoning (21, 22, 25, 60),
// invisible text (50) and system-prompt extraction (51).
export const INSTRUCTION_THREATS = new Set([2, 3, 21, 22, 25, 40, 50, 51, 60, 68, 70, 72, 74]);

const KNOWN_SOURCES = new Set(["user", "sdk", "agent_sdk", "system", "poll_event", "schedule_wakeup", "loop_wakeup"]);

export function promptScanMode(policy) {
  const m = policy && policy.promptScan;
  if (m === false || m === "off") return "off";
  return m === "all" ? "all" : "untrusted";
}

export function promptScanAction(policy) {
  return policy && policy.promptScanAction === "block" ? "block" : "report";
}

// The `source` as a fixed label for alerts: one of KNOWN_SOURCES, "none" when absent, "other" otherwise.
export function promptSource(input) {
  const s = input && input.source;
  if (s === undefined || s === null || s === "") return "none";
  return typeof s === "string" && KNOWN_SOURCES.has(s) ? s : "other";
}

// "server" (MoorAI server mode), "person" (typed, or no source), or "event" (anything else).
export function promptOrigin(input, { server = false } = {}) {
  if (server) return "server";
  const s = promptSource(input);
  return s === "none" || s === "user" ? "person" : "event";
}

export function promptScanPlan(policy, input, { server = false } = {}) {
  const mode = promptScanMode(policy);
  const origin = promptOrigin(input, { server });
  const text = input && typeof input.prompt === "string" ? input.prompt : "";
  const scan = mode !== "off" && !!text.trim() && (mode === "all" || origin !== "person");
  return { scan, mode, origin, source: promptSource(input), action: promptScanAction(policy) };
}

// The findings that block a prompt under promptScanAction "block". `actionOf(id)` is the hook's
// threatActionFor(policy, id).
export function promptBlockers(findings, actionOf) {
  return (findings || []).filter((f) => f.threatId > 0 && (INSTRUCTION_THREATS.has(f.threatId) || ["block", "kill"].includes(actionOf(f.threatId))));
}
