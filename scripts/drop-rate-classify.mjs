// Pure classification for scripts/drop-rate.mjs: given what the deterministic engine did with one attack
// on one surface, did the attack (a) get caught by a rule, (b) miss the rules but stay ELIGIBLE for the
// semantic / on-device-model path, or (c) miss and get DROPPED before any model could see it — and why.
//
// Eligibility is a code-path question. Nothing here calls a model: a model's answer (available, timed out,
// flagged, confidence >= 0.5) decides RECOVERY, not eligibility, and is out of scope by construction.
//
// Every rule below mirrors a gate in the shipped code; the reference is next to each entry.
import { semanticEnabled } from "../data/semantic-escalation.js";

// data/model-escalation.mjs:139 and data/device-inference.mjs:102 send `text.slice(0, 4000)`.
export const MODEL_WINDOW_CHARS = 4000;

export const REASONS = Object.freeze({
  POLICY_OFF: "policy-off",                 // escalation not enabled by the policy (the shipped default)
  NOT_SCANNED: "surface-not-scanned",       // the surface never scans this text
  NO_ESCALATION_CALL: "surface-has-no-escalation", // the surface scans but never calls the semantic path
  OTHER_TEXT: "surface-escalates-other-text",      // the surface escalates a different text than the payload
  STRONG_SKIP: "strong-uncredited-finding", // a High/Critical/Blocked finding that is not the corpus's detection skips escalation
  BASE_NONEMPTY: "uncredited-finding-blocks-miss-recovery", // escalateMiss runs only when the decision credited nothing
  TURN_SPLIT: "multi-turn-split",           // the arc never reaches one escalation call as a whole
  EMPTY: "empty-text"
});

// kind: "harness" = the eval harness's --semantic contract; "hook"/"guard" = a shipped escalation call
// site; "none" = the surface scans but has no escalation call; "other-text" = escalates a different text;
// "unscanned" = the surface does not scan this text. `stage` is the stage the surface scans at.
export const SURFACES = Object.freeze({
  "harness": { kind: "harness", joinsTurns: true, ref: "scripts/redteam-eval.mjs:172 (escalate only when findings.length === 0; turns joined)" },
  "hook:PostToolUse": { kind: "hook", stage: "output", ref: "cli/moorai-hook.mjs:1818 (WebFetch/WebSearch/Bash/PowerShell/Agent/Task/mcp__* results, :135)" },
  "hook:Read": { kind: "hook", stage: "file", ref: "cli/moorai-hook.mjs:2180" },
  "hook:Write": { kind: "hook", stage: "output", ref: "cli/moorai-hook.mjs:2345" },
  "hook:WebFetch-input": { kind: "hook", stage: "prompt", ref: "cli/moorai-hook.mjs:2376 (url + prompt)" },
  "guard:claude-p": { kind: "guard", stage: "prompt", ref: "cli/moorai-guard.mjs:311 -> :80-95" },
  "hook:Bash-command": { kind: "other-text", stage: "prompt", ref: "cli/moorai-hook.mjs:2276 escalates btext (files the command reads, :2198), never ti.command" },
  "hook:UserPromptSubmit-person": { kind: "unscanned", stage: "file", ref: "cli/moorai-hook.mjs:1870 + cli/prompt-scan.mjs promptScanPlan (default promptScan 'untrusted')" },
  "hook:UserPromptSubmit-untrusted": { kind: "none", stage: "file", ref: "cli/moorai-hook.mjs:1867-1901 (no maybeEscalate)" },
  "hook:Task-prompt": { kind: "none", stage: "prompt", ref: "cli/moorai-hook.mjs:2461 (no maybeEscalate)" },
  "hook:mcp-args": { kind: "none", stage: "prompt", ref: "cli/moorai-hook.mjs:2382-2450 (no maybeEscalate)" },
  "hook:index": { kind: "none", stage: "index", ref: "cli/moorai-hook.mjs:1009 runIndexScanWorker (scanForIndex only)" },
  "sdk": { kind: "none", ref: "packages/agent-sdk/src/decide.mjs:42 NOT_EVALUATED includes model-escalation" },
  "mcp-gateway": { kind: "none", stage: "file", ref: "mcp-proxy/moorai-mcp-guard.mjs (no semantic import; its escalate() at :303 is a process-kill ladder)" },
  "model-proxy": { kind: "none", ref: "model-proxy/*.mjs (no semantic import)" },
  "inference-hook": { kind: "none", ref: "cli/inference-hook/*.mjs (no semantic import)" }
});

// The opt-in gate. Hook and guard require policy.modelEscalation AND semanticEscalation != off
// (cli/moorai-hook.mjs:1092; cli/moorai-guard.mjs:82 + src/semantic.js:76/:137). The harness calls
// escalateMiss directly, which gates on semanticEnabled only (src/semantic.js:137).
export function escalationOn(policy, kind) {
  if (!semanticEnabled(policy)) return false;
  return kind === "harness" ? true : !!(policy && policy.modelEscalation);
}

// Stages at which escalate()'s DETECT gate has an in-stage detector (src/semantic.js:78): stage -> the
// threat ids it can add. Read off the engine so a new `semantic:` detector changes the answer.
export function detectGateStages(engine, stages) {
  const out = {};
  for (const s of stages) {
    const want = engine._wantStages(s);
    const ids = engine.detectors.filter((d) => d.semantic === "detect" && engine._inStage(d, want)).map((d) => d.threatId);
    if (ids.length) out[s] = [...new Set(ids)];
  }
  return out;
}

const STRONG = new Set(["High", "Critical", "Blocked"]);

// What the deterministic engine did with one sample at one stage. `credited(ids, findings)` is the
// corpus scorer's own definition of "detected". Multi-turn samples go through scanSession exactly as
// scripts/redteam-eval.mjs:170 does.
export function observe(engine, sample, stage, credited) {
  const turns = Array.isArray(sample.turns);
  const findings = (turns ? engine.scanSession(sample.turns) : engine.scan(sample.text, stage)) || [];
  const baseIds = [...new Set(findings.map((f) => f.threat.id))];
  const text = turns ? sample.turns.join("\n") : String(sample.text || "");
  return {
    caught: !!credited(baseIds, findings),
    baseIds,
    reported: baseIds.length > 0,
    strong: findings.some((f) => STRONG.has(f.riskLevel || f.threat.riskLevel)),
    stage,
    turns,
    textLength: text.trim() ? text.length : 0
  };
}

export function classify(obs, surface, policy, { detectGate = {} } = {}) {
  const S = SURFACES[surface];
  if (!S) throw new Error(`unknown surface ${surface}`);
  const drop = (reason) => ({ bucket: "dropped", reason });
  if (S.kind === "unscanned") return drop(REASONS.NOT_SCANNED); // no rule runs, so nothing is caught either
  if (obs.caught) return { bucket: "caught" };
  if (S.kind === "none") return drop(REASONS.NO_ESCALATION_CALL);
  if (S.kind === "other-text") return drop(REASONS.OTHER_TEXT);
  if (!escalationOn(policy, S.kind)) return drop(REASONS.POLICY_OFF);
  if (!obs.textLength) return drop(REASONS.EMPTY);
  if (obs.turns && !S.joinsTurns) return drop(REASONS.TURN_SPLIT);
  const partial = obs.textLength > MODEL_WINDOW_CHARS;
  if (!obs.baseIds.length) return { bucket: "eligible", route: "miss-recovery", partial };
  if (S.kind === "harness") return drop(REASONS.BASE_NONEMPTY);
  // hook/guard: maybeEscalate returns early on a strong finding (cli/moorai-hook.mjs:1093, cli/moorai-guard.mjs:83)
  if (obs.strong) return drop(REASONS.STRONG_SKIP);
  // escalateMiss is skipped (the decision credited a finding, cli/moorai-hook.mjs runEscalationWorker);
  // only the detect gate is left, and it adds nothing for a threat that already fired (src/semantic.js:100).
  // obs.baseIds is the CREDITED set (the raw re-scan restricted to the ids the decision kept, which is what
  // the worker gates on), so a finding the decision dropped no longer blocks miss-recovery.
  const gate = detectGate[obs.stage] || [];
  if (gate.some((id) => !obs.baseIds.includes(id))) return { bucket: "eligible", route: "detect-gate", partial };
  return drop(REASONS.BASE_NONEMPTY);
}

export function tally(rows, groupOf) {
  const out = {};
  const bump = (g, r) => {
    const e = (out[g] ??= { n: 0, caught: 0, eligible: 0, dropped: 0, reasons: {} });
    e.n++; e[r.bucket]++;
    if (r.bucket === "dropped") e.reasons[r.reason] = (e.reasons[r.reason] || 0) + 1;
  };
  for (const r of rows) { bump(groupOf(r), r); }
  for (const r of rows) bump("ALL", r);
  return out;
}
