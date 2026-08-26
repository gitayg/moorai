// #21 — semantic / embedding escalation layer. Regex/entropy (the engine) runs first and OWNS the
// allow/deny decision; this module is only reached on the ambiguity gate and only when the policy opts
// in (semanticEscalation ≠ "off", default OFF). It asks an on-device model — the loopback Ollama model,
// or the agent's OWN provider key already on the device — for a bounded, fail-open second opinion, then
// reduces it to a content-free { flagged, category, confidence } verdict. It introduces NO new egress
// and NO new third party: the only backends are the ones data/model-escalation.mjs already talks to.
//
// This lives OUTSIDE engine.js on purpose. engine.js is imported by the browser bundle (src/app.js); the
// backends here pull node-only code (device-inference.mjs → node:fs). So the engine takes this in by
// injection (engine.scanSemantic(text, stage, policy, escalate)) — the browser never imports this file.
//
// NOTE on ordering (see test/escalation-ordering.test.mjs, F-301): the caller MUST place the escalate
// call AFTER any deny decision, so content the policy is about to block is never sent to the provider.
// This module does not — and cannot — reorder the caller's pipeline; it only classifies what it is given.
import { classifyOpportunistic } from "../data/model-escalation.mjs";
import { semanticEnabled } from "../data/semantic-escalation.js";

const LEVEL_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };
const CONFIRM_MIN = 0.5;

function contentFree(v) {
  return {
    flagged: !!v.flagged,
    category: String(v.category || "model").slice(0, 40),
    confidence: Math.max(0, Math.min(1, Number(v.confidence) || 0)),
    backend: v.backend
  };
}

// Bounded, fail-open verdict for one span. Gated by the policy flag (default OFF): when disabled it
// returns null WITHOUT consulting any model — the off-by-default, zero-egress guarantee lives here.
// Hard-bounded by timeoutMs on top of the per-backend timeouts, so it can never hang the hook. Never
// throws; every failure path resolves to null (fail-open — the caller keeps the regex-only verdict).
export async function semanticVerdict(text, policy, { timeoutMs = 3500 } = {}) {
  if (!semanticEnabled(policy)) return null;
  if (!text || !String(text).trim()) return null;
  let timer;
  try {
    const guard = new Promise((res) => { timer = setTimeout(() => res(null), timeoutMs); });
    const v = await Promise.race([classifyOpportunistic(text, policy), guard]);
    return v && typeof v.flagged === "boolean" ? contentFree(v) : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// Orchestrator injected into engine.scanSemantic. `base` is the finished regex/entropy finding list.
// Only detectors flagged for escalation (`d.semantic`) participate; everything else is passed through
// untouched. A single bounded verdict over the text is fetched, then applied two ways:
//   - confirm gate  (d.semantic === true | "confirm"): if the model clears the span (not a risk, with
//     confidence ≥ CONFIRM_MIN), the otherwise-firing finding is DROPPED as a false positive.
//   - detect gate   (d.semantic === "detect"): if the model flags a risk the regex missed, a finding is
//     ADDED for that detector's threat (content-free match label — the span text never leaves here).
// Fail-open everywhere: policy off, no flagged detectors, or a null verdict → `base` is returned as-is.
// `opts.verdict(text, policy)` overrides the model call (used by tests); otherwise semanticVerdict runs.
export async function escalate(engine, base, text, stage, policy, opts = {}) {
  if (!semanticEnabled(policy)) return base;
  const want = engine._wantStages(stage);
  const semDetectors = engine.detectors.filter((d) => d.semantic && engine._inStage(d, want));
  if (!semDetectors.length) return base;

  const verdict = opts.verdict
    ? await opts.verdict(text, policy)
    : await semanticVerdict(text, policy, opts);
  if (!verdict) return base;

  let findings = base;

  if (verdict.flagged === false && verdict.confidence >= CONFIRM_MIN) {
    const drop = new Set(
      semDetectors.filter((d) => d.semantic === true || d.semantic === "confirm").map((d) => d.detectorId)
    );
    if (drop.size) findings = findings.filter((f) => !drop.has(f.detectorId));
  }

  if (verdict.flagged === true && verdict.confidence >= CONFIRM_MIN) {
    const fired = new Set(findings.map((f) => f.threat.id));
    for (const d of semDetectors) {
      if (d.semantic !== "detect") continue;
      const threat = engine.threat(d.threatId);
      if (!threat || fired.has(threat.id)) continue;
      fired.add(threat.id);
      findings = [...findings, {
        detectorId: d.detectorId,
        mode: d.mode || "warn",
        hint: d.hint,
        match: `semantic:${verdict.category}`,
        threat,
        semantic: true,
        confidence: verdict.confidence
      }];
    }
  }

  if (findings === base) return base;
  return findings.slice().sort(
    (a, b) =>
      (LEVEL_RANK[b.threat.riskLevel] - LEVEL_RANK[a.threat.riskLevel]) ||
      (b.threat.riskScore - a.threat.riskScore)
  );
}
