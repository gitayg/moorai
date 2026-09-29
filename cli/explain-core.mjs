// "Why did MoorAI decide that?" — the decision the hook's detector engine + policy reach on one string,
// with every detector that fired, every one that matched but was dropped, and why. The verdict is
// decideText() from cli/hook-core.mjs — the function the hook calls — so the decision cannot drift
// from the hook's; the trace around it only explains, it never decides.
import { decideText, threatActionFor, calibrateRisk, withSafer, coachMessage } from "./hook-core.mjs";

export const STAGES = ["prompt", "file", "output", "index", "tool"];
const EFFECT = { block: "deny", kill: "deny (kills the session)", justify: "ask (halts for sign-off)", notify: "report only", alert: "report only", disabled: "dropped by policy" };

function firstRaw(engine, d, text) {
  try { return engine._firstMatch(text, d.patterns); } catch { return null; }
}

// Some refine-gated detectors use a catch-all pattern and do all their work in refine() (inj-perturbed's
// is /[A-Za-z]{3,}/). Their "matched but dropped" rows say nothing about the input, so they are hidden
// unless `all` is set. Found by probing, not listed: a detector is gate-only if its pattern matches a
// plain sentence.
const NEUTRAL = "the quick brown fox jumps over the lazy dog 42 times.";
function gateOnly(engine, det) { return !!det.refine && !!firstRaw(engine, det, NEUTRAL); }

// One entry per detector that matched anything, plus findings that only the decode/normalize pass or
// the weighted score produced (they have no raw pattern hit).
export function explainText(engine, policy, text, stage, { ctx, coach = false, allowAll = false, showMatch = true, all = false } = {}) {
  const d = decideText(engine, policy, text, stage, { ctx });
  const scanned = new Map(engine.scan(text, stage, ctx).map((f) => [f.threat.id, f]));
  const want = engine._wantStages(stage);
  const rows = [];
  const traced = new Set();
  const base = (threat, detectorId, match) => ({
    detectorId,
    threatId: threat.id,
    threat: threat.threat,
    category: threat.category,
    severity: calibrateRisk(threat.riskLevel, { stage, category: threat.category }),
    riskScore: threat.riskScore,
    ...(showMatch && match != null ? { match: engine._clip(String(match)) } : {})
  });
  for (const det of engine.detectors) {
    if (!engine._inStage(det, want)) continue;
    const raw = firstRaw(engine, det, text);
    if (!raw) continue;
    const threat = engine.threat(det.threatId);
    if (!threat) continue;
    traced.add(det.detectorId);
    const refined = det.refine ? engine._matchDetector(text, det, ctx) : raw;
    const row = base(threat, det.detectorId, refined || raw);
    if (det.refine && !refined) { if (!all && gateOnly(engine, det)) continue; rows.push({ ...row, status: "dropped", why: "pattern matched, but the detector's refine() gate (entropy / allowlist / proximity) rejected every match" }); continue; }
    const kept = scanned.get(threat.id);
    if (kept && kept.detectorId !== det.detectorId) { rows.push({ ...row, status: "superseded", why: `#${threat.id} is already reported by ${kept.detectorId} (one finding per threat)` }); continue; }
    rows.push({ ...row, status: "reported", why: det.refine ? "matched and passed the refine() gate" : "pattern matched" });
  }
  for (const f of scanned.values()) {
    if (traced.has(f.detectorId)) continue;
    rows.push({ ...base(f.threat, f.detectorId, f.match), status: "reported", why: f.obfuscated ? `found after decoding (${f.obfuscated})` : "found by the decode/normalize pass or the weighted score" });
  }
  for (const r of rows) {
    if (r.status !== "reported") { r.action = threatActionFor(policy, r.threatId); r.effect = "none (not a finding)"; continue; }
    r.action = threatActionFor(policy, r.threatId);
    r.effect = EFFECT[r.action] || r.action;
    if (r.action === "disabled") { r.status = "dropped"; r.why = "policy sets this threat to \"disabled\""; }
  }
  // Content-policy findings (parental-control rules) come only from decideText.
  for (const f of d.findings.filter((x) => x.threatId === 0)) rows.push({ detectorId: "content-rule", threatId: 0, threat: f.category, category: f.category, severity: f.riskLevel, status: "reported", why: "policy.contentPolicy rule", action: f.riskLevel === "Blocked" ? "block" : "notify", effect: f.riskLevel === "Blocked" ? "deny" : "report only", ...(showMatch ? { match: f.match } : {}) });
  const rank = { reported: 0, superseded: 1, dropped: 2 };
  rows.sort((a, b) => rank[a.status] - rank[b.status] || (b.riskScore || 0) - (a.riskScore || 0));
  const reason = d.reasons.join("; ");
  let hookOutcome = d.decision;
  if (allowAll) hookOutcome = "allow (break-glass active: the hook allows every call)";
  else if (coach && d.decision !== "allow") hookOutcome = "allow + coach note (device not enrolled: detects and tells, never blocks)";
  return {
    stage,
    decision: d.decision,
    hookOutcome,
    reasons: d.reasons,
    kill: d.kill,
    findings: rows,
    saferAlternatives: d.alternatives,
    message: d.decision === "allow" ? "" : coach ? coachMessage(reason, d.alternatives[0]) : `MoorAI: ${withSafer(reason, d.alternatives)}`
  };
}

export function formatExplain(r, { basis = "", mode = "" } = {}) {
  const out = [`stage: ${r.stage} · policy: ${basis} · mode: ${mode}`, ""];
  if (!r.findings.length) out.push("no detector matched");
  for (const f of r.findings) {
    const head = f.status === "reported" ? `${f.action} → ${f.effect}` : f.status.toUpperCase();
    out.push(`  #${f.threatId} ${f.threat} [${f.category}] · ${f.severity} (risk ${f.riskScore ?? "-"}) · ${f.detectorId}`);
    out.push(`      ${head} — ${f.why}`);
    if (f.match != null) out.push(`      match: ${JSON.stringify(f.match)}`);
  }
  out.push("", `decision: ${r.decision}${r.kill ? " (kill)" : ""}`, `hook outcome: ${r.hookOutcome}`);
  if (r.reasons.length) out.push(`reasons: ${r.reasons.join("; ")}`);
  if (r.saferAlternatives.length) { out.push("safer alternatives:"); for (const a of r.saferAlternatives) out.push(`  - ${a}`); }
  if (r.message) out.push(`message: ${r.message}`);
  out.push("", "scope: detector engine + policy (decideText) only; tool-specific hook checks — file paths, MCP allow-list and reputation, egress sinks, intent alignment — are not evaluated.");
  return out.join("\n");
}
