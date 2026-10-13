// Operator-authored context: the text the application itself puts in front of the model — Anthropic `system`,
// OpenAI system / developer messages, Gemini systemInstruction, Ollama system messages and /api/generate
// `system` (the provider files mark these items `context: true`). The operator chose to give its own model
// that data, so a PRIVACY finding there (a card number, an email address, a secret in an "internal data"
// block) is not a leak by the user: it is reported at stage "context", decision notify, and never refuses
// the request. Stamped enforcement LIMITED when the policy's action for it would have blocked or asked.
//
// Every other finding in operator context is decided exactly as before, at stage "prompt": a system prompt
// assembled from untrusted parts (retrieved text, a ticket, a template filled with user data) can carry an
// injection, and that still refuses in enforce mode. A user turn, a tool result and the model's output are
// never context.
import { decideText } from "../cli/hook-core.mjs";
import { settleHeadlessAsk } from "../cli/server-mode.mjs";
import { REASON, ENFORCEMENT } from "../cli/provenance.mjs";

// Threats that mean "this text contains sensitive data", as opposed to "this text attacks something":
//   1 sensitive data · 9 intellectual property · 15 employee / customer personal data · 18 sensitive data
//   retained in a conversation · 27 leakage via history / uploads · 36 cross-context leakage · 39 secret /
//   credential · 44 PHI · 65 local secret value.
// Not included, so still decided in operator context: 51 system-prompt extraction, 71 rendered-output
// exfiltration, 78 / 79 out-of-band collection hosts, 63 / 67 egress and transit (attacks or destinations,
// not data), and every content rule (threat 0).
export const CONTEXT_REPORT_ONLY = Object.freeze(new Set([1, 9, 15, 18, 27, 36, 39, 44, 65]));
export const CONTEXT_STAGE = "context";

// Two views of one engine: only the privacy detectors, and everything else. The engine's own scan runs once
// per view on the same text; a finding is never moved between them.
const views = new WeakMap();
function viewsOf(engine) {
  let v = views.get(engine);
  if (!v) {
    const privacy = Object.create(engine), rest = Object.create(engine);
    privacy.scan = (t, st, c) => engine.scan(t, st, c).filter((f) => CONTEXT_REPORT_ONLY.has(f.threat.id));
    privacy.scanContent = () => [];
    rest.scan = (t, st, c) => engine.scan(t, st, c).filter((f) => !CONTEXT_REPORT_ONLY.has(f.threat.id));
    v = { privacy, rest };
    views.set(engine, v);
  }
  return v;
}

// The verdict for one operator-context item, { decision, reasons }. With no privacy finding it is rt.scan's,
// unchanged. With one: the privacy findings are reported at stage context, and the verdict is the one the
// remaining findings reach, reported and settled as rt.scan reports and settles them.
export async function scanContext(rt, it, text, { settle }) {
  const s = await rt.ready();
  const { privacy, rest } = viewsOf(s.engine);
  const p = decideText(privacy, s.policy, text, "prompt", { ctx: it.ctx });
  if (!p.findings.length) return rt.scan(text, "prompt", it.ctx, { tool: it.kind, event: "ModelRequest", settle });
  const prov = { prov: { policyId: s.policyId, policySource: s.source, event: "ModelRequest" } };
  const tool = `model-proxy:${it.kind}`;
  for (const f of p.findings) {
    rt.reporter.post({ threatId: f.threatId, category: f.category, riskLevel: f.riskLevel, stage: CONTEXT_STAGE, tool, decision: "notify", contentHash: rt.hash(f.match || ""), ...(p.decision !== "allow" ? { enforcement: ENFORCEMENT.LIMITED } : {}) }, prov);
  }
  const d = decideText(rest, s.policy, text, "prompt", { ctx: it.ctx });
  for (const f of d.findings) {
    rt.reporter.post({ threatId: f.threatId, category: f.category, riskLevel: d.decision === "deny" ? "Blocked" : f.riskLevel, stage: "prompt", tool, contentHash: rt.hash(f.match || "") }, prov);
  }
  if (d.decision !== "ask" || !settle || rt.settings.passThrough) return { decision: d.decision, reasons: d.reasons };
  const h = settleHeadlessAsk({ active: true, headless: rt.settings.headless }, s.policy, { decision: "ask", reason: d.reasons.join(", "), tool: it.kind });
  if (h.alert) rt.reporter.post({ ...h.alert, tool, reasonCode: REASON.HEADLESS_ASK, enforcement: h.decision === "deny" ? "STRENGTHENED" : "LIMITED" }, prov);
  return { decision: h.decision, reasons: d.reasons };
}
