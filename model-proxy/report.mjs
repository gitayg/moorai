// Content-free reporting for the model proxy, through the runtime's own reporter (surface "model-proxy",
// the workload identity, provenance stamping, the bounded fire-and-forget queue). Two adjustments:
//   * the tool label: "model-proxy:<label>" instead of the hook's "hook:<label>" — the label is the content
//     kind for a request item (prompt, system, tool_result, document) or the tool the model called;
//   * report-only mode: an alert whose configured outcome is a block or an ask is stamped
//     enforcement LIMITED ("weaker than configured", cli/provenance.mjs), because the proxy forwarded the
//     traffic unchanged. Nothing about the text, the arguments, a header or a URL is ever added.
import { REASON, ENFORCEMENT } from "../cli/provenance.mjs";

const enforcing = (a) => a.riskLevel === "Blocked" || a.decision === "deny" || a.decision === "ask";

export function wrapReporter(rt, { enforce }) {
  const post = rt.reporter.post;
  rt.reporter.post = (alert, opts) => {
    const a = { ...alert };
    if (typeof a.tool === "string" && a.tool.startsWith("hook:")) a.tool = `model-proxy:${a.tool.slice(5)}`;
    if (!enforce && !a.enforcement && enforcing(a)) a.enforcement = ENFORCEMENT.LIMITED;
    return post(a, opts);
  };
}

// One alert per label for content the proxy could not evaluate in full (an item past the scan cap, more
// new items than one request scans, tool-call arguments past the hold cap).
export function unevaluatedReporter(rt) {
  const seen = new Set();
  return (label, direction) => {
    const name = String(label || "unknown").replace(/[^A-Za-z0-9_.:\-]/g, "_").slice(0, 64);
    const k = `${direction}:${name}`;
    if (seen.has(k)) return;
    if (seen.size >= 1024) seen.clear();
    seen.add(k);
    rt.ready().then((s) => rt.reporter.post({
      threatId: 0, category: "Model proxy: content not evaluated (size cap)", riskLevel: "Info", stage: direction === "request" ? "prompt" : "tool",
      tool: `model-proxy:${name}`, reasonCode: REASON.UNEVALUATED_SIZE_CAP, enforcement: ENFORCEMENT.UNEVALUATED, contentHash: rt.hash(k)
    }, { prov: { policyId: s.policyId, policySource: s.source, event: direction === "request" ? "ModelRequest" : "PreToolUse" } })).catch(() => {});
  };
}

// The refusal text an agent sees: the threat ids / categories the engine names and the tool name the model
// used (from the agent's own tool list) — never the content that was refused.
const safeName = (s) => String(s || "").replace(/[^A-Za-z0-9_.:\-]/g, "_").slice(0, 64);
export function refusalMessage(verdict, direction) {
  const parts = verdict.denied.slice(0, 4).map((d) => `${direction === "request" ? safeName(d.kind) : `tool call ${safeName(d.name)}`}: ${(d.reasons || []).join(", ") || "policy"}`);
  return `MoorAI model-proxy refused this ${direction === "request" ? "request" : "response"} — ${parts.join("; ")}`;
}
