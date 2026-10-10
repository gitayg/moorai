// Content-free reporting for the Inference hooks server, through the runtime's own reporter (surface
// "inference-hook", the workload identity, provenance stamping, the bounded fire-and-forget queue).
// Adjustments, applied to every alert a frame raises (the frame's context rides an AsyncLocalStorage, so
// concurrent frames never mix):
//   * the tool label: "inference-hook:<label>" instead of the hook's "hook:<label>" — the label is the
//     content kind (prompt, tool_result, attachment) or the tool name the model used;
//   * inferenceRef: the reference_id this server returns to Anthropic for the frame, so a denial in the
//     Activity Feed (inference_hooks_request_denied carries it) joins to these alerts;
//   * inferenceSource: source.application (claude-ai, claude-code, cowork, config-test, ...), reduced to
//     [a-z0-9-], advisory routing metadata only;
//   * shadow mode: an alert whose configured outcome is a block or an ask is stamped enforcement LIMITED
//     ("weaker than configured", cli/provenance.mjs) — it would have been denied, and was allowed.
// Never the transcript, a matched span, an email address, an actor id or a URL.
import { AsyncLocalStorage } from "node:async_hooks";
import { REASON, ENFORCEMENT } from "../provenance.mjs";
import { NO_KEY } from "../content-hash.mjs";

export const frameContext = new AsyncLocalStorage();
const enforcing = (a) => a.riskLevel === "Blocked" || a.decision === "deny" || a.decision === "ask";
export const cleanSource = (s) => (typeof s === "string" ? s.toLowerCase().replace(/[^a-z0-9-]/g, "").slice(0, 32) : "");

export function wrapReporter(rt, { shadow }) {
  const post = rt.reporter.post;
  rt.reporter.post = (alert, opts) => {
    const a = { ...alert };
    const f = frameContext.getStore();
    if (typeof a.tool === "string" && a.tool.startsWith("hook:")) a.tool = `inference-hook:${a.tool.slice(5)}`;
    if (f && f.ref) a.inferenceRef = f.ref;
    if (f && f.source) a.inferenceSource = f.source;
    if (shadow && !a.enforcement && enforcing(a)) a.enforcement = ENFORCEMENT.LIMITED;
    return post(a, opts);
  };
}

// The `session` field for alerts this module posts itself: the keyed hash of the frame's session_id,
// computed by the runtime with cli/content-hash.mjs, exactly as rt.scan computes it. No key, no field.
export function sessionField(rt, raw) {
  if (typeof raw !== "string" || !raw) return {};
  const h = rt.hash(raw);
  return h === NO_KEY ? {} : { session: h };
}

// One alert per frame that could not be judged in full: what was not judged (kinds and why), and what
// --fail did about it (failed: the fail verdict decided the frame, i.e. nothing else denied it).
// Content-free.
export function reportUnevaluated(rt, { unevaluated = [], failed, fail, shadow, session, error }) {
  const whys = [...new Set(unevaluated.map((u) => u.why))].sort();
  const kinds = [...new Set(unevaluated.map((u) => u.kind))].sort();
  return rt.ready().then((s) => rt.reporter.post({
    threatId: 0,
    category: error ? "Inference hook: evaluation error" : "Inference hook: content not evaluated",
    riskLevel: fail === "closed" && !shadow ? "Blocked" : "Info",
    stage: "prompt",
    tool: `inference-hook:${kinds[0] || "request"}`,
    decision: failed ? (fail === "closed" && !shadow ? "deny" : "allow") : "allow",
    reasonCode: error ? REASON.UNEVALUATED_HOOK_ERROR : whys.includes("unparseable") ? REASON.UNEVALUATED_BAD_INPUT : whys.includes("timeout") ? REASON.UNEVALUATED_EARLY_EXIT : REASON.UNEVALUATED_SIZE_CAP,
    enforcement: ENFORCEMENT.UNEVALUATED,
    unevaluated: error ? ["error"] : whys,
    failMode: fail,
    contentHash: rt.hash(`inference-hook:unevaluated:${error ? "error" : whys.join(",")}`),
    ...sessionField(rt, session)
  }, { prov: { policyId: s.policyId, policySource: s.source, event: "ModelRequest" } })).catch(() => {});
}
