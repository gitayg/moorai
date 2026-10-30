// The mask on a tool RESULT, for the surfaces that hold the result before the model reads it and can hand
// on a changed copy: the HTTP MCP gateway and the stdio MCP guard (a tools/call result), and the model proxy
// (a tool result a request sends upstream). The hook has its own copy of the same steps (cli/moorai-hook.mjs
// tryMask / settleMask), because it also has to settle a verdict for Claude Code.
//
// Which threats are masked is cli/inbound.mjs's decision with { mask: true }: by default #39 (a credential in
// a result, CRED_RESULT_DECISION), and any data-tier threat the signed policy sets to "mask". The value is
// walked by cli/mask.mjs (string leaves only, so the shape is unchanged), and the rewritten text is scanned
// again: a surviving finding of a masked threat (an encoded match, a value over the rewrite budget) is a
// failed mask, and the caller falls back to that threat's action without the mask.
//
// Content-free: returns the rewritten value, a count and threat ids; the alert carries only the count and ids.
import { maskValue, maskNote } from "./mask.mjs";
import { decideText, maskFallbackDecision } from "./hook-core.mjs";
import { decideInbound, inboundText } from "./inbound.mjs";
import { REASON } from "./provenance.mjs";

// → null (nothing to mask, or the result is denied anyway) | { ids, value, count } (masked and verified)
//   | { ids, failed: true, fallback } (fallback: maskFallbackDecision's { decision, reasons, alternatives }).
// `verdict`: a decideInbound result the caller already has, made with { mask: true }; else it is made here.
export function maskResult(engine, policy, value, { stage = "file", surface = "door", hash, verdict, text } = {}) {
  const t = text ?? inboundText(value);
  if (!t) return null;
  const d = verdict || decideInbound(engine, policy, t, { surface, stage, mask: true });
  const ids = d.maskIds || [];
  if (!ids.length || d.decision === "deny") return null;
  try {
    const r = maskValue(engine, value, { stage, ids, ctx: { inbound: true }, hash });
    if (r.complete && r.count) {
      const left = decideText(engine, policy, inboundText(r.value), stage, { ctx: { inbound: true }, only: ids, mask: true });
      if (!left.findings.some((f) => ids.includes(f.threatId))) return { ids, value: r.value, count: r.count };
    }
  } catch { /* a failed mask falls back */ }
  return { ids, failed: true, fallback: maskFallbackDecision(policy, ids, t) };
}

// The content-free alert a surface posts for an applied mask (the hook's postMask has the same fields).
export function maskAlert({ tool, stage, ids, count, surface }) {
  return { threatId: 0, category: "Sensitive span masked", riskLevel: "Info", stage, tool, decision: "mask", reasonCode: REASON.MASK_APPLIED, maskedThreats: ids, maskedCount: count, maskedIn: "result", ...(surface ? { surface } : {}), ts: new Date().toISOString(), contentHash: "mask:" + ids.join(".") };
}

// An MCP tools/call result with its masked copy and a note for the model. The note is a text block added
// at the end of `content`, so a client that reads only the first block still gets the masked value first.
export function maskedMcpResult(msg, masked, where = "this MCP tool result") {
  const r = masked.value && typeof masked.value === "object" && !Array.isArray(masked.value) ? masked.value : {};
  const content = Array.isArray(r.content) ? [...r.content, { type: "text", text: maskNote(where, masked.count, masked.ids) }] : r.content;
  return { ...msg, result: { ...r, ...(content !== undefined ? { content } : {}) } };
}
