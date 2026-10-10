// The verdict body, exactly as platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint
// ("Return a verdict") specifies it: HTTP 200 for both outcomes, `action` "allow" | "deny";
// `deny_reason` (shown to the end user, at most 500 characters) and `reference_id` (at most 50 characters
// from [A-Za-z0-9._:/-], opaque, no content, no personal data) on a deny.
//
// deny_reason names the engine's reasons ("#54 Remote Code Execution") and, for a tool call, the tool name
// the model used — never the content that was denied.
import { randomBytes } from "node:crypto";

export const DENY_REASON_MAX = 500;
export const REFERENCE_RE = /^[A-Za-z0-9._:/-]{1,50}$/;
export const ALLOW = Object.freeze({ action: "allow" });

export const newReference = () => `moorai:${randomBytes(12).toString("hex")}`;
const clip = (s) => (s.length > DENY_REASON_MAX ? `${s.slice(0, DENY_REASON_MAX - 1)}…` : s);

export function denyBody(reason, reference) {
  return { action: "deny", deny_reason: clip(reason), ...(REFERENCE_RE.test(reference || "") ? { reference_id: reference } : {}) };
}

export function policyDenyReason(frameType, denied) {
  const parts = denied.slice(0, 4).map((d) => {
    const why = (d.reasons || []).join(", ") || "policy";
    return d.kind === "tool_call" ? `tool ${d.name}: ${why}` : d.kind === "prompt" ? why : `${d.kind.replace("_", " ")}: ${why}`;
  });
  const what = frameType === "tool_call" ? "a tool call Claude was about to make" : "this request";
  return `MoorAI blocked ${what} under your organization's AI policy (${parts.join("; ")}). Remove the flagged content and try again.`;
}

const WHY = { size: "content too large to inspect", items: "too much new content to inspect", timeout: "inspection timed out", error: "inspection failed", unparseable: "the request could not be read", body: "the request is too large to inspect", busy: "the inspection server is at capacity" };
export function failDenyReason(whys) {
  const text = [...new Set(whys)].map((w) => WHY[w] || w).join(", ");
  return `MoorAI could not inspect this request (${text}), and your organization's policy blocks what it cannot inspect.`;
}
