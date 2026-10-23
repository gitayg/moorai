// The hook's side of approval receipts (cli/approval-receipts.mjs, docs/approval-receipts.md §4): which MCP calls
// get a receipt, the `_moorai` key a model or attacker put in the input, and the PreToolUse answer that carries it.
//
// Nothing changes without a valid approvalReceipts field in the verified policy. With one, for every mcp__ call:
//   * a `_moorai` key already in the input is stripped before the call is judged, so neither the checks nor the
//     approval actionHash nor argsSha256 see it, and the input that goes on is the stripped one;
//   * where the host cannot rewrite the input (a translated call from another agent, the Cursor CLI, a tool name
//     that arrived under an alias), a call that carries `_moorai` is denied, since the key could not be removed;
//   * a call the hook finally ALLOWS to a listed server / tool is answered with `updatedInput` = the stripped input
//     plus `_moorai: { receipt }`: the console's receipt when an approval's first use allowed it, else one signed
//     with the device key (basis "allowed");
//   * a call the hook asks on carries no receipt (its stripped input goes with the ask when it had `_moorai`); a
//     denied call carries nothing.
import { randomBytes } from "node:crypto";
import { receiptPolicy, matchAudience, stripReserved, argsSha256, mintReceipt, WIRE_RE } from "./approval-receipts.mjs";

// → null (nothing changes) or { rp, match: { aud, mcpServer, tool } | null, injected, ti (stripped), rewrites }.
export function receiptIntake({ event, tool, ti, policy, coach = false, rewrites = true, warn } = {}) {
  if (event !== "PreToolUse" || coach || typeof tool !== "string" || !tool.startsWith("mcp__")) return null;
  const rp = receiptPolicy(policy, warn ? { warn } : undefined);
  if (!rp) return null;
  const s = stripReserved(ti);
  return { rp, match: matchAudience(rp, tool), injected: s.had, ti: s.value, rewrites: !!rewrites };
}

// What the approval request carries so the console can mint a receipt for the identical call: { aud, tool,
// argsSha256 } (the argument hash, never the arguments; the console takes device and session from the alert's actor
// and session). null when the call gets no receipt.
export function receiptRequest(intake) {
  if (!intake || !intake.match || !intake.rewrites) return null;
  return { aud: intake.match.aud, tool: intake.match.tool, argsSha256: argsSha256(intake.ti) };
}

// The PreToolUse answer's input for this call. decision: the final verdict; base: the input that would go on
// (a mask's or wrap's rewrite, else the stripped call input); grant: { requestId, receipt } of an approval this call
// used, or null; signer: { sign(bytes), publicKey } of the device key, or null.
// → { input: the updatedInput to send, or null for none; keySource: "console" | "device" | null }.
export function receiptAnswer(intake, { decision, base, grant = null, device = "", session = "", nowSec = Math.floor(Date.now() / 1000), nonce = randomBytes(16).toString("hex"), signer = null } = {}) {
  const none = { input: null, keySource: null };
  if (!intake || decision === "deny" || !intake.rewrites) return none;
  const b = stripReserved(base ?? intake.ti).value;
  const plain = intake.injected ? { input: b, keySource: null } : none;
  if (decision !== "allow" || !intake.match) return plain;
  if (grant && typeof grant.receipt === "string" && WIRE_RE.test(grant.receipt)) return { input: { ...b, _moorai: { receipt: grant.receipt } }, keySource: "console" };
  if (!signer) return plain;
  const wire = mintReceipt({ signer, aud: intake.match.aud, tool: intake.match.tool, input: b, device, session, nonce, iat: nowSec, ttlSec: intake.rp.ttlSec, basis: "allowed", keySource: "device" });
  return wire ? { input: { ...b, _moorai: { receipt: wire } }, keySource: "device" } : plain;
}
