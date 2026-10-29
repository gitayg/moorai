// The MCP gateway surfaces' fail mode (cli/fail-mode.mjs, surface "mcpGateway"): what the stdio guard
// (mcp-proxy/moorai-mcp-guard.mjs) does with a tools/call or a tool result it could not judge — the gate
// threw, there was no engine, the result scan missed its deadline or its overload window, or a
// reputation threshold is set and no score exists yet, or a block-mode tool-drift re-list before a
// tools/call failed or ran out of time (mcp-proxy/tool-recheck.mjs), or the sensitivity label of a file
// the arguments name could not be established under labelPolicy (cli/sensitivity-labels.mjs).
//
//   open   (the default) forward it unchanged, as the guard always has.
//   closed refuse it: a tools/call gets an isError tool result and never reaches the server; a result is
//          replaced by an isError result. One content-free alert, reasonCode FAIL_CLOSED.
//
// Coach mode (unenrolled, unmanaged) never refuses. Admin binding > signed policy > open; nothing
// user-writable is read. The supply-chain floor is NOT governed by this: an MCP package MoorAI could not
// fetch or verify stays REVIEW (cli/mcp-package.mjs) whatever the fail mode says, because "not
// verified" is that check's verdict, not a failure to reach one.
import { resolveFailMode } from "./fail-mode.mjs";
import { REASON, ENFORCEMENT } from "./provenance.mjs";

export function gatewayFailMode({ policy = null, admin = null, warn } = {}) {
  return resolveFailMode(policy, "mcpGateway", { admin, fallback: "open", ...(warn ? { warn } : {}) });
}

const WHY = {
  error: "MoorAI failed while evaluating it",
  "no-engine": "no MoorAI policy engine was available",
  timeout: "MoorAI did not finish evaluating it in time",
  budget: "MoorAI's scan budget was exhausted",
  reputation: "the MCP server's reputation could not be established",
  recheck: "MoorAI could not re-check the MCP server's current tool list",
  label: "MoorAI could not read the sensitivity label of a file it names"
};
const BASIS = { error: REASON.UNEVALUATED_HOOK_ERROR, "no-engine": REASON.UNEVALUATED_NO_POLICY, timeout: REASON.UNEVALUATED_EARLY_EXIT, budget: REASON.UNEVALUATED_EARLY_EXIT, reputation: REASON.UNEVALUATED_EARLY_EXIT, recheck: REASON.UNEVALUATED_EARLY_EXIT, label: REASON.UNEVALUATED_SIZE_CAP };
const known = (why) => (Object.prototype.hasOwnProperty.call(WHY, why) ? why : "error");

// The isError text after the guard's own "MoorAI blocked this MCP tool call: " / "... tool result: ".
export function gatewayFailReason(why) {
  return `not evaluated (${WHY[known(why)]}), and your organization blocks what MoorAI cannot evaluate`;
}

// stage: "mcp" (a tools/call) or "result". Content-free: the cause, the server label, the tool label.
export function gatewayFailAlert({ stage = "mcp", why, source, tool = "mcp", server = "", toolPrefix = "desktop" } = {}) {
  const w = known(why);
  return {
    threatId: 0, category: stage === "result" ? "Fail-closed: MCP result not evaluated" : "Fail-closed: MCP call not evaluated",
    riskLevel: "Blocked", stage, tool: `${toolPrefix}:${tool}`, decision: "deny", reasonCode: REASON.FAIL_CLOSED, basisCode: BASIS[w],
    enforcement: ENFORCEMENT.STRENGTHENED, failMode: "closed", failModeSource: source || "default", failWhy: w,
    ...(server ? { mcpServer: server } : {}), contentHash: `fail-closed:${stage}:${w}`
  };
}
