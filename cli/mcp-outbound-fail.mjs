// Encoded content in an MCP call's arguments that MoorAI could not evaluate (cli/mcp-outbound.mjs
// d.unevaluated: a value not decoded whole, or a file's sensitivity label not read or read from a value whose
// decoding skipped characters). Each surface applies its fail mode to it, as for a sampling request past the
// scan bounds (mcp-proxy/sampling-scan.mjs):
//
//   closed  refused: the hook (failMode.hook) denies the PreToolUse call, the stdio guard and the HTTP gateway
//           (failMode.mcpGateway) answer the tools/call with an isError result. One FAIL_CLOSED alert.
//   open    forwarded, with the content-free alert below (threat id 0, Medium), once per tool: per session in the
//           hook, per process in the stdio guard and the HTTP gateway.
//
// It never lowers a decision: a call another check denies is denied whatever the fail mode. Coach mode never
// refuses. Content-free: the cause, the number of values, the server and tool labels.
import { REASON } from "./provenance.mjs";

export const OUTBOUND_UNEVALUATED_CATEGORY = "MCP: outbound arguments not fully evaluated";

export function outboundUnevaluatedAlert(u, { tool = "mcp", server = "", toolPrefix = "desktop" } = {}) {
  const why = u && u.why === "label" ? "label" : "size";
  return {
    threatId: 0, category: OUTBOUND_UNEVALUATED_CATEGORY, riskLevel: "Medium", stage: "mcp", tool: `${toolPrefix}:${tool}`,
    decision: "notify", basisCode: REASON.UNEVALUATED_SIZE_CAP, failMode: "open", failWhy: why,
    unevaluatedValues: (u && Number.isInteger(u.values) && u.values) || 1,
    ...(server ? { mcpServer: server } : {}), contentHash: `mcp:outbound:unevaluated:${why}`
  };
}
