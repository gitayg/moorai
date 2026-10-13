// The gateway's fail mode (cli/fail-mode.mjs surface "mcpGateway", helpers in cli/mcp-fail.mjs): what it
// does with a tools/call or a tool result it could not judge — a check threw, there was no engine, the
// result scan missed its deadline or its overload window, or a reputation threshold is set and no score
// exists yet. The same rule and alert shape as the stdio guard (mcp-proxy/moorai-mcp-guard.mjs).
//
//   open   (the default) forward it unchanged, as the gateway always has.
//   closed refuse it: a tools/call gets an isError tool result and never reaches the upstream; a result
//          is replaced by an isError result. One content-free alert, reasonCode FAIL_CLOSED.
//
// Coach (unenrolled, unmanaged) never refuses, as for every other gateway block. Admin binding > signed
// policy > open; nothing user-writable is read. A fail-closed refusal is the gateway's failure, not the
// client's, so it never counts toward the client's cool-down.
import { gatewayFailMode, gatewayFailReason, gatewayFailAlert } from "../cli/mcp-fail.mjs";
import { state, ADMIN } from "./policy.mjs";
import { IDENTITY, post } from "./report.mjs";

export { gatewayFailReason as failReason };

// The {mode, source} when the gateway fails closed on an enforcing device, else null (forward, as always).
export function failClosed() {
  if (state.COACH) return null;
  const fm = gatewayFailMode({ policy: state.VERIFIED, admin: ADMIN });
  return fm.mode === "closed" ? fm : null;
}

// stage: "mcp" (a tools/call) or "result".
export function alertFailClosed(stage, why, fm, tool, server) {
  try { post({ ...gatewayFailAlert({ stage, why, source: fm.source, tool: tool || "mcp", server, toolPrefix: "gateway" }), ts: new Date().toISOString(), ...IDENTITY }); } catch { /* evidence, not enforcement */ }
}
