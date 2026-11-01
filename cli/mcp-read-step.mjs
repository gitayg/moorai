// The Claude Code hook's MCP read checks: per-server harvest budgets (cli/mcp-harvest.mjs) with their state on
// the device, and the path scope check (cli/mcp-scope.mjs) against the server's launch config.
//
// STATE (~/.moorai/mcp-harvest.json, mode 0600, written like session-risk.json): per keyed hash of
// (session id, server label): keyed hashes of the distinct read calls with their times, result sizes with
// their times, and which budgets were alerted. 64 keys, dropped after the window. Keys use the device key in
// session.key (cli/session-state.mjs). No server label, tool, argument, URI or result byte is stored.
// Same trust boundary as session-risk.json: the agent runs as the same user and can delete the file, which
// resets its own counts. Fail-open: any error is "nothing to do".
import { readSessionState, writeSessionState, sessionKeyedHash } from "./session-state.mjs";
import { mcpHarvestConfig, isMcpRead, dumpShaped, assessHarvest, harvestAlert, harvestReason, readIdentity } from "./mcp-harvest.mjs";
import { declaredScope, judgeScope, decideScope, scopeAlert } from "./mcp-scope.mjs";
import { findServerDecl } from "./mcp-reputation.mjs";

export const MCP_HARVEST_FILE = "mcp-harvest.json";

// One MCP call (PreToolUse). `method` "resources/read" for ReadMcpResourceTool ({server, uri}).
// → { level: "allow"|"ask"|"block", over, reason, alerts: [alert body without tool prefix/ts/identity], readId }
//   readId: the text the session-risk mass read counts this call under (null when it is not a read).
export function harvestCallStep({ policy, sessionId, server, tool, args, method = "tools/call", now = Date.now(), toolLabel }) {
  const none = { level: "allow", over: [], reason: "", alerts: [], readId: null };
  try {
    const cfg = mcpHarvestConfig(policy);
    if (!isMcpRead(policy, { method, server, tool })) return none;
    const readId = readIdentity(server, method === "resources/read" ? "resources/read" : tool, args);
    if (cfg.mode === "off") return { ...none, readId };
    const key = sessionKeyedHash(`mh:${sessionId || ""}|${server}`);
    const readKey = sessionKeyedHash(`mr:${readId}`);
    if (!key || !readKey) return { ...none, readId };
    const r = assessHarvest(readSessionState(MCP_HARVEST_FILE), key, { pre: true, readKey, dump: method === "tools/call" && dumpShaped(args) }, now, cfg);
    writeSessionState(MCP_HARVEST_FILE, r.state);
    const decision = r.level === "block" ? "deny" : r.level;
    const alerts = r.fresh.map((k) => harvestAlert(k, { server, tool: toolLabel, reads: r.reads, bytes: r.bytes, cfg, decision }));
    return { level: r.level, over: r.over, reason: r.over.length ? harvestReason(r.over) : "", alerts, readId };
  } catch { return none; }
}

// A read call's result (PostToolUse): its size joins the server's byte budget. → [alert body]
export function harvestResultStep({ policy, sessionId, server, tool, bytes, now = Date.now(), toolLabel }) {
  try {
    const cfg = mcpHarvestConfig(policy);
    if (cfg.mode === "off" || !(bytes > 0) || !isMcpRead(policy, { server, tool })) return [];
    const key = sessionKeyedHash(`mh:${sessionId || ""}|${server}`);
    if (!key) return [];
    const r = assessHarvest(readSessionState(MCP_HARVEST_FILE), key, { bytes }, now, cfg);
    writeSessionState(MCP_HARVEST_FILE, r.state);
    return r.fresh.map((k) => harvestAlert(k, { server, tool: toolLabel, reads: r.reads, bytes: r.bytes, cfg, decision: "allow" }));
  } catch { return []; }
}

// The path scope check for one MCP call, against policy roots or the server's launch config.
// → null | { decision: "allow"|"ask"|"deny", reason, alert }
export function scopeCallStep({ policy, server, tool, args, cwd = process.cwd(), toolLabel, decl }) {
  try {
    const d = decl === undefined ? findServerDecl(server, { cwd }) : decl;
    const scope = declaredScope({ policy, label: server, decl: d });
    if (!scope) return null;
    const judged = judgeScope(scope, tool, args, { server });
    const v = decideScope(policy, server, tool, judged);
    if (!v) return null;
    return { decision: v.decision, reason: v.reason, alert: scopeAlert({ tool: toolLabel, server, judged, source: scope.source, decision: v.decision }) };
  } catch { return null; }
}
