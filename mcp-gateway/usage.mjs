// MCP usage from the gateway (CONTRACT C4): every tools/call the gateway gates is counted per server
// label (the route's server) and per tool name (params.name, names only) under path "gateway", host
// "gateway", through the same tally and completed-day post the hook and the stdio proxy use
// (cli/mcp-usage-beat.mjs). Counted blocked or not, as the proxy and the hook count (the proxy counts
// "blocked or not … the hook counts at the top of its mcp__ branch the same way"), so the three paths
// stay comparable on the console.
//
// The identity is the hook's (usageIdentity): user "service" / device "svc:<serviceId>" in server mode,
// user@host otherwise. Completed days are flushed at start-up and every USAGE_FLUSH_MS, off the request
// path, on an unref'd timer; flushMcpUsage posts a day once and shares its pending mark with any other
// gateway process on the same machine.
import { recordMcpCall, flushMcpUsage, usageIdentity } from "../cli/mcp-usage-beat.mjs";
import { CONFIG, IDENTITY } from "./report.mjs";

export const USAGE_FLUSH_MS = 30 * 60 * 1000;
const USAGE_IDENTITY = (() => { try { return usageIdentity(); } catch { return IDENTITY; } })();

// Synchronous and fail-open; the caller schedules it after the request is on its way.
export function countCall(server, tool) {
  return recordMcpCall({ path: "gateway", host: "gateway", label: server, tool });
}

export function flushUsage() {
  return flushMcpUsage({ config: CONFIG, identity: USAGE_IDENTITY, path: "gateway", host: "gateway" }).catch(() => null);
}

export function startUsageFlush() {
  flushUsage();
  const t = setInterval(flushUsage, USAGE_FLUSH_MS);
  if (t.unref) t.unref();
  return t;
}
