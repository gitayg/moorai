// Declared workload profiles at the gateway (cli/workload-profile.mjs, CONTRACT C5 PROFILE_DRIFT). A
// tools/call through a route is evaluated as the hook evaluates the same call made by an agent: the tool
// is named mcp__<route server label>__<params.name>, so the profile an operator wrote for the hook
// ("tools": ["mcp__github__*"], "mcpServers": ["github"]) means the same thing here, and the server label
// it is matched against is the route's.
//
// Same trust rules as the hook: profiles come only from the verified console policy (state.POLICY, from
// loadVerifiedPolicy) and the root-owned machine-wide config (readRootOwned(systemConfigPath())), never a
// repository file, a user config or an environment variable. serviceId is server mode's workload name;
// the repo match uses the gateway's cwd, as the hook uses the session's. Report or block per the profile's
// action; an unenrolled device is coached (forwarded, stderr note); no policy / no profile = no effect.
//
// Drift kinds here are "tool" and "mcpServer" only (C5). The hook's third kind, "host", is read out of
// MCP arguments; the gateway does not evaluate it (host extraction is switched off), so no argument-
// derived item can reach a gateway alert.
import { evaluateProfile, rejectedAlert } from "../cli/workload-profile.mjs";
import { readRootOwned } from "../cli/hook-core.mjs";
import { systemConfigPath } from "../cli/server-mode.mjs";

const NO_HOSTS = () => [];
let sys = { at: 0, value: null };
// The root-owned machine-wide config, re-read at most once a minute (this is a long-lived process).
export function systemConfig(now = Date.now()) {
  if (now - sys.at < 60000) return sys.value;
  let value = null;
  try { const v = JSON.parse(readRootOwned(systemConfigPath()) || "null"); value = v && typeof v === "object" && !Array.isArray(v) ? v : null; } catch { value = null; }
  sys = { at: now, value };
  return value;
}

export const gatewayToolName = (server, tool) => `mcp__${server}__${tool}`;

// → { decision: "allow"|"deny", reason, alerts, rejectedAlert, coach? } — never throws (evaluateProfile is
// fail-open and so is this).
export function profileCheck({ policy, server, tool, serviceId, coach, cwd = process.cwd(), system = systemConfig(), deps = {} }) {
  try {
    const r = evaluateProfile({ policy, system, serviceId, cwd, tool: gatewayToolName(server, tool), toolInput: {}, coach, deps: { extractHosts: NO_HOSTS, ...deps } });
    return { ...r, rejectedAlert: rejectedAlert(r.rejected) };
  } catch {
    return { decision: "allow", reason: "", alerts: [], rejectedAlert: null };
  }
}
