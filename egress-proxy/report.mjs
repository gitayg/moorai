// Content-free reporting for the egress proxy, the MCP gateway's way (mcp-gateway/report.mjs): an alert goes
// to OpenTelemetry when configured and to the console when the device is enrolled, with the workload
// identity (container id, Kubernetes pod / namespace / node) when one is detected. What leaves is what
// server.mjs builds: category, risk, decision, reason code, binary (null), host, port, method and the
// deciding rule. Never a path, a query, a header, a body or a credential.
import os from "node:os";
import { loadConfig } from "../cli/config.mjs";
import { isEnrolled } from "../cli/hook-core.mjs";
import { actorHash } from "../cli/content-hash.mjs";
import { emitOtel } from "../cli/otel.mjs";
import { serverMode, serviceWho, workloadIdentity } from "../cli/server-mode.mjs";

export const CONFIG = loadConfig();
export const SERVER_MODE = serverMode();
const WHO = SERVER_MODE.active ? serviceWho(SERVER_MODE) : { user: os.userInfo().username, device: os.hostname() };
export const IDENTITY = { user: WHO.user, device: WHO.device, platform: os.platform(), tenant: CONFIG.tenant, actor: actorHash(WHO.user, WHO.device) };
export const WORKLOAD = workloadIdentity();

export function post(alert) {
  const a = { ...alert, ts: new Date().toISOString(), ...IDENTITY };
  try { emitOtel(a, { config: CONFIG, identity: IDENTITY }); } catch { /* telemetry is never enforcement */ }
  if (!isEnrolled(CONFIG)) return;
  try {
    return fetch(`${CONFIG.serverUrl}/api/alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {}) },
      body: JSON.stringify(WORKLOAD ? { ...a, workload: WORKLOAD } : a),
      signal: AbortSignal.timeout(1500)
    }).catch(() => {});
  } catch { /* never let a network error touch a connection */ }
}

const REPORTED = new Set();
export function reportOnce(category, hash, riskLevel) {
  if (REPORTED.has(hash)) return;
  REPORTED.add(hash);
  post({ threatId: 0, category, riskLevel, stage: "policy", tool: "egress-proxy:policy", contentHash: hash });
}
