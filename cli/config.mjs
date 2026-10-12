import { serverMode, systemConfig, readUserConfig } from "./server-mode.mjs";

// Resolves the agent's management binding: which console the hook fetches policy from and posts to, under
// which tenant, with which install token. Every component reads it here (the hook, the claude -p guard, the
// MCP guard and gateway, the doctor), so the rule cannot drift between them.
//
// ADMIN FIRST, ON LAPTOPS TOO. The root-owned machine config (/etc/moorai/config.json; Windows
// <ProgramData from HKLM>\MoorAI\config.json, read only when its ACL is administrator-only) is read first,
// through hook-core readRootOwned. When it names a usable `serverUrl`, the device is MANAGED:
//   * serverUrl and tenant are the machine file's, always (tenant "unprovisioned" if it names none);
//   * the install token comes from the user's own file (~/.moorai/config.json, 0600, the enrolled user's),
//     never from the machine file: that file is world-readable (0644 / Users read), so it carries only the
//     non-secret binding, and an installToken found in it is ignored. The token can only ever be sent to
//     the admin console, whatever the user file says about consoles;
//   * a user file (~/.moorai, ~/.curaiq, ~/.raiseme config.json) that names another console or tenant is
//     REFUSED, never merged, and listed in `refused` so the hook raises one content-free tamper alert
//     (reasonCode BINDING_REFUSED: the key names, never a value). A refused tenant takes the user file's
//     token down with it: that token belongs to the other tenant;
//   * `managed: true`: data/enforcement.js counts it as management evidence, so a managed device never
//     drops to coach mode, whatever the user file says or lacks. Without a token its alerts cannot be
//     posted (the console authenticates them by token); the hook still enforces, keeps a content-free
//     local record, and consumes alert sequence numbers so the gap shows once the token is back.
// The user files and the environment are the agent's to write, which is why none of them can move a
// managed binding. The token in the user's own file stays readable by the agent (same OS user) until the
// privileged helper (design docs/proposals/trust-anchors.md, phase 2) holds it.
//
// Unmanaged (no usable machine serverUrl): exactly what this function always returned, the first user
// file that parses, then MoorAI_SERVER / MoorAI_TENANT, then localhost. Server mode (cli/server-mode.mjs)
// keeps its own precedence, which already puts the machine file first (a root-owned file in a container
// image or a Kubernetes secret volume, which may carry the token).
const clean = (v) => (typeof v === "string" ? v.trim() : "");
function validUrl(v) {
  try { const u = new URL(clean(v)); return u.protocol === "http:" || u.protocol === "https:" ? clean(v).replace(/\/+$/, "") : ""; } catch { return ""; }
}

// Pure. system: the parsed machine config or null. user: readUserConfig() ({ path, data }) or null.
export function resolveBinding({ system = null, user = null, env = process.env } = {}) {
  const sys = system && typeof system === "object" ? system : {};
  const u = user && user.data && typeof user.data === "object" ? user.data : null;
  const sysUrl = validUrl(sys.serverUrl);
  if (!sysUrl) {
    const fallback = { serverUrl: env.MoorAI_SERVER || "http://localhost:8787", tenant: env.MoorAI_TENANT || "unprovisioned" };
    if (!u) return fallback;
    return { serverUrl: u.serverUrl || fallback.serverUrl, tenant: u.tenant || fallback.tenant, installToken: u.installToken || "" };
  }
  const refused = [];
  const sources = { serverUrl: "system", tenant: clean(sys.tenant) ? "system" : "default", installToken: "none" };
  if (u && clean(u.serverUrl) && validUrl(u.serverUrl) !== sysUrl) refused.push("serverUrl");
  const tenant = clean(sys.tenant) || "unprovisioned";
  if (u && clean(u.tenant) && clean(u.tenant) !== tenant) refused.push("tenant");
  let installToken = "";
  if (u && clean(u.installToken)) {
    if (refused.includes("tenant")) refused.push("installToken");
    else { installToken = clean(u.installToken); sources.installToken = "file"; }
  }
  return { serverUrl: sysUrl, tenant, installToken, managed: true, source: "system", sources, refused, ...(refused.length && user && user.path ? { refusedFile: user.path } : {}) };
}

export function loadConfig({ system, user, env = process.env } = {}) {
  const sm = serverMode();
  if (sm.active) return { ...sm.config };
  return resolveBinding({ system: system !== undefined ? system : systemConfig(), user: user !== undefined ? user : readUserConfig(), env });
}

// The content-free tamper alert for a refused user binding: key names and nothing else. Null when nothing
// was refused. Same shape as the hook's other policy-stage tamper alerts.
export const BINDING_REFUSED = "BINDING_REFUSED";
export function bindingRefusedAlert(config) {
  if (!config || !config.managed || !Array.isArray(config.refused) || !config.refused.length) return null;
  const keys = [...config.refused].sort();
  return { threatId: 0, category: "Console binding refused (admin binding present)", riskLevel: "Critical", stage: "policy", tool: "hook:policy", contentHash: `binding-refused:${keys.join(".")}`, reasonCode: BINDING_REFUSED, refusedKeys: keys };
}
