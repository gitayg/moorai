// MXC denial capture -> content-free MoorAI alerts.
//
// With `processContainer.captureDenials.mode: "block"` MXC keeps enforcing and, AFTER the workload
// exits, writes `denials.<run-id>.json` for the launcher (microsoft/mxc @ 7cd00d1,
// docs/logging-access-denied.md "Output file the caller consumes"). The documented shape:
//
//   { "denials": [ { "resource", "resourceType", "accessType", "pid", "filetime" } ],
//     "summary": { "exitCode", "totalDenials", "deniedResourcesTruncated" } }
//
//   resourceType ∈ file | ui | network | capability | other
//   accessType   ∈ read | write | execute | unknown
//   resource     = absolute C:\… path for file, the capability NAME (or S-1-15-3-… SID) for capability,
//                  the raw identifier otherwise
//
// Only these documented fields are read. `resource` never leaves this module: a file becomes its path
// class (cli/mxc-policy.mjs PATH_CLASSES), a capability becomes its well-known name or "custom-sid",
// and every other type is reported by type alone. `pid` and `filetime` are dropped.
//
// The desktop host does this at launch time in Rust (src-tauri/src/mxc.rs); both are pinned to the
// same output by test/fixtures/mxc/denial-cases.json.

import { classifyPath, tokens, PATH_CLASSES } from "./mxc-policy.mjs";

export const MXC_DENIAL_CATEGORY = "MXC: access denied";
export const RESOURCE_TYPES = ["file", "ui", "network", "capability", "other"];
export const ACCESS_TYPES = ["read", "write", "execute", "unknown"];
export const MAX_DENIAL_BYTES = 16 * 1024 * 1024;
export const MAX_GROUPS = 32;

const CAPABILITY_NAME = /^[A-Za-z][A-Za-z0-9]{0,63}$/;
const RISK = Object.fromEntries(PATH_CLASSES.map((c) => [c.id, c.risk]));
const RANK = { Low: 0, Medium: 1, High: 2 };

function riskFor(resourceType, cls) {
  if (resourceType === "file") return RISK[cls] || "Low";
  if (resourceType === "network" || resourceType === "capability") return "Medium";
  return "Low";
}

// text: the denials JSON file contents. ctx: { env, workspace } (the same values the policy was built
// from, so path classes line up with the grants).
// -> { ok:true, groups:[{ reasonCode, resourceType, accessType, pathClass?, capability?, riskLevel, count }],
//      total, truncated, droppedGroups }   or   { ok:false, error }
export function parseDenials(text, ctx = {}) {
  if (typeof text !== "string") return { ok: false, error: "not-text" };
  if (text.length > MAX_DENIAL_BYTES) return { ok: false, error: "too-large" };
  let doc;
  try { doc = JSON.parse(text); } catch { return { ok: false, error: "malformed" }; }
  if (!doc || typeof doc !== "object" || !Array.isArray(doc.denials)) return { ok: false, error: "malformed" };
  const t = tokens(ctx.env, ctx.workspace);
  const groups = new Map();
  let total = 0;
  for (const d of doc.denials) {
    if (!d || typeof d !== "object") continue;
    total++;
    const resourceType = RESOURCE_TYPES.includes(d.resourceType) ? d.resourceType : "other";
    const accessType = ACCESS_TYPES.includes(d.accessType) ? d.accessType : "unknown";
    const g = { resourceType, accessType };
    let label = resourceType;
    if (resourceType === "file") {
      g.pathClass = classifyPath(typeof d.resource === "string" ? d.resource : "", t);
      // "other" is also a resourceType (registry and the like); an unclassified file must not join its group
      label = g.pathClass === "other" ? "file-other" : g.pathClass;
    } else if (resourceType === "capability") {
      g.capability = typeof d.resource === "string" && CAPABILITY_NAME.test(d.resource) ? d.resource : "custom-sid";
      label = `capability-${g.capability}`;
    }
    g.reasonCode = `${label}-${accessType}`;
    g.riskLevel = riskFor(resourceType, g.pathClass);
    const k = g.reasonCode;
    const prev = groups.get(k);
    if (prev) prev.count++;
    else groups.set(k, { ...g, count: 1 });
  }
  const sorted = [...groups.values()].sort((a, b) => RANK[b.riskLevel] - RANK[a.riskLevel] || b.count - a.count || (a.reasonCode < b.reasonCode ? -1 : a.reasonCode > b.reasonCode ? 1 : 0));
  const summary = doc.summary && typeof doc.summary === "object" ? doc.summary : {};
  return {
    ok: true,
    groups: sorted.slice(0, MAX_GROUPS),
    droppedGroups: Math.max(0, sorted.length - MAX_GROUPS),
    total,
    truncated: summary.deniedResourcesTruncated === true
  };
}

// One alert per group, the same content-free envelope cli/moorai-agentwatch.mjs posts to /api/alerts.
// identity: { user, device, platform, tenant }.
export function denialAlerts(parsed, { agent = "", ts = new Date().toISOString(), identity = {} } = {}) {
  if (!parsed || !parsed.ok) return [];
  return parsed.groups.map((g) => {
    const a = {
      threatId: 0,
      category: MXC_DENIAL_CATEGORY,
      riskLevel: g.riskLevel,
      stage: "containment",
      tool: `mxc:${agent}`,
      ts,
      contentHash: `mxc:${g.reasonCode}`,
      reasonCode: g.reasonCode,
      resourceType: g.resourceType,
      accessType: g.accessType,
      count: g.count,
      truncated: parsed.truncated || parsed.droppedGroups > 0,
      source: "mxc-capture-denials"
    };
    if (g.pathClass) a.pathClass = g.pathClass;
    if (g.capability) a.capability = g.capability;
    return { ...identity, ...a };
  });
}
