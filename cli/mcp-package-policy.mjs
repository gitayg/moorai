// MCP server package policy: hold a registry MCP server (an npm or PyPI package launched by npx / uvx /
// pipx …) whose launch is unpinned, whose version is not the one the org approved, whose package fails a
// critical pre-install check, or whose release is on the known-bad list. Judged where the server is known:
// the Claude Code hook (mcp__<label>__* calls, the label resolved to its launch config) and the MCP guard
// (the launch command it wraps). Enforcement lands on tools/call, as every other MCP gate.
//
// SIGNED POLICY ONLY:
//
//   "mcpPackagePolicy": "report" | "ask" | "block"
//   "mcpPackagePolicy": { "action": "report" | "ask" | "block",
//                         "pins": { "npm:<name>": "<exact version>", "pypi:<name>": "<exact version>" },
//                         "requirePins": true }
//
// Absent: "report" (an alert on first sight or a version change; nothing is held). An action that is not one
// of the three exact values reads as "block" (the org asked for this control and the value cannot be read).
//
// What is judged, from the launch config and the server's reputation evidence (cli/mcp-reputation.mjs):
//   unpinned-version      the launch names no exact version (none, a range or a dist-tag such as latest):
//                         whatever the registry serves at launch runs.
//   version-not-approved  the policy pins this package and the launch names another version or none; with
//                         requirePins, any registry server the policy does not pin.
//   critical-check        a code that fails a moorai-mcp-check check (CRITICAL_CODES): a documented malicious
//                         or typosquatted name, a name not on the registry, a repository that publishes another
//                         package, a remote install script, poisoned tool metadata, SkillTriage DO-NOT-INSTALL,
//                         an integrity mismatch. The hook has the offline codes only (names, the installed npx
//                         copy); the guard adds the registry lookup's when mcpReputation.lookup opts in.
//   version-changed       the reputation cache saw another version of this server before. REPORT ONLY: the
//                         cache is user-writable, and user-writable state never decides a hold. To hold a
//                         changed version, pin the approved one.
//   known-bad-release     the launched version is on the known-bad list (data/known-bad-packages.js). Decided by
//                         knownBadPackages.action (default block), not by mcpPackagePolicy.
//
// Content-free alert: the server label, codes, a keyed hash of the server identity. Never the package name,
// version, a path, an argument or an env var.
import { serverIdentity, findServerDecl } from "./mcp-reputation.mjs";
import { resolveKnownBad, matchKnownBad, knownBadDecision, normName, normVersion } from "../data/known-bad-packages.js";

export const MCP_PACKAGE_ACTIONS = Object.freeze(["report", "ask", "block"]);
export const MCP_PACKAGE_CATEGORY = "MCP: server package supply chain";
export const MCP_PACKAGE_HELD_CATEGORY = "MCP: server package held by policy";
// The threat the alert reports under: #57 Unsanctioned or malicious package install (npx -y of an unvetted
// package is its documented example).
export const MCP_PACKAGE_THREAT = 57;
export const MCP_PACKAGE_REASON = "MCP_PACKAGE_POLICY";
// The reputation codes that fail a moorai-mcp-check check (cli/mcp-package/check-items.mjs: publisher,
// install-scripts and tools fail on these), plus the catalogue / integrity codes that are a block on their own.
export const CRITICAL_CODES = Object.freeze(["pkg-known-malicious", "mcp-typosquat", "pkg-typosquat", "repo-mismatch", "name-not-published",
  "catalogue-name-not-published", "catalogue-do-not-install", "integrity-mismatch", "pkg-install-script-remote", "tool-poisoning", "tool-hidden-content"]);

const own = (o, k) => o !== null && typeof o === "object" && !Array.isArray(o) && Object.prototype.hasOwnProperty.call(o, k);
const RANK = { allow: 1, ask: 2, deny: 3 };

// policy: the verified signed policy (or null). Never throws. → { action, pins: Map, requirePins, invalid, source }
export function resolveMcpPackagePolicy(policy) {
  const out = { action: "report", pins: new Map(), requirePins: false, invalid: false, source: "default" };
  try {
    if (!own(policy, "mcpPackagePolicy")) return out;
    out.source = "policy";
    const p = policy.mcpPackagePolicy;
    if (typeof p === "string") { if (MCP_PACKAGE_ACTIONS.includes(p)) out.action = p; else { out.action = "block"; out.invalid = true; } return out; }
    if (!p || typeof p !== "object" || Array.isArray(p)) { out.action = "block"; out.invalid = true; return out; }
    if (own(p, "action")) { if (MCP_PACKAGE_ACTIONS.includes(p.action)) out.action = p.action; else { out.action = "block"; out.invalid = true; } }
    if (own(p, "pins")) {
      if (!p.pins || typeof p.pins !== "object" || Array.isArray(p.pins)) out.invalid = true;
      else for (const [k, v] of Object.entries(p.pins).slice(0, 2000)) {
        const m = /^(npm|pypi):(.+)$/i.exec(k);
        const ver = typeof v === "string" ? normVersion(m ? m[1].toLowerCase() : "", v) : null;
        if (!m || !ver) { out.invalid = true; continue; }
        const eco = m[1].toLowerCase();
        out.pins.set(`${eco}:${normName(eco, m[2])}`, ver);
      }
    }
    if (own(p, "requirePins")) out.requirePins = p.requirePins === true;
  } catch { out.invalid = true; }
  return out;
}

const actionDecision = (a) => (a === "block" ? "deny" : a === "ask" ? "ask" : "allow");

// decl: { command, args } | { url }. rep: the reputation result (or null). policy: the verified policy (or null).
// → null (not a registry server) | { decision, held: [codes], reportOnly: [codes], critical: [codes], key, reason }
export function judgeMcpPackage(decl, rep, policy) {
  const id = serverIdentity(decl);
  if (id.kind !== "npm" && id.kind !== "pypi") return null;
  const mp = resolveMcpPackagePolicy(policy);
  const kb = resolveKnownBad(policy);
  const eco = id.kind;
  const version = id.pinned ? normVersion(eco, id.ref.version) : null;
  const held = [], reportOnly = [];
  if (!id.pinned) held.push("unpinned-version");
  const pin = mp.pins.get(`${eco}:${normName(eco, id.ref.name)}`);
  if (pin ? pin !== version : mp.requirePins) held.push("version-not-approved");
  const reasons = rep && Array.isArray(rep.reasons) ? rep.reasons : [];
  const critical = CRITICAL_CODES.filter((c) => reasons.includes(c));
  if (critical.length) held.push("critical-check");
  if (rep && rep.versionChanged) reportOnly.push("version-changed");
  const bad = matchKnownBad(kb, { ecosystem: eco, name: id.ref.name, version });
  let decision = held.length ? actionDecision(mp.action) : "allow";
  if (bad) { held.push("known-bad-release"); const kd = knownBadDecision(kb.action); if (RANK[kd] > RANK[decision]) decision = kd; }
  if (!held.length && !reportOnly.length) return { decision: "allow", held, reportOnly, critical, key: id.key, reason: "" };
  const reason = `MCP server package ${[...held, ...reportOnly].join(", ")}${critical.length ? ` (${critical.join(", ")})` : ""}`;
  return { decision, held, reportOnly, critical, key: id.key, reason };
}

// Content-free alert for one judgement.
export function mcpPackageAlert(j, { server, tool, decision, identityHash = (s) => s, stage = "mcp" } = {}) {
  const d = decision || j.decision;
  return {
    threatId: MCP_PACKAGE_THREAT,
    category: d === "deny" || d === "ask" ? MCP_PACKAGE_HELD_CATEGORY : MCP_PACKAGE_CATEGORY,
    riskLevel: d === "deny" ? "Blocked" : j.held.includes("known-bad-release") || j.critical.length ? "Critical" : j.held.length ? "Medium" : "Low",
    stage,
    tool,
    decision: d === "deny" ? "block" : d === "ask" ? "ask" : d === "coach" ? "coach" : "alert",
    mcpServer: String(server || ""),
    packageSignals: [...j.held, ...j.reportOnly].sort(),
    ...(j.critical.length ? { criticalCodes: [...j.critical] } : {}),
    reasonCode: MCP_PACKAGE_REASON,
    contentHash: identityHash(`mcp-package:${j.key}`)
  };
}

// The Claude Code hook's entry point. rep: hookReputation()'s result (or null: reputation off or failed).
// → null | { decision, reason, report, alert }. report: first sight or a version change, or (with no
// reputation evidence to de-duplicate on) a hold.
export function mcpPackageHook(label, { rep = null, policy = null, home, cwd, identityHash } = {}) {
  const decl = (rep && rep.decl) || findServerDecl(label, { ...(home ? { home } : {}), ...(cwd ? { cwd } : {}) });
  if (!decl) return null;
  const r = rep && rep.rep ? rep.rep : null;
  const j = judgeMcpPackage(decl, r, policy);
  if (!j || (!j.held.length && !j.reportOnly.length)) return null;
  const report = r ? !!(r.firstSeen || r.versionChanged) : j.decision !== "allow";
  return { decision: j.decision, reason: `mcp__${label} — ${j.reason}`, reasonCode: MCP_PACKAGE_REASON, report, alert: mcpPackageAlert(j, { server: label, tool: `hook:mcp__${label}`, identityHash }) };
}
