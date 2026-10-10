// First-seen MCP server reputation — the pure half: weights, score, band, policy action and the
// content-free alert. No I/O (browser-safe, like data/enforcement.js); cli/mcp-reputation.mjs collects the
// signals and owns the cache.
//
// Inspired by gateways that refuse an MCP server below a reputation threshold. MoorAI already pins MCP
// servers and catches one that TURNS malicious (tool-baseline drift, result scanning); this scores a
// server the FIRST time it is seen, from the same engine SkillTriage runs (MoorAI's own package
// heuristics, name classifier and tool-stage detectors) plus, opt-in, SkillTriage's published verdicts.
//
// A score starts at 100 and every signal subtracts its weight. Reasons are CATEGORY CODES only (a MoorAI
// heuristic id such as "pkg-install-script-remote", "threat-<n>" for an engine threat, or one of the
// codes below). Report-only by default: nothing is blocked unless an org policy sets
// mcpReputation.blockBelow AND the device is allowed to enforce (data/enforcement.js).

import { POPULAR_MCP_SERVERS } from "./popular-mcp-servers.js";

export const REPUTATION_CATEGORY = "MCP: server reputation";

// Weights for the codes this layer mints itself. Package-analysis findings are weighted by their tier
// (TIER_WEIGHT) under their own heuristic / threat code.
export const REASON_WEIGHTS = {
  "pkg-known-malicious": 100,     // exact match to a documented malicious / hallucinated name
  "name-not-published": 60,       // the registry has no such package: any account can claim the name
  "catalogue-name-not-published": 60,
  "catalogue-do-not-install": 70, // SkillTriage's published verdict for this package (a block-tier finding)
  "integrity-mismatch": 50,
  // Repository link (registry lookup only; cli/mcp-repo-link.mjs). Measured live 2026-09-29 on the 325
  // listed servers: 98 declare no repository at all (mcp-server-sqlite among them), 8 declare one that
  // is not publicly there, 2 point at a repository whose manifest names another package (npm's
  // security-holder placeholder, and one legitimate rename); on 1,514 npm search results the mismatch
  // rate was 1.8%, mostly third parties republishing someone else's server under their own name.
  "repo-mismatch": 30,            // provenance or the repository's own manifest names another package
  "mcp-typosquat": 45,            // near-miss of a popular MCP server name
  "pkg-typosquat": 45,            // near-miss of a popular library name (data/popular-packages.js)
  "tool-poisoning": 40,           // #60 in an advertised tool description / schema
  "tool-hidden-content": 30,      // #50 hidden canary / invisible characters in tool metadata
  "catalogue-review": 20,
  "pkg-ecosystem-confusion": 15,
  "unresolved-launch": 15,        // the launch command resolves to nothing we can identify
  "repo-unreachable": 15,         // the declared repository is not publicly there (deleted, private, placeholder)
  "new-package": 10,              // first published < 30 days ago (registry lookup only)
  // One account can publish (registry lookup only; cli/mcp-package/maintainers.mjs: npm's top-level
  // `maintainers`, PyPI's `ownership.roles`). A WEAK signal: one person's stolen token or bad day ships a
  // release nobody else reviewed, but that describes most small projects. Measured live 2026-10-09 on the
  // listed servers: 127 of 238 npm (53%) and 67 of 85 PyPI with roles (79%) have exactly one. So it is
  // the lowest weight here: alone a server stays "good" (95); it only moves the band next to other
  // signals (with new-package, repo-missing and unpinned-version: 75, "fair").
  "single-maintainer": 5,
  "remote-server": 10,            // an HTTP/SSE server: no code on this device to read
  "docker-image": 10,             // image analysis is not supported
  "tool-metadata": 10,            // any other tool-stage finding
  "catalogue-caution": 5,
  "unpinned-version": 5,          // `npx -y pkg` runs whatever is latest at launch
  "repo-missing": 5,              // no repository declared, or unparseable (30% of the listed servers)
  "local-source": 5               // a local script: provenance is whoever wrote the file
};
// A block-tier finding is what SkillTriage calls DO-NOT-INSTALL, so on its own it lands in "bad" (< 35).
export const TIER_WEIGHT = { block: 70, justify: 20, notify: 5 };

export const BANDS = [[80, "good"], [60, "fair"], [35, "poor"], [0, "bad"]];
export function bandOf(score) {
  for (const [min, band] of BANDS) if (score >= min) return band;
  return "bad";
}

// signals: [{code, weight}] → {score, band, reasons}. A code counts once, at its highest weight.
export function scoreReputation(signals) {
  const worst = new Map();
  for (const s of signals || []) {
    if (!s || typeof s.code !== "string") continue;
    const w = Number.isFinite(s.weight) ? s.weight : REASON_WEIGHTS[s.code] ?? 0;
    if (!worst.has(s.code) || worst.get(s.code) < w) worst.set(s.code, w);
  }
  let score = 100;
  for (const w of worst.values()) score -= w;
  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, band: bandOf(score), reasons: [...worst.keys()].sort() };
}

export const signal = (code, weight = REASON_WEIGHTS[code] ?? 0) => ({ code, weight });

// ---- MCP-server typosquat: the popular MCP server names are the reference set ----
const LISTED = { npm: new Set(POPULAR_MCP_SERVERS.npm), pypi: new Set(POPULAR_MCP_SERVERS.pypi) };

// Bounded Damerau-Levenshtein "is the distance <= max" (early exit per row).
function withinEdit(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return false;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    let rowMin = Infinity;
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      rowMin = Math.min(rowMin, d[i][j]);
    }
    if (rowMin > max) return false;
  }
  return d[a.length][b.length] <= max;
}

// "listed" | "typosquat" | "unknown". Measured on the list itself: 3 of 325 listed names sit within this
// distance of another listed name (server-github/server-gitlab, n8n-mcp/nx-mcp, atla-/atlan-mcp-server),
// which is why a LISTED name is never a typosquat, and why short names only get distance 1.
export function classifyMcpName(name, ecosystem) {
  const set = LISTED[ecosystem];
  const n = String(name || "").toLowerCase().trim();
  if (!set || n.length < 4) return "unknown";
  if (set.has(n)) return "listed";
  const max = n.length >= 12 ? 2 : 1;
  for (const p of set) if (withinEdit(n, p, max)) return "typosquat";
  return "unknown";
}

// ---- policy ----
// policy = org policy's `mcpReputation` object: { enabled?, blockBelow?, lookup?, feed? }.
// → "allow" | "alert" | "block" | "coach"
export function reputationAction(rep, policy = {}, { enforce = false } = {}) {
  const p = policy && typeof policy === "object" ? policy : {};
  if (p.enabled === false || !rep) return "allow";
  const t = Number(p.blockBelow);
  if (Number.isFinite(t) && t > 0 && rep.score < t) return enforce ? "block" : "coach";
  return rep.band === "good" ? "allow" : "alert";
}

export const BAND_RISK = { good: "Info", fair: "Low", poor: "High", bad: "Critical" };

// Content-free by construction: server LABEL (already on every MCP alert), a keyed identity hash, the
// score, the band and category codes. Never the package name, a path, an argument or an env var.
export function reputationAlert(rep, { server, decision, identityHash, stage = "mcp", tool = "mcp:reputation" } = {}) {
  return {
    threatId: 0,
    category: REPUTATION_CATEGORY,
    riskLevel: decision === "block" ? "Blocked" : BAND_RISK[rep.band] || "Medium",
    stage,
    tool,
    decision: decision || "alert",
    mcpServer: String(server || ""),
    reputation: { score: rep.score, band: rep.band, reasons: [...(rep.reasons || [])] },
    ts: new Date().toISOString(),
    contentHash: identityHash || ""
  };
}

export function reputationSummary(rep) {
  if (!rep) return "";
  return `${rep.score}/100 ${rep.band}${rep.reasons && rep.reasons.length ? ` (${rep.reasons.join(", ")})` : ""}`;
}
