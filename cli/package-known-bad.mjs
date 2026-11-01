// A shell command that installs or runs a known-compromised package release, or pipes a known-bad install
// script into a shell (data/known-bad-packages.js: the shipped list plus the signed policy's
// knownBadPackages). Denied by default; the signed policy's knownBadPackages.action may set "ask" or
// "report". The hook judges the command and every script decoded from it.
//
// Content-free: the alert carries the ecosystem, the list the entry came from, the count of matches and a
// keyed hash of ecosystem:name@version. Never the package name, the command or a path.
import { packageInstalls } from "../data/package-installs.js";
import { resolveKnownBad, matchKnownBad, knownBadDecision, KNOWN_BAD_CATEGORY } from "../data/known-bad-packages.js";

// The threat the alert reports under: #57 Unsanctioned or malicious package install.
export const KNOWN_BAD_THREAT = 57;
// The verdict-provenance reason code (cli/provenance.mjs carries the shared ones).
export const KNOWN_BAD_REASON = "PACKAGE_KNOWN_BAD";
export const KNOWN_BAD_ALTERNATIVE = "Install a release that is not on the known-bad list, pinned to its exact version, after checking the project's security advisory.";

// → [{ ref, entry }] for every package or script in the command that is on the list.
export function knownBadHits(command, { ps, kb }) {
  const r = packageInstalls(command, { ps });
  const hits = [];
  for (const ref of [...r.packages, ...r.scripts]) {
    const entry = matchKnownBad(kb, ref);
    if (entry && !hits.some((h) => h.ref.ecosystem === ref.ecosystem && h.ref.name === ref.name && h.ref.version === ref.version)) hits.push({ ref, entry });
  }
  return hits;
}

// command, shell ("sh" | "ps"), scripts [{text, shell}], policy: the verified signed policy (or null),
// hash: a keyed one-way hash. → null | { decision, reason, alert }
export function knownBadShellCheck({ command, shell = "sh", scripts = [], policy = null, tool = "Bash", hash = (s) => s }) {
  const kb = resolveKnownBad(policy);
  const hits = [];
  for (const { text, shell: sh } of [{ text: command, shell }, ...scripts]) {
    if (typeof text !== "string" || !text) continue;
    for (const h of knownBadHits(text, { ps: sh === "ps", kb })) hits.push(h);
  }
  if (!hits.length) return null;
  const decision = knownBadDecision(kb.action);
  const first = hits[0];
  const what = first.ref.ecosystem === "url" ? "an install script on the known-bad list" : `a known-compromised ${first.ref.ecosystem} release`;
  const reason = `${tool} installs ${what}${hits.length > 1 ? ` (and ${hits.length - 1} more)` : ""}`;
  const alert = {
    threatId: KNOWN_BAD_THREAT,
    category: KNOWN_BAD_CATEGORY,
    riskLevel: decision === "deny" ? "Blocked" : "Critical",
    stage: "prompt",
    tool: `hook:${tool}`,
    decision: decision === "deny" ? "block" : decision === "ask" ? "ask" : "alert",
    ecosystem: first.ref.ecosystem,
    knownBadSource: first.entry.source,
    matches: hits.length,
    contentHash: hash(`known-bad:${first.ref.ecosystem}:${first.entry.name}@${first.ref.version || "*"}`)
  };
  return { decision, reason, alert };
}
