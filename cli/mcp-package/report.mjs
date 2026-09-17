// Markdown rendering of the per-package section of a `moorai scan` report. Content-free: only the
// fields analyzePackage already emits (ids, categories, tiers, package-relative paths).

const BADGE = { CLEAN: "✅ CLEAN", CAUTION: "🟡 CAUTION", REVIEW: "🟠 REVIEW", "DO-NOT-INSTALL": "🔴 DO-NOT-INSTALL" };

function notesText(notes) {
  return (notes || []).map((n) => (n.ageDays !== undefined ? `${n.id} (${n.ageDays}d)` : n.count !== undefined ? `${n.id} (${n.count})` : n.id)).join(", ");
}

export function renderPackagesMarkdown(packages) {
  let out = `## MCP server packages\n\n| Package | Ecosystem | Analysed | Verdict | Integrity | Findings | Notes |\n|---|---|---|---|---|---|---|\n`;
  for (const p of packages) {
    const integrity = p.artifact && p.artifact.commit ? `git ${p.artifact.commit.slice(0, 12)} (no digest)`
      : p.integrity ? `${p.integrity.algorithm} ${p.integrity.verified ? "verified" : "NOT verified"}` : "—";
    const analysed = p.analysed ? (p.cached ? "yes (cached)" : "yes") : p.reason || "no";
    out += `| ${p.package} | ${p.ecosystem} | ${analysed} | ${BADGE[p.verdict]} | ${integrity} | ${p.findings.length} | ${notesText(p.notes) || "—"} |\n`;
  }
  const flagged = packages.flatMap((p) => p.findings);
  if (flagged.length) {
    out += `\n| Package | File | Threat | Category | Tier |\n|---|---|---|---|---|\n`;
    for (const f of flagged) out += `| ${f.package} | ${f.relativePath || "(name)"} | ${typeof f.threatId === "number" ? "#" + f.threatId : f.threatId} | ${f.category} | ${f.tier} |\n`;
  }
  return out;
}
