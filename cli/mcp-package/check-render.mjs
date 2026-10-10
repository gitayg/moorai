// Plain-text rendering of a `moorai-mcp-check` report (the --json shape is the report object itself).

const MARK = { pass: "PASS", warn: "WARN", fail: "FAIL", "not-checked": "N/C " };

export function renderCheck(r) {
  const p = r.package;
  const head = p.kind === "remote" ? `remote ${p.url}` : `${p.kind}:${p.name}${p.resolved ? `@${p.resolved}` : p.requested ? `@${p.requested}` : ""}`;
  const lines = [`moorai-mcp-check  ${head}`, ""];
  r.checks.forEach((c, i) => lines.push(`${String(i + 1).padStart(2)}. ${MARK[c.status]}  ${c.title}: ${c.reason}`));
  const s = r.summary;
  lines.push("", `${s.pass} pass, ${s.warn} warn, ${s.fail} fail, ${s["not-checked"]} not checked`);
  lines.push(`Reputation: ${r.reputation.score}/100 ${r.reputation.band}${r.reputation.reasons.length ? ` (${r.reputation.reasons.join(", ")})` : ""}; ${r.reputation.basis}`);
  lines.push(`SkillTriage: ${r.skilltriage.reason}`);
  return lines.join("\n") + "\n";
}
