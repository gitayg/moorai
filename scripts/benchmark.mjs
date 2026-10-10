#!/usr/bin/env node
// MoorAI Agent Security Benchmark (#16) — a reproducible, publishable measure of the on-device
// detection engine: OWASP LLM Top 10 coverage, MITRE ATLAS coverage, and adversarial-corpus pass
// rate. Runs the same engine and corpus the product ships, so the number can't be gamed. Writes a
// machine-readable docs/benchmark.json and a human-readable docs/BENCHMARK.md, and prints a summary.
//
//   npm run benchmark                 (measures latency too, about a minute)
//   npm run benchmark -- --no-latency (coverage only; what `npm run test:generated` runs)
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { classifyFailures, reportAcceptedFailures } from "./accepted-failures.mjs";
import { OWASP_AGENTIC, OWASP_MCP, owaspAgenticIds, owaspMcpIds, owaspAgenticPartialNote, owaspMcpPartialNote, frameworkEdition } from "../data/owasp-frameworks.js";
import { measureLatency, LATENCY_ROWS } from "./latency-bench.mjs";
import { renderLatencyMarkdown } from "./latency.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const corpus = JSON.parse(readFileSync(join(ROOT, "test/redteam/corpus.json"), "utf8"));
const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);

const OWASP = {
  LLM01: "Prompt Injection", LLM02: "Sensitive Information Disclosure", LLM03: "Supply Chain",
  LLM04: "Data & Model Poisoning", LLM05: "Improper Output Handling", LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage", LLM08: "Vector & Embedding Weaknesses", LLM09: "Misinformation",
  LLM10: "Unbounded Consumption"
};

// --- threat + detector coverage per OWASP LLM id ---
const detectorThreat = new Map(DETECTORS.map((d) => [d.detectorId, d.threatId]));
const detCountByThreat = DETECTORS.reduce((m, d) => (m.set(d.threatId, (m.get(d.threatId) || 0) + 1), m), new Map());
const owaspCov = Object.fromEntries(Object.keys(OWASP).map((k) => [k, { threats: 0, detectors: 0 }]));
for (const t of threats.threats) {
  const k = t.owasp;
  if (!owaspCov[k]) continue;
  owaspCov[k].threats += 1;
  owaspCov[k].detectors += detCountByThreat.get(t.id) || 0;
}

// --- OWASP Agentic (ASI) and MCP Top 10: same detector count, plus bounded credits ---
// An item is covered when a rule that credits it in full has >=1 on-device detector, partial when only
// bounded credits (owaspAgenticPartial / owaspMcpPartial) have one, and uncovered otherwise. A rule whose
// mechanism lives outside data/detectors.js (the hook's drift, delegation or session checks) is listed
// under Threats but adds no detector, so it cannot make an item read as covered here.
function frameworkCoverage(fw, idsOf, noteOf) {
  const byItem = Object.fromEntries(Object.keys(fw.items).map((k) => [k, { threats: 0, partialThreats: 0, detectors: 0, status: "uncovered" }]));
  for (const t of threats.threats) {
    const dets = detCountByThreat.get(t.id) || 0;
    for (const id of idsOf(t)) {
      const c = byItem[id];
      if (!c) continue;
      const partial = Boolean(noteOf(t, id));
      c.threats += 1;
      if (partial) c.partialThreats += 1;
      c.detectors += dets;
      if (dets > 0) c.status = !partial ? "covered" : c.status === "covered" ? "covered" : "partial";
    }
  }
  const count = (s) => Object.values(byItem).filter((v) => v.status === s).length;
  return { edition: frameworkEdition(fw), source: fw.source, covered: count("covered"), partial: count("partial"), uncovered: count("uncovered"), total: Object.keys(fw.items).length, byItem };
}
const agenticCov = frameworkCoverage(OWASP_AGENTIC, owaspAgenticIds, owaspAgenticPartialNote);
const mcpCov = frameworkCoverage(OWASP_MCP, owaspMcpIds, owaspMcpPartialNote);

// --- adversarial corpus pass rate (mirrors redteam) ---
let pass = 0;
const fails = [];
for (const c of corpus.cases) {
  const findings = c.turns ? engine.scanSession(c.turns) : engine.scan(c.text, c.stage || "prompt");
  const ids = new Set(findings.map((f) => f.threat.id));
  const ok = c.none ? findings.length === 0 : ids.has(c.expect);
  ok ? pass++ : fails.push(c.id);
}

// --- latency: raw per-call samples, nearest-rank p50/p95/p99 (scripts/latency.mjs) ---
const latency = process.argv.includes("--no-latency") ? { measured: false } : await measureLatency();

const covered = Object.values(owaspCov).filter((v) => v.detectors > 0).length;
const generatedAt = new Date().toISOString();
const report = {
  name: "MoorAI Agent Security Benchmark",
  generatedAt,
  engine: { detectors: DETECTORS.length, threats: threats.threats.length, corpusCases: corpus.cases.length },
  corpus: { passed: pass, total: corpus.cases.length, passRate: +(pass / corpus.cases.length).toFixed(4) },
  owaspLlmTop10: { covered, total: 10, byItem: owaspCov },
  owaspAgenticTop10: agenticCov,
  owaspMcpTop10: mcpCov,
  latency: "__LATENCY__"
};

// --- write machine-readable + markdown artifacts ---
mkdirSync(join(ROOT, "docs"), { recursive: true });
// The latency block is written on ONE line so `npm run test:generated` can ignore it as a unit.
writeFileSync(join(ROOT, "docs/benchmark.json"), JSON.stringify(report, null, 2).replace('"latency": "__LATENCY__"', () => `"latency": ${JSON.stringify(latency)}`) + "\n");

const rows = Object.entries(OWASP).map(([k, name]) => {
  const c = owaspCov[k];
  const status = c.detectors > 0 ? "✅ covered" : "—";
  return `| ${k} | ${name} | ${c.threats} | ${c.detectors} | ${status} |`;
}).join("\n");
const STATUS = { covered: "✅ covered", partial: "◐ partial", uncovered: "—" };
const fwRows = (fw, cov) => Object.entries(fw.items).map(([k, name]) => {
  const c = cov.byItem[k];
  return `| ${k} | ${name} | ${c.threats} | ${c.partialThreats} | ${c.detectors} | ${STATUS[c.status]} |`;
}).join("\n");
const fwLine = (cov) => `${cov.covered}/${cov.total} covered, ${cov.partial} partial, ${cov.uncovered} uncovered`;
const md = `# MoorAI Agent Security Benchmark

> Reproducible coverage of MoorAI's on-device detection engine. Regenerate with \`npm run benchmark\`.
> Generated: ${generatedAt}

- **Detectors:** ${DETECTORS.length}
- **Threats:** ${threats.threats.length}
- **Adversarial corpus:** ${pass}/${corpus.cases.length} passed (${(100 * pass / corpus.cases.length).toFixed(1)}%)
- **OWASP LLM Top 10:** ${covered}/10 items covered by ≥1 on-device detector
- **OWASP Top 10 for Agentic Applications:** ${fwLine(agenticCov)}
- **OWASP MCP Top 10:** ${fwLine(mcpCov)}

## OWASP LLM Top 10 (2025) coverage

| Item | Name | Threats | Detectors | Status |
|------|------|--------:|----------:|--------|
${rows}

## OWASP Top 10 for Agentic Applications (${frameworkEdition(OWASP_AGENTIC)}) coverage

| Item | Name | Threats | Partial | Detectors | Status |
|------|------|--------:|--------:|----------:|--------|
${fwRows(OWASP_AGENTIC, agenticCov)}

## OWASP MCP Top 10 (${frameworkEdition(OWASP_MCP)}) coverage

| Item | Name | Threats | Partial | Detectors | Status |
|------|------|--------:|--------:|----------:|--------|
${fwRows(OWASP_MCP, mcpCov)}

For the two agentic lists, **Threats** counts the rules that credit the item (\`owaspAgentic\` / \`owaspMcp\`
in \`data/threats.json\`) and **Partial** how many of those credits are bounded. An item is *covered* when a
rule crediting it in full has an on-device detector, *partial* when only bounded credits do, and *—*
otherwise. Rules whose mechanism is not a detector in \`data/detectors.js\` (drift, delegation, session
risk, the MCP allow-list) are counted under Threats but add no detectors. Sources:
[${OWASP_AGENTIC.name}](${OWASP_AGENTIC.source}), [${OWASP_MCP.name}](${OWASP_MCP.source}).

Coverage is measured, not asserted: every number above is produced by running the shipped detection
engine (\`src/engine.js\`) against the shipped threat matrix (\`data/threats.json\`) and the adversarial
corpus (\`test/redteam/corpus.json\`). Content-free by construction — the benchmark reasons over
categories and threat ids, never prompt content.

${renderLatencyMarkdown(latency, LATENCY_ROWS)}`;
writeFileSync(join(ROOT, "docs/BENCHMARK.md"), md);

const g = (s) => `\x1b[32m${s}\x1b[0m`, r = (s) => `\x1b[31m${s}\x1b[0m`, b = (s) => `\x1b[1m${s}\x1b[0m`;
console.log(`\n${b("MoorAI Agent Security Benchmark")}`);
console.log(`  detectors ${DETECTORS.length} · threats ${threats.threats.length} · corpus ${pass}/${corpus.cases.length} (${(100 * pass / corpus.cases.length).toFixed(1)}%)`);
console.log(`  OWASP LLM Top 10: ${covered}/10 items covered`);
for (const [k, name] of Object.entries(OWASP)) {
  const c = owaspCov[k];
  console.log(`   ${c.detectors > 0 ? g("✓") : r("·")} ${k} ${name} ${`\x1b[2m(${c.threats} threats, ${c.detectors} detectors)\x1b[0m`}`);
}
for (const [label, fw, cov] of [["OWASP Agentic Top 10", OWASP_AGENTIC, agenticCov], ["OWASP MCP Top 10", OWASP_MCP, mcpCov]]) {
  console.log(`  ${label}: ${fwLine(cov)}`);
  for (const [k, name] of Object.entries(fw.items)) {
    const c = cov.byItem[k];
    const mark = c.status === "covered" ? g("✓") : c.status === "partial" ? "\x1b[33m◐\x1b[0m" : r("·");
    console.log(`   ${mark} ${k} ${name} ${`\x1b[2m(${c.threats} threats, ${c.partialThreats} partial, ${c.detectors} detectors)\x1b[0m`}`);
  }
}
if (latency.measured) {
  console.log(`  Latency (nearest-rank, ms) on ${latency.machine.cpu}, Node ${latency.machine.node}:`);
  console.log(`   ${"path".padEnd(44)} ${"n".padStart(5)} ${"p50".padStart(8)} ${"p95".padStart(8)} ${"p99".padStart(8)} ${"max".padStart(8)}`);
  const f = (x) => (x === null ? "—" : x.toFixed(2)).padStart(8);
  for (const r of latency.rows) console.log(`   ${r.label.replace(/`/g, "").padEnd(44)} ${String(r.n).padStart(5)} ${f(r.p50Ms)} ${f(r.p95Ms)} ${f(r.p99Ms)} ${f(r.maxMs)}`);
} else console.log("  Latency: not measured (--no-latency)");
console.log(`\n  wrote docs/benchmark.json + docs/BENCHMARK.md`);

// THE DEFECT THIS REPLACES: `if (fails.length) console.log(r("corpus misses: ...")); process.exit(0);`
// — the miss list was computed, printed in red, and then thrown away. A benchmark that publishes
// docs/BENCHMARK.md while reporting red and returning success cannot fail CI, cannot fail a
// pre-commit hook, and cannot fail a human skimming output. It scores the SAME corpus as
// `npm run redteam`, so it shares that harness's accepted-failure baseline rather than keeping a
// second opinion about which misses are known.
const cls = classifyFailures(fails, corpus.cases.map((c) => c.id));
const unexpected = new Set(cls.unexpected);
if (unexpected.size) console.log(r(`  corpus misses: ${fails.filter((id) => unexpected.has(id)).join(", ")}`));
const clean = reportAcceptedFailures(cls);
process.exit(clean ? 0 : 1);
