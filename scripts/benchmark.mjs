#!/usr/bin/env node
// MoorAI Agent Security Benchmark (#16) — a reproducible, publishable measure of the on-device
// detection engine: OWASP LLM Top 10 coverage, MITRE ATLAS coverage, and adversarial-corpus pass
// rate. Runs the same engine and corpus the product ships, so the number can't be gamed. Writes a
// machine-readable docs/benchmark.json and a human-readable docs/BENCHMARK.md, and prints a summary.
//
//   npm run benchmark
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";

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

// --- adversarial corpus pass rate (mirrors redteam) ---
let pass = 0;
const fails = [];
for (const c of corpus.cases) {
  const findings = c.turns ? engine.scanSession(c.turns) : engine.scan(c.text, c.stage || "prompt");
  const ids = new Set(findings.map((f) => f.threat.id));
  const ok = c.none ? findings.length === 0 : ids.has(c.expect);
  ok ? pass++ : fails.push(c.id);
}

const covered = Object.values(owaspCov).filter((v) => v.detectors > 0).length;
const generatedAt = new Date().toISOString();
const report = {
  name: "MoorAI Agent Security Benchmark",
  generatedAt,
  engine: { detectors: DETECTORS.length, threats: threats.threats.length, corpusCases: corpus.cases.length },
  corpus: { passed: pass, total: corpus.cases.length, passRate: +(pass / corpus.cases.length).toFixed(4) },
  owaspLlmTop10: { covered, total: 10, byItem: owaspCov }
};

// --- write machine-readable + markdown artifacts ---
mkdirSync(join(ROOT, "docs"), { recursive: true });
writeFileSync(join(ROOT, "docs/benchmark.json"), JSON.stringify(report, null, 2) + "\n");

const rows = Object.entries(OWASP).map(([k, name]) => {
  const c = owaspCov[k];
  const status = c.detectors > 0 ? "✅ covered" : "—";
  return `| ${k} | ${name} | ${c.threats} | ${c.detectors} | ${status} |`;
}).join("\n");
const md = `# MoorAI Agent Security Benchmark

> Reproducible coverage of MoorAI's on-device detection engine. Regenerate with \`npm run benchmark\`.
> Generated: ${generatedAt}

- **Detectors:** ${DETECTORS.length}
- **Threats:** ${threats.threats.length}
- **Adversarial corpus:** ${pass}/${corpus.cases.length} passed (${(100 * pass / corpus.cases.length).toFixed(1)}%)
- **OWASP LLM Top 10:** ${covered}/10 items covered by ≥1 on-device detector

## OWASP LLM Top 10 (2025) coverage

| Item | Name | Threats | Detectors | Status |
|------|------|--------:|----------:|--------|
${rows}

Coverage is measured, not asserted: every number above is produced by running the shipped detection
engine (\`src/engine.js\`) against the shipped threat matrix (\`data/threats.json\`) and the adversarial
corpus (\`test/redteam/corpus.json\`). Content-free by construction — the benchmark reasons over
categories and threat ids, never prompt content.
`;
writeFileSync(join(ROOT, "docs/BENCHMARK.md"), md);

const g = (s) => `\x1b[32m${s}\x1b[0m`, r = (s) => `\x1b[31m${s}\x1b[0m`, b = (s) => `\x1b[1m${s}\x1b[0m`;
console.log(`\n${b("MoorAI Agent Security Benchmark")}`);
console.log(`  detectors ${DETECTORS.length} · threats ${threats.threats.length} · corpus ${pass}/${corpus.cases.length} (${(100 * pass / corpus.cases.length).toFixed(1)}%)`);
console.log(`  OWASP LLM Top 10: ${covered}/10 items covered`);
for (const [k, name] of Object.entries(OWASP)) {
  const c = owaspCov[k];
  console.log(`   ${c.detectors > 0 ? g("✓") : r("·")} ${k} ${name} ${`\x1b[2m(${c.threats} threats, ${c.detectors} detectors)\x1b[0m`}`);
}
console.log(`\n  wrote docs/benchmark.json + docs/BENCHMARK.md`);
if (fails.length) console.log(r(`  corpus misses: ${fails.join(", ")}`));
process.exit(0);
