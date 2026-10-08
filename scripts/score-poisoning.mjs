#!/usr/bin/env node
// Recall / false-positive scorer for threats #21 (RAG poisoning) and #22 (memory poisoning) over
// test/redteam/poisoning-corpus.json, scoring each sample the way production sees it:
//   memory-write, Write/Edit — DetectionEngine.scan(content, "output", { targetPath }), the hook's write branch
//   memory-write, Bash       — shellMemoryWrites(command), then the same scan per memory target
//   index                    — DetectionEngine.scanForIndex(text), the embedding-pipeline choke-point
// A sample counts as caught only when its OWN threat (#21 or #22) is raised; `anyFinding` is reported
// beside it so a sample caught by #40 alone is visible rather than counted.
//
//   node scripts/score-poisoning.mjs                       # tune half (the default; tuning waves read only this)
//   node scripts/score-poisoning.mjs --split test --i-am-reporting-the-headline   # locked half, scored once
//   node scripts/score-poisoning.mjs --json
//
// Content-free: prints sample ids, families and detector ids, never a sample's text.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { DetectionEngine } from "../src/engine.js";
import { shellMemoryWrites } from "../data/poisoning-tells.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

export function scanSample(engine, s) {
  if (s.kind === "index") return engine.scanForIndex(s.text);
  const writes = s.tool === "Bash" ? shellMemoryWrites(s.command) : [{ path: s.path, text: s.text }];
  return writes.flatMap((w) => engine.scan(w.text, "output", { targetPath: w.path }));
}

export function scoreCorpus({ split = "tune", file = "test/redteam/poisoning-corpus.json" } = {}) {
  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const engine = new DetectionEngine(threats, DETECTORS);
  const data = JSON.parse(readFileSync(join(ROOT, file), "utf8"));
  const rows = data.samples.filter((s) => split === "all" || s.split === split).map((s) => {
    const f = scanSample(engine, s);
    const own = f.filter((x) => x.threat.id === s.target);
    return { id: s.id, target: s.target, family: s.family, split: s.split, shouldDetect: s.shouldDetect, detected: own.length > 0, anyFinding: f.length > 0, detectors: [...new Set(f.map((x) => x.detectorId))] };
  });
  const sum = (target) => {
    const r = rows.filter((x) => x.target === target);
    const atk = r.filter((x) => x.shouldDetect), ben = r.filter((x) => !x.shouldDetect);
    return { attacks: atk.length, caught: atk.filter((x) => x.detected).length, benign: ben.length, fp: ben.filter((x) => x.detected).length, fpAnyThreat: ben.filter((x) => x.anyFinding).length };
  };
  return { split, t22: sum(22), t21: sum(21), rows };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const argv = process.argv.slice(2);
  const split = argv.includes("--split") ? argv[argv.indexOf("--split") + 1] : "tune";
  if (split !== "tune" && !argv.includes("--i-am-reporting-the-headline")) {
    console.error("the locked `test` half is scored once, as a headline, with --i-am-reporting-the-headline");
    process.exit(2);
  }
  const r = scoreCorpus({ split });
  if (argv.includes("--json")) { console.log(JSON.stringify(r, null, 2)); process.exit(0); }
  const pct = (a, b) => (b ? `${((100 * a) / b).toFixed(1)}%` : "n/a");
  console.log(`poisoning corpus · split=${split}`);
  for (const [k, s] of [["#22 memory poisoning", r.t22], ["#21 RAG poisoning", r.t21]]) {
    console.log(`  ${k}: recall ${s.caught}/${s.attacks} (${pct(s.caught, s.attacks)})  FP ${s.fp}/${s.benign} (${pct(s.fp, s.benign)})  benign with ANY finding ${s.fpAnyThreat}/${s.benign}`);
  }
  for (const x of r.rows) if (x.shouldDetect !== x.detected) console.log(`  ${x.shouldDetect ? "MISS" : "FP  "} ${x.id.padEnd(18)} ${x.family.padEnd(26)} ${x.detectors.join(",") || "-"}`);
}
