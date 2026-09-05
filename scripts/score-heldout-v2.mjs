#!/usr/bin/env node
// Standalone scorer for the FRESH held-out set (test/redteam/heldout-v2.json) — Wave B.
//
// It imports the CURRENT detection engine and the EXISTING, exported scoring reducers from
// scripts/redteam-eval.mjs (evalSample + score) — it does NOT modify redteam-eval.mjs, does NOT touch any
// detector, and runs the exact same verdict logic the real eval uses, so the number is apples-to-apples.
// On top of that it adds a per-AXIS recall breakdown (which transformation breaks detection most) — the
// roadmap signal for the next tuning wave.
//
//   node scripts/score-heldout-v2.mjs            # text report
//   node scripts/score-heldout-v2.mjs --json     # machine-readable
//   node scripts/score-heldout-v2.mjs --misses   # also list every missed attack id
//
// Content-free: emits only ids / axes / threat-ids / booleans, never a sample's text.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { evalSample, score } from "./redteam-eval.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function groupRecall(rows, key) {
  const m = new Map();
  for (const r of rows) {
    if (!r.shouldDetect) continue;
    const g = r[key] || "—";
    if (!m.has(g)) m.set(g, { attacks: 0, caught: 0 });
    const e = m.get(g); e.attacks++; if (r.detected) e.caught++;
  }
  return [...m.entries()]
    .map(([k, e]) => ({ [key]: k, ...e, recall: e.caught / e.attacks }))
    .sort((a, b) => a.recall - b.recall || String(a[key]).localeCompare(String(b[key])));
}

async function run() {
  const args = process.argv.slice(2);
  const asJson = args.includes("--json");
  const showMisses = args.includes("--misses");

  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const data = JSON.parse(readFileSync(join(ROOT, "test/redteam/heldout-v2.json"), "utf8"));
  const attacks = (data.attacks || []).map((s) => ({ ...s, shouldDetect: true }));
  const benign = (data.benign || []).map((s) => ({ ...s, shouldDetect: false }));
  const samples = [...attacks, ...benign];

  const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
  const scan = (text, stage) => engine.scan(text, stage);

  const rows = [];
  for (const s of samples) {
    const r = await evalSample(engine, s, scan);
    r.axis = s.axis;
    rows.push(r);
  }

  const sc = score(rows);
  const byAxis = groupRecall(rows, "axis");
  const attackRows = rows.filter((r) => r.shouldDetect);
  const overallRecall = attackRows.filter((r) => r.detected).length / attackRows.length;
  const misses = attackRows.filter((r) => !r.detected).map((r) => ({ id: r.id, family: r.family, axis: r.axis }));
  const fps = rows.filter((r) => !r.shouldDetect && r.detected).map((r) => ({ id: r.id, axis: r.axis, firedThreats: r.firedThreats }));

  if (asJson) {
    process.stdout.write(JSON.stringify({
      totals: sc.totals,
      overallRecall,
      precision: sc.precision,
      families: sc.families.filter((f) => f.attacks > 0).map((f) => ({ family: f.family, attacks: f.attacks, caught: f.caught, recall: f.recall })),
      byAxis,
      misses, fps
    }, null, 2) + "\n");
    return;
  }

  const C = { g: "\x1b[32m", r: "\x1b[31m", y: "\x1b[33m", dim: "\x1b[2m", b: "\x1b[1m", off: "\x1b[0m" };
  const pct = (x) => `${(x * 100).toFixed(1)}%`;
  const col = (rec) => (rec === 1 ? C.g : rec === 0 ? C.r : C.y);
  let out = `\n${C.b}MoorAI — FRESH held-out (v2) generalization measurement${C.off}\n`;
  out += `${C.dim}engine: current detectors · ${attackRows.length} attacks · ${benign.length} benign · deterministic${C.off}\n\n`;
  out += `  ${C.b}Overall held-out recall:${C.off} ${col(overallRecall)}${pct(overallRecall)}${C.off}  ${C.dim}(${attackRows.filter((r) => r.detected).length}/${attackRows.length} attacks caught)${C.off}\n`;
  out += `  ${C.b}Precision on new benign:${C.off}  ${sc.totals.fp ? C.y : C.g}${pct(sc.precision)}${C.off}  ${C.dim}(${fps.length} FP / ${benign.length} benign · FP rate ${pct(fps.length / benign.length)})${C.off}\n\n`;

  out += `  ${C.b}Recall by family${C.off}\n`;
  for (const f of sc.families) {
    if (!f.attacks) continue;
    out += `    ${col(f.recall)}${String(f.caught).padStart(2)}/${String(f.attacks).padEnd(2)}${C.off}  ${f.family.padEnd(12)} ${C.dim}${pct(f.recall)}${C.off}\n`;
  }
  out += `\n  ${C.b}Recall by transformation axis (worst first ← next-wave targets)${C.off}\n`;
  for (const a of byAxis) {
    out += `    ${col(a.recall)}${String(a.caught).padStart(2)}/${String(a.attacks).padEnd(2)}${C.off}  ${String(a.axis).padEnd(18)} ${C.dim}${pct(a.recall)}${C.off}\n`;
  }
  if (fps.length) {
    out += `\n  ${C.y}False positives on benign:${C.off} ${fps.map((f) => `${f.id}[${f.firedThreats.join(",")}]`).join(", ")}\n`;
  }
  if (showMisses && misses.length) {
    out += `\n  ${C.dim}Missed attacks:${C.off}\n`;
    for (const m of misses) out += `    ${C.r}✗${C.off} ${m.family.padEnd(12)} ${String(m.axis).padEnd(18)} ${m.id}\n`;
  }
  process.stdout.write(out + "\n");
}

const invokedDirectly = (() => {
  try { return fileURLToPath(import.meta.url) === process.argv[1]; } catch { return false; }
})();
if (invokedDirectly) run();

export { run };
