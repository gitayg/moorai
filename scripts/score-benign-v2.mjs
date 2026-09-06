#!/usr/bin/env node
// Standalone PRECISION scorer for the large benign corpus (test/redteam/benign-corpus-v2.json).
//
// Recall gets the attention; false positives are what make people disable a security tool. This script
// answers the other half of the question: across 500+ realistic, deliberately diverse benign developer /
// agent prompts — including a large hard-negative slice that is SHAPED like an attack but isn't one —
// how often does the current engine fire when it should stay silent?
//
// It imports the CURRENT detection engine and the EXISTING exported reducers from scripts/redteam-eval.mjs
// (evalSample + score) — it does NOT modify redteam-eval.mjs and does NOT touch any detector, so the number
// is apples-to-apples with the recall benchmarks. On top of that it adds the diagnostics a precision wave
// actually needs: FP rate per bucket, FP rate per hard-negative twin family, and for every FP the
// detector ids + threat ids that fired.
//
//   node scripts/score-benign-v2.mjs                 # text report
//   node scripts/score-benign-v2.mjs --json          # machine-readable
//   node scripts/score-benign-v2.mjs --fail-over 2   # exit 1 if FP rate exceeds 2%  (CI gate)
//   node scripts/score-benign-v2.mjs --file <path>   # score an alternate benign corpus
//   node scripts/score-benign-v2.mjs --strict        # count the `ambiguous` slice too (default: reported separately)
//
// Content-free: emits only sample ids, bucket names, twin names, detector ids and threat ids — never a
// sample's text.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { evalSample, score } from "./redteam-eval.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_CORPUS = "test/redteam/benign-corpus-v2.json";

export function parseArgs(argv) {
  const val = (f) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : undefined);
  return {
    json: argv.includes("--json"),
    strict: argv.includes("--strict"),
    file: val("--file") || DEFAULT_CORPUS,
    failOver: val("--fail-over") !== undefined ? Number(val("--fail-over")) : null
  };
}

// Group rows by a key and compute FP counts. Pure arithmetic — no scanning.
export function groupFp(rows, key) {
  const m = new Map();
  for (const r of rows) {
    const g = r[key];
    if (g == null) continue;
    if (!m.has(g)) m.set(g, { samples: 0, fp: 0 });
    const e = m.get(g);
    e.samples++;
    if (r.detected) e.fp++;
  }
  return [...m.entries()]
    .map(([k, e]) => ({ [key]: k, ...e, fpRate: e.samples ? e.fp / e.samples : 0 }))
    .sort((a, b) => b.fpRate - a.fpRate || String(a[key]).localeCompare(String(b[key])));
}

// The engine's finding carries `detectorId` alongside the threat; evalSample only keeps threat ids, so we
// re-derive the detector attribution for the FP rows only (content-free, and cheap — FPs are rare).
async function attribute(engine, sample) {
  const findings = await engine.scan(sample.text, sample.stage || "prompt");
  return {
    detectors: [...new Set(findings.map((f) => f.detectorId))],
    threats: [...new Set(findings.map((f) => f.threat?.id))],
    threatNames: [...new Set(findings.map((f) => f.threat?.threat))],
    modes: [...new Set(findings.map((f) => f.mode))]
  };
}

export async function runCorpus({ file = DEFAULT_CORPUS, strict = false } = {}) {
  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const data = JSON.parse(readFileSync(join(ROOT, file), "utf8"));
  const samples = (data.benign || []).map((s) => ({ ...s, shouldDetect: false }));

  const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
  const scan = (text, stage) => engine.scan(text, stage);

  const rows = [];
  for (const s of samples) {
    const r = await evalSample(engine, s, scan);
    r.bucket = s.category || "—";
    r.twin = s.hard_negative ? s.twin_of || "unlabelled" : null;
    r.hardNegative = !!s.hard_negative;
    r.ambiguous = !!s.ambiguous;
    rows.push(r);
  }

  const fpRows = rows.filter((r) => r.detected);
  const fps = [];
  for (const r of fpRows) {
    const s = samples.find((x) => x.id === r.id);
    fps.push({ id: r.id, bucket: r.bucket, twin: r.twin, ambiguous: r.ambiguous, ...(await attribute(engine, s)) });
  }

  const counted = strict ? rows : rows.filter((r) => !r.ambiguous);
  const countedFp = counted.filter((r) => r.detected).length;
  const hn = rows.filter((r) => r.hardNegative);
  const plain = rows.filter((r) => !r.hardNegative);

  return {
    file,
    strict,
    totals: {
      samples: rows.length,
      counted: counted.length,
      fp: countedFp,
      fpAll: fpRows.length,
      ambiguousSamples: rows.filter((r) => r.ambiguous).length,
      ambiguousFp: rows.filter((r) => r.ambiguous && r.detected).length
    },
    fpRate: counted.length ? countedFp / counted.length : 0,
    specificity: counted.length ? (counted.length - countedFp) / counted.length : 1,
    hardNegative: { samples: hn.length, fp: hn.filter((r) => r.detected).length },
    plainBenign: { samples: plain.length, fp: plain.filter((r) => r.detected).length },
    byBucket: groupFp(rows, "bucket"),
    byTwin: groupFp(hn, "twin"),
    fps,
    score: score(rows) // whole-corpus reducer, kept for shape-compatibility with the other benchmarks
  };
}

function render(res) {
  const C = { g: "\x1b[32m", r: "\x1b[31m", y: "\x1b[33m", dim: "\x1b[2m", b: "\x1b[1m", off: "\x1b[0m" };
  const pct = (x) => `${(x * 100).toFixed(2)}%`;
  const col = (rate) => (rate === 0 ? C.g : rate < 0.02 ? C.y : C.r);
  const t = res.totals;

  let out = `\n${C.b}MoorAI — benign corpus v2 · FALSE-POSITIVE / precision measurement${C.off}\n`;
  out += `${C.dim}engine: current detectors · ${t.samples} benign samples · ${res.hardNegative.samples} hard negatives · deterministic${C.off}\n\n`;
  out += `  ${C.b}False positives:${C.off}  ${col(res.fpRate)}${t.fp}${C.off} / ${t.counted}   ${C.b}FP rate${C.off} ${col(res.fpRate)}${pct(res.fpRate)}${C.off}   ${C.b}specificity${C.off} ${pct(res.specificity)}\n`;
  out += `  ${C.dim}plain benign: ${res.plainBenign.fp}/${res.plainBenign.samples}   ·   hard negatives: ${res.hardNegative.fp}/${res.hardNegative.samples}${C.off}\n`;
  if (!res.strict && t.ambiguousSamples) {
    out += `  ${C.dim}ambiguous slice (meta-security-discussion) excluded from the headline: ${t.ambiguousFp}/${t.ambiguousSamples} fired · rerun with --strict to include${C.off}\n`;
  }

  out += `\n  ${C.b}FP rate by bucket (worst first)${C.off}\n`;
  for (const b of res.byBucket) {
    const mark = b.fp ? col(b.fpRate) : C.dim;
    out += `    ${mark}${String(b.fp).padStart(2)}/${String(b.samples).padEnd(3)}${C.off} ${String(b.bucket).padEnd(16)} ${C.dim}${pct(b.fpRate)}${C.off}\n`;
  }

  out += `\n  ${C.b}FP rate by hard-negative twin family (worst first)${C.off}\n`;
  for (const b of res.byTwin) {
    const mark = b.fp ? col(b.fpRate) : C.dim;
    out += `    ${mark}${String(b.fp).padStart(2)}/${String(b.samples).padEnd(3)}${C.off} ${String(b.twin).padEnd(32)} ${C.dim}${pct(b.fpRate)}${C.off}\n`;
  }

  if (res.fps.length) {
    out += `\n  ${C.y}${C.b}Every false positive (id · bucket/twin · detectors · threats)${C.off}\n`;
    for (const f of res.fps) {
      out += `    ${C.r}✗${C.off} ${f.id.padEnd(18)} ${String(f.twin || f.bucket).padEnd(30)} ${C.b}${f.detectors.join(",")}${C.off} ${C.dim}→ threat ${f.threats.join(",")} (${f.threatNames.join(" | ")})${f.ambiguous ? " [ambiguous]" : ""}${C.off}\n`;
    }
  } else {
    out += `\n  ${C.g}No false positives.${C.off}\n`;
  }
  return out + "\n";
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const res = await runCorpus(args);
  if (args.json) process.stdout.write(JSON.stringify(res, null, 2) + "\n");
  else process.stdout.write(render(res));
  if (args.failOver != null && res.fpRate * 100 > args.failOver) process.exitCode = 1;
}

const invokedDirectly = (() => {
  try { return fileURLToPath(import.meta.url) === process.argv[1]; } catch { return false; }
})();
if (invokedDirectly) main();
