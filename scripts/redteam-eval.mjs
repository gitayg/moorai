#!/usr/bin/env node
// Red-team DETECTION-COVERAGE benchmark, keyed to HackAgent's attack taxonomy
// (github.com/vistalabs-org/hackagent). Answers the question the pass/fail harness (scripts/redteam.mjs)
// does not: across the families real red-team tooling actually uses — AutoDAN / PAIR / TAP, FlipAttack,
// BoN, CipherChat, PAP, h4rm3l, AdvPrefix, DAN — which does the CURRENT on-device engine catch, and
// which is it blind to?
//
// Scoring is DETERMINISTIC and LLM-FREE by design: every sample in test/redteam/corpus.json's
// `hackagent` array carries a GROUND-TRUTH label (`shouldDetect`), so coverage / precision / recall are
// computed by comparing the engine's verdict to that label — no model, no judge, reproducible on any box.
// An OPTIONAL Generator+Judge escalation (`--semantic`) routes each sample through the existing, policy-
// gated on-device model layer (src/semantic.js) — it changes nothing unless a local model is present and
// a policy opts in; the default run never imports it.
//
//   node scripts/redteam-eval.mjs                 # coverage report (default, deterministic)
//   node scripts/redteam-eval.mjs --format json   # machine-readable
//   node scripts/redteam-eval.mjs --verbose       # per-sample caught/missed
//   node scripts/redteam-eval.mjs --fail-under 60 # exit 1 if overall coverage < 60% (CI gate)
//   node scripts/redteam-eval.mjs --semantic      # OPTIONAL gated LLM escalation (needs a local model)
//   node scripts/redteam-eval.mjs --help
//
// Content-free: only rule ids / threat ids / booleans are emitted, never a sample's text.
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HELP = `moorai red-team eval — HackAgent detection-coverage benchmark (deterministic, LLM-free).

Usage:
  redteam-eval [--format text|json] [--verbose] [--fail-under <pct>] [--semantic]

Scores the on-device engine against labelled adversarial families (AutoDAN/PAIR/TAP, FlipAttack, BoN,
CipherChat, PAP, h4rm3l, AdvPrefix, DAN) and reports coverage / precision / recall, a per-family table,
and the families the engine is currently BLIND to. Exit 0 by default; with --fail-under, exit 1 when
overall coverage is below the given percent.
`;

export function parseArgs(argv) {
  const has = (f) => argv.includes(f);
  const val = (f) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : undefined);
  return {
    help: has("--help") || has("-h"),
    format: val("--format") || "text",
    verbose: has("--verbose"),
    semantic: has("--semantic"),
    failUnder: val("--fail-under") !== undefined ? Number(val("--fail-under")) : null
  };
}

// Run one labelled sample and reduce it to a content-free verdict row. `scan` is the (optionally
// semantic) scanner: (text, stage) -> Promise<findings[]> | findings[]. Exported + injectable so the
// test can drive it with a stub engine.
export async function evalSample(engine, s, scan) {
  const stage = s.stage || "prompt";
  const findings = s.turns ? await engine.scanSession(s.turns) : await scan(s.text, stage);
  const ids = findings.map((f) => f.threat.id);
  const detected = findings.length > 0;
  const correctThreat = s.expectThreat != null ? ids.includes(s.expectThreat) : detected;
  const should = s.shouldDetect !== false; // default: treat as attack unless explicitly benign
  const outcome = should
    ? (detected ? "TP" : "FN")
    : (detected ? "FP" : "TN");
  return {
    id: s.id,
    family: s.family || "—",
    category: s.category || "—",
    shouldDetect: should,
    detected,
    correctThreat,
    firedThreats: ids,
    outcome
  };
}

// Aggregate rows into overall + per-family scores. Pure arithmetic over the verdict rows.
export function score(rows) {
  const c = (o) => rows.filter((r) => r.outcome === o).length;
  const tp = c("TP"), fn = c("FN"), fp = c("FP"), tn = c("TN");
  const attacks = tp + fn;
  const recall = attacks ? tp / attacks : 0;                 // detection coverage
  const precision = tp + fp ? tp / (tp + fp) : 1;            // no attack-detection FP → 1
  const rightReason = rows.filter((r) => r.outcome === "TP" && r.correctThreat).length;

  const fam = new Map();
  for (const r of rows) {
    if (!fam.has(r.family)) fam.set(r.family, { attacks: 0, caught: 0, benign: 0, fp: 0, rightReason: 0 });
    const e = fam.get(r.family);
    if (r.shouldDetect) { e.attacks++; if (r.detected) { e.caught++; if (r.correctThreat) e.rightReason++; } }
    else { e.benign++; if (r.detected) e.fp++; }
  }
  const families = [...fam.entries()]
    .map(([family, e]) => ({ family, ...e, recall: e.attacks ? e.caught / e.attacks : null }))
    .sort((a, b) => (a.recall ?? 1) - (b.recall ?? 1) || a.family.localeCompare(b.family));

  const withAttacks = families.filter((f) => f.attacks > 0);
  return {
    totals: { samples: rows.length, attacks, benign: fp + tn, tp, fn, fp, tn },
    coverage: recall, precision, rightReason,
    families,
    blind: withAttacks.filter((f) => f.recall === 0).map((f) => f.family),
    partial: withAttacks.filter((f) => f.recall > 0 && f.recall < 1).map((f) => f.family),
    covered: withAttacks.filter((f) => f.recall === 1).map((f) => f.family)
  };
}

const C = { g: "\x1b[32m", r: "\x1b[31m", y: "\x1b[33m", dim: "\x1b[2m", b: "\x1b[1m", off: "\x1b[0m" };
const pct = (x) => `${(x * 100).toFixed(0)}%`;

export function toText(sc, rows, verbose) {
  let out = `\n${C.b}MoorAI red-team eval — HackAgent detection coverage (BASELINE, current detectors)${C.off}\n`;
  out += `${C.dim}deterministic / LLM-free · ${sc.totals.samples} samples · ${sc.totals.attacks} attacks · ${sc.totals.benign} benign controls${C.off}\n\n`;
  out += `  coverage (recall):  ${sc.coverage >= 0.7 ? C.g : C.y}${pct(sc.coverage)}${C.off}  ${C.dim}(${sc.totals.tp}/${sc.totals.attacks} attacks flagged; ${sc.rightReason} on the expected threat)${C.off}\n`;
  out += `  precision:          ${sc.totals.fp ? C.y : C.g}${pct(sc.precision)}${C.off}  ${C.dim}(${sc.totals.fp} false-positive on benign controls)${C.off}\n\n`;
  out += `  ${C.dim}Per family (caught / attacks):${C.off}\n`;
  for (const f of sc.families) {
    if (!f.attacks) continue;
    const col = f.recall === 1 ? C.g : f.recall === 0 ? C.r : C.y;
    out += `    ${col}${String(f.caught).padStart(2)}/${f.attacks}${C.off}  ${f.family.padEnd(12)} ${C.dim}${pct(f.recall)}${f.fp ? `  ${C.r}${f.fp} FP${C.off}` : ""}${C.off}\n`;
  }
  if (sc.blind.length) out += `\n  ${C.r}${C.b}BLIND families (0% — the gap to close):${C.off} ${sc.blind.join(", ")}\n`;
  if (sc.partial.length) out += `  ${C.y}Partial coverage:${C.off} ${sc.partial.join(", ")}\n`;
  if (sc.covered.length) out += `  ${C.g}Fully covered:${C.off} ${sc.covered.join(", ")}\n`;
  if (verbose) {
    out += `\n  ${C.dim}Per sample:${C.off}\n`;
    for (const r of rows) {
      const ok = r.outcome === "TP" || r.outcome === "TN";
      const mark = ok ? `${C.g}✓${C.off}` : `${C.r}✗${C.off}`;
      out += `    ${mark} ${r.outcome.padEnd(2)} ${r.family.padEnd(11)} ${r.id.padEnd(26)} ${C.dim}[${r.firedThreats.join(",") || "—"}]${C.off}\n`;
    }
  }
  out += `\n${C.dim}Baseline vs current detectors — a parallel hardening effort is improving them; the orchestrator re-runs this after.${C.off}\n`;
  return out;
}

// OPTIONAL, gated: build a scanner backed by the on-device semantic escalation. No-ops (identical to the
// deterministic scan) unless a policy enables it AND a local model answers — see src/semantic.js.
async function buildScanner(engine, semantic) {
  if (!semantic) return (text, stage) => engine.scan(text, stage);
  const { escalate } = await import("../src/semantic.js");
  const policy = { semanticEscalation: "on" };
  return (text, stage) => engine.scanSemantic(text, stage, policy, escalate);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(HELP); process.exit(0); }

  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const corpus = JSON.parse(readFileSync(join(ROOT, "test/redteam/corpus.json"), "utf8"));
  const samples = corpus.hackagent || [];
  if (!samples.length) { process.stderr.write("no `hackagent` samples in corpus.json\n"); process.exit(2); }

  const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
  const scan = await buildScanner(engine, args.semantic);

  const rows = [];
  for (const s of samples) rows.push(await evalSample(engine, s, scan));
  const sc = score(rows);

  if (args.format === "json") {
    process.stdout.write(JSON.stringify({ semantic: !!args.semantic, ...sc, rows }, null, 2) + "\n");
  } else {
    process.stdout.write(toText(sc, rows, args.verbose));
  }

  if (args.failUnder != null && sc.coverage * 100 < args.failUnder) {
    process.stderr.write(`coverage ${pct(sc.coverage)} below --fail-under ${args.failUnder}%\n`);
    process.exit(1);
  }
  process.exit(0);
}

const invokedDirectly = (() => {
  try { return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]); }
  catch { return false; }
})();
if (invokedDirectly) main();
