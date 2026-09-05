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

// Run one labelled sample and reduce it to a content-free verdict row. `scan` is the deterministic
// scanner: (text, stage) -> Promise<findings[]> | findings[]. Exported + injectable so the test can drive
// it with a stub engine.
//
// `opts.escalate(engine, text, stage) -> Promise<finding|null>` is the OPTIONAL miss-recovery hook (only
// --semantic wires it). It runs ONLY when the deterministic layer returned nothing, so it can lift a
// MISSED sample to a caught one but can never suppress or alter a deterministic finding — coverage with
// escalation is therefore monotonically ≥ the deterministic baseline. Turn-based samples are flattened
// to one newline-joined text so a multi-turn crescendo is judged as a whole (see src/semantic.js).
export async function evalSample(engine, s, scan, opts = {}) {
  const stage = s.stage || "prompt";
  let findings = s.turns ? await engine.scanSession(s.turns) : await scan(s.text, stage);
  let recovered = false;
  if (opts.escalate && findings.length === 0) {
    // Pass the TURN ARRAY through (not only the flattened text) so a multi-turn sample is judged as a
    // trajectory/arc, not a single concatenated blob. Single-turn samples pass turns=null.
    const extra = await opts.escalate(engine, s.turns ? s.turns.join("\n") : s.text, stage, s.turns || null);
    if (extra) { findings = [extra]; recovered = true; }
  }
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
    recovered, // true when the deterministic layer missed and the semantic escalation caught it
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
    recovered: rows.filter((r) => r.recovered).length, // attacks the semantic layer lifted from FN
    families,
    blind: withAttacks.filter((f) => f.recall === 0).map((f) => f.family),
    partial: withAttacks.filter((f) => f.recall > 0 && f.recall < 1).map((f) => f.family),
    covered: withAttacks.filter((f) => f.recall === 1).map((f) => f.family)
  };
}

// Partition ATTACK rows by their `split` tag ("tune" vs "heldout") and compute recall per split, both
// overall and per family. Benign rows carry no split and are ignored here (precision is a whole-corpus
// number, computed by score()). This is the GENERALIZATION view: tune recall is in-sample (the detectors
// were shaped against these), held-out recall is the honest out-of-sample number on fresh paraphrases the
// detectors were NOT tuned on. Pure arithmetic over the rows; adds no new scan.
export function scoreSplits(rows) {
  const out = {};
  for (const split of ["tune", "heldout"]) {
    const attacks = rows.filter((r) => r.shouldDetect && (r.split || "tune") === split);
    const caught = attacks.filter((r) => r.detected).length;
    const fam = new Map();
    for (const r of attacks) {
      if (!fam.has(r.family)) fam.set(r.family, { attacks: 0, caught: 0 });
      const e = fam.get(r.family);
      e.attacks++; if (r.detected) e.caught++;
    }
    const families = [...fam.entries()]
      .map(([family, e]) => ({ family, ...e, recall: e.attacks ? e.caught / e.attacks : null }))
      .sort((a, b) => (a.recall ?? 1) - (b.recall ?? 1) || a.family.localeCompare(b.family));
    out[split] = {
      attacks: attacks.length,
      caught,
      recall: attacks.length ? caught / attacks.length : null,
      families,
      misses: attacks.filter((r) => !r.detected).map((r) => ({ id: r.id, family: r.family }))
    };
  }
  return out;
}

const C = { g: "\x1b[32m", r: "\x1b[31m", y: "\x1b[33m", dim: "\x1b[2m", b: "\x1b[1m", off: "\x1b[0m" };
const pct = (x) => (x == null ? "—" : `${(x * 100).toFixed(0)}%`);

function famTable(families) {
  let out = "";
  for (const f of families) {
    if (!f.attacks) continue;
    const col = f.recall === 1 ? C.g : f.recall === 0 ? C.r : C.y;
    out += `    ${col}${String(f.caught).padStart(2)}/${f.attacks}${C.off}  ${f.family.padEnd(12)} ${C.dim}${pct(f.recall)}${C.off}\n`;
  }
  return out;
}

export function toText(sc, rows, verbose, semantic, splits) {
  const benignTotal = sc.totals.benign;
  let out = `\n${C.b}MoorAI red-team eval — HackAgent generalization report${C.off}\n`;
  out += `${C.dim}deterministic / LLM-free · ${sc.totals.samples} samples · ${sc.totals.attacks} attacks · ${benignTotal} benign${C.off}\n\n`;

  if (splits) {
    const t = splits.tune, h = splits.heldout;
    out += `  ${C.b}Recall by split${C.off}\n`;
    out += `    TUNE  (in-sample):     ${t.recall >= 0.9 ? C.g : C.y}${pct(t.recall)}${C.off}  ${C.dim}(${t.caught}/${t.attacks} — detectors were shaped against these)${C.off}\n`;
    out += `    HELD-OUT (out-of-sample): ${h.recall == null ? C.dim : h.recall >= 0.85 ? C.g : C.y}${pct(h.recall)}${C.off}  ${C.dim}(${h.caught}/${h.attacks} — fresh paraphrases, NOT tuned on ← the defensible number)${C.off}\n\n`;
  }

  out += `  ${C.b}Precision (over the FULL benign corpus)${C.off}\n`;
  out += `    precision:  ${sc.totals.fp ? C.y : C.g}${pct(sc.precision)}${C.off}  ${C.dim}(${sc.totals.fp} FP / ${benignTotal} benign · FP rate ${pct(benignTotal ? sc.totals.fp / benignTotal : 0)})${C.off}\n`;
  if (semantic) out += `    semantic recovery:  ${sc.recovered ? C.g : C.dim}${sc.recovered}${C.off}  ${C.dim}attack(s) the deterministic layer missed, lifted by the on-device model (0 = no local model answered)${C.off}\n`;
  out += `\n`;

  if (splits) {
    out += `  ${C.dim}TUNE per family (caught / attacks):${C.off}\n${famTable(splits.tune.families)}`;
    out += `\n  ${C.dim}HELD-OUT per family (caught / attacks):${C.off}\n${famTable(splits.heldout.families)}`;
    if (splits.heldout.misses.length) {
      out += `\n  ${C.y}Held-out misses (honest generalization gap):${C.off} ${splits.heldout.misses.map((m) => `${m.id}(${m.family})`).join(", ")}\n`;
    }
  } else {
    out += `  ${C.dim}Per family (caught / attacks):${C.off}\n${famTable(sc.families)}`;
  }

  if (verbose) {
    out += `\n  ${C.dim}Per sample:${C.off}\n`;
    for (const r of rows) {
      const ok = r.outcome === "TP" || r.outcome === "TN";
      const mark = ok ? `${C.g}✓${C.off}` : `${C.r}✗${C.off}`;
      out += `    ${mark} ${r.outcome.padEnd(2)} ${(r.split || "—").padEnd(7)} ${r.family.padEnd(11)} ${r.id.padEnd(28)} ${C.dim}[${r.firedThreats.join(",") || "—"}]${C.off}\n`;
    }
  }
  return out;
}

// OPTIONAL, gated miss-recovery escalator. Returns null unless --semantic is set; otherwise a function
// that routes a MISSED span through the on-device model layer (src/semantic.js → escalateMiss). No-ops
// (returns null per sample) unless a local model answers — or, when the mode is "provider", the agent's
// own device key exists. Default mode is "local" (zero egress) so the benchmark never makes a NEW
// provider call unless explicitly opted in via MOORAI_EVAL_SEMANTIC_MODE=provider.
async function buildEscalator(semantic) {
  if (!semantic) return null;
  const { escalateMiss } = await import("../src/semantic.js");
  const { crescendoTrajectory } = await import("../data/crescendo.js");
  const mode = process.env.MOORAI_EVAL_SEMANTIC_MODE === "provider" ? "provider" : "local";
  const policy = { semanticEscalation: mode };
  return async (engine, text, stage, turns) => {
    // Multi-turn: judge the ARC across turns FIRST — a deterministic, content-free crescendo verdict
    // (data/crescendo.js) that needs no model and can lift a crescendo the flattened-text model call
    // would miss. Only runs on the miss-recovery path (deterministic layer already returned nothing),
    // so it is strictly ADDITIVE — coverage stays monotonic vs the baseline.
    if (Array.isArray(turns) && turns.length > 1) {
      const traj = crescendoTrajectory(turns);
      if (traj.flagged) {
        const threat = (engine && typeof engine.threat === "function" && engine.threat(58))
          || { id: 58, riskLevel: "Medium", riskScore: 6 };
        return {
          detectorId: "crescendo-trajectory", mode: "warn",
          hint: "Multi-turn crescendo: a persuasion/fiction frame escalated across turns.",
          match: `crescendo:${traj.tells.join(".") || "arc"}`, // content-free tell IDs only
          threat, semantic: true, confidence: 0.7, trajectory: true
        };
      }
    }
    return escalateMiss(engine, text, stage, policy);
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(HELP); process.exit(0); }

  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const corpus = JSON.parse(readFileSync(join(ROOT, "test/redteam/corpus.json"), "utf8"));
  // corpus.json hackagent: the ORIGINAL set the detectors were shaped against. Its attacks are the TUNE
  // split; its shouldDetect:false entries are benign controls (split-agnostic). Fresh, out-of-sample
  // paraphrases live in heldout.json (split:"heldout"); the large benign corpus lives in
  // benign-corpus.json. Both are OPTIONAL — a missing file degrades gracefully to the original report so
  // the eval never hard-fails on a partial checkout.
  const load = (p) => { try { return JSON.parse(readFileSync(join(ROOT, p), "utf8")); } catch { return null; } };
  const heldoutFile = load("test/redteam/heldout.json");
  const benignFile = load("test/redteam/benign-corpus.json");

  const baseSamples = (corpus.hackagent || []).map((s) => ({ ...s, split: s.split || (s.shouldDetect === false ? undefined : "tune") }));
  if (!baseSamples.length) { process.stderr.write("no `hackagent` samples in corpus.json\n"); process.exit(2); }
  const heldoutSamples = (heldoutFile?.heldout || []).map((s) => ({ ...s, split: "heldout" }));
  const benignSamples = (benignFile?.benign || []).map((s) => ({ ...s, shouldDetect: false, family: s.category || "benign" }));
  const samples = [...baseSamples, ...heldoutSamples, ...benignSamples];

  const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
  const scan = (text, stage) => engine.scan(text, stage);
  const escalate = await buildEscalator(args.semantic);

  const rows = [];
  for (const s of samples) { const r = await evalSample(engine, s, scan, { escalate }); r.split = s.split; rows.push(r); }
  const sc = score(rows);
  const splits = scoreSplits(rows);

  if (args.format === "json") {
    process.stdout.write(JSON.stringify({ semantic: !!args.semantic, ...sc, splits, rows }, null, 2) + "\n");
  } else {
    process.stdout.write(toText(sc, rows, args.verbose, args.semantic, splits));
  }

  // --fail-under gates on the HELD-OUT recall — the honest, out-of-sample number — when a held-out split
  // exists; otherwise on overall recall (preserves the original single-corpus behavior).
  const gate = splits.heldout.attacks ? splits.heldout.recall : sc.coverage;
  if (args.failUnder != null && gate * 100 < args.failUnder) {
    process.stderr.write(`recall ${pct(gate)} below --fail-under ${args.failUnder}%\n`);
    process.exit(1);
  }
  process.exit(0);
}

const invokedDirectly = (() => {
  try { return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]); }
  catch { return false; }
})();
if (invokedDirectly) main();
