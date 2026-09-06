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
//   node scripts/redteam-eval.mjs --policy offline  # score prevention against a different posture
//   node scripts/redteam-eval.mjs --help
//
// DETECTION vs PREVENTION (AMTSO): recall above is a DETECTION number. AMTSO's "Guidelines for Testing
// of Agentic Security Products" v1.0 says a detection number presented as protection is a reporting
// error, so every row ALSO carries an AMTSO outcome — see AMTSO_OUTCOMES / amtsoOutcomeFor below.
//
// Content-free: only rule ids / threat ids / booleans are emitted, never a sample's text.
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { threatActionFor } from "../cli/hook-core.mjs";
import { OFFLINE_DEFAULT_POLICY } from "../data/offline-default.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HELP = `moorai red-team eval — HackAgent detection-coverage benchmark (deterministic, LLM-free).

Usage:
  redteam-eval [--format text|json] [--verbose] [--fail-under <pct>] [--semantic]
               [--policy builtin|offline|<path.json>] [--timeout-ms <n>]

Scores the on-device engine against labelled adversarial families (AutoDAN/PAIR/TAP, FlipAttack, BoN,
CipherChat, PAP, h4rm3l, AdvPrefix, DAN) and reports coverage / precision / recall, a per-family table,
and the families the engine is currently BLIND to. Exit 0 by default; with --fail-under, exit 1 when
overall coverage is below the given percent.

Also reports the AMTSO outcome split — prevented / detected-but-not-prevented / missed / inconclusive —
because a detection number presented as protection is a reporting error. Prevention is derived from
threatActionFor(policy, threatId), the same function the shipped PreToolUse hook enforces with, under
the posture named by --policy (default: no org policy at all).
`;

export function parseArgs(argv) {
  const has = (f) => argv.includes(f);
  const val = (f) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : undefined);
  return {
    help: has("--help") || has("-h"),
    format: val("--format") || "text",
    verbose: has("--verbose"),
    semantic: has("--semantic"),
    // Which enforcement posture the PREVENTION half of the AMTSO split is derived against.
    // "builtin" (default) = no org policy at all, i.e. threatActionFor's own fallbacks.
    policy: val("--policy") || "builtin",
    timeoutMs: val("--timeout-ms") !== undefined ? Number(val("--timeout-ms")) : null,
    failUnder: val("--fail-under") !== undefined ? Number(val("--fail-under")) : null
  };
}

// ---------------------------------------------------------------------------------------------
// AMTSO outcome model — "Guidelines for Testing of Agentic Security Products" v1.0 (2026-09-02).
//
// The six-state vocabulary. This harness is DETERMINISTIC and MODEL-FREE, so it can produce four of
// the six: model-refusal and model-recognition are properties of the ASSISTANT's reply, not of the
// product, and there is no model in this loop to observe. They are named here (and reported as 0)
// rather than omitted, so a consumer can see they were measured-as-absent, not silently folded into
// another bucket — AMTSO is explicit that a model refusal must not be credited as product detection.
export const AMTSO_OUTCOMES = Object.freeze({
  PREVENTED: "prevented",
  DETECTED_NOT_PREVENTED: "detected-not-prevented",
  MODEL_REFUSAL: "model-refusal",
  MODEL_RECOGNITION: "model-recognition",
  MISSED: "missed",
  INCONCLUSIVE: "inconclusive"
});

// Enforcement-action strength. These are the SAME strings and the SAME precedence the shipped
// enforcement path uses: cli/hook-core.mjs `decideText` maps block|kill → deny, justify → ask, and
// notify|alert → allow-but-report, and it derives that action ONLY from `threatActionFor(policy, id)`
// — it never looks at a detector's own `mode`. That is why prevention here is derived from
// threatActionFor rather than from the finding: reading the detector's mode would measure a field
// enforcement ignores. A detector `mode:"warn"` on a threat whose policy action is "notify" produces
// an allow, so it is DETECTION; a policy action of "block" produces a deny, so it is PREVENTION.
const ACTION_RANK = { disabled: 0, notify: 1, alert: 2, justify: 3, block: 4, kill: 5 };

// "justify" counts as prevention because AMTSO's definition is "stopped OR materially disrupted the
// malicious outcome": the hook returns `ask`, so the tool call does not auto-execute — it is halted
// pending a human. This matches the repo's own existing convention in
// scripts/moorai-validate-blocking.mjs (`isStopped = deny || ask`). The stricter hard-deny-only count
// is still reported separately as `preventedHard`, so a reader who disagrees can use that instead.
const PREVENTIVE_ACTION = new Set(["justify", "block", "kill"]);
const HARD_PREVENTIVE_ACTION = new Set(["block", "kill"]);

// Strongest policy action across a row's fired threats, or null when nothing fired / all disabled.
// `policy` of null/undefined = no org policy, i.e. threatActionFor's built-in fallbacks.
export function policyActionFor(threatIds, policy) {
  let best = null;
  for (const id of threatIds || []) {
    const a = threatActionFor(policy, id);
    if (a === "disabled") continue;
    if (best === null || (ACTION_RANK[a] ?? 0) > (ACTION_RANK[best] ?? 0)) best = a;
  }
  return best;
}

// Reduce one row's evidence to an AMTSO outcome. Benign (shouldDetect:false) rows get null — the
// vocabulary describes what happened to a malicious attempt; a benign row's failure mode is a false
// positive, which the existing precision number already owns.
export function amtsoOutcomeFor({ shouldDetect, detected, action, error } = {}) {
  if (error) return AMTSO_OUTCOMES.INCONCLUSIVE;   // contradictory / unusable evidence, NOT a miss
  if (!shouldDetect) return null;
  if (!detected) return AMTSO_OUTCOMES.MISSED;
  return PREVENTIVE_ACTION.has(action) ? AMTSO_OUTCOMES.PREVENTED : AMTSO_OUTCOMES.DETECTED_NOT_PREVENTED;
}

// Bound one awaited phase so a hung scan/escalation becomes INCONCLUSIVE instead of hanging the run
// or being silently recorded as a miss. No budget (the default) → the value passes straight through
// and no timer is ever armed, so the default path is byte-identical to the pre-budget behavior.
function withBudget(p, ms, phase) {
  if (!ms || !p || typeof p.then !== "function") return p;
  let t;
  return Promise.race([
    Promise.resolve(p).finally(() => clearTimeout(t)),
    new Promise((_, reject) => {
      t = setTimeout(() => {
        const e = new Error(`${phase} exceeded ${ms}ms budget`);
        e.phase = phase;
        reject(e);
      }, ms);
    })
  ]);
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
// `opts.policy` (default null = no org policy) is the enforcement posture the AMTSO prevention half is
// derived against; `opts.timeoutMs` (default off) bounds each awaited phase. Both are additive — the
// legacy return fields (id/family/category/shouldDetect/detected/correctThreat/firedThreats/recovered/
// outcome) are unchanged, and the new ones (action/prevented/preventedHard/amtso/error) only ADD.
export async function evalSample(engine, s, scan, opts = {}) {
  const stage = s.stage || "prompt";
  let findings = [];
  let recovered = false;
  // AMTSO "Inconclusive": non-determinism, insufficient instrumentation, environmental failure or
  // contradictory evidence. A scan that THROWS or blows its time budget yields no usable evidence
  // about the product — recording that as a miss would be a claim the run cannot support — so it
  // lands here instead. Before this, a throwing scan crashed the whole eval.
  let error = null;
  let phase = "scan"; // which awaited phase is in flight, so a failure is attributed to the right one
  try {
    findings = (await withBudget(
      s.turns ? engine.scanSession(s.turns) : scan(s.text, stage), opts.timeoutMs, "scan"
    )) || [];
    if (opts.escalate && findings.length === 0) {
      phase = "escalate";
      // Pass the TURN ARRAY through (not only the flattened text) so a multi-turn sample is judged as a
      // trajectory/arc, not a single concatenated blob. Single-turn samples pass turns=null.
      const extra = await withBudget(
        opts.escalate(engine, s.turns ? s.turns.join("\n") : s.text, stage, s.turns || null),
        opts.timeoutMs, "escalate"
      );
      if (extra) { findings = [extra]; recovered = true; }
    }
  } catch (e) {
    error = { phase: e?.phase || phase, reason: String(e?.message || e).slice(0, 160) };
    findings = [];
  }
  const ids = findings.map((f) => f.threat.id);
  const detected = findings.length > 0;
  const correctThreat = s.expectThreat != null ? ids.includes(s.expectThreat) : detected;
  const should = s.shouldDetect !== false; // default: treat as attack unless explicitly benign
  // Legacy outcome, deliberately unchanged: an inconclusive attack row still counts FN here, so the
  // existing coverage/precision arithmetic every other caller reads stays conservative and identical.
  const outcome = should
    ? (detected ? "TP" : "FN")
    : (detected ? "FP" : "TN");
  const action = detected ? policyActionFor(ids, opts.policy ?? null) : null;
  return {
    id: s.id,
    family: s.family || "—",
    category: s.category || "—",
    shouldDetect: should,
    detected,
    correctThreat,
    firedThreats: ids,
    recovered, // true when the deterministic layer missed and the semantic escalation caught it
    outcome,
    // ---- ADDITIVE: AMTSO outcome model ----
    action,                                                    // strongest policy action, or null
    prevented: action != null && PREVENTIVE_ACTION.has(action), // deny OR human sign-off
    preventedHard: action != null && HARD_PREVENTIVE_ACTION.has(action), // hard deny only
    error,                                                     // null unless the evidence is unusable
    amtso: amtsoOutcomeFor({ shouldDetect: should, detected, action, error })
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

  // AMTSO outcome per row. Falls back to deriving it when a caller hands score() hand-built rows that
  // predate the outcome model (the existing unit tests do exactly that) — so score() never reports a
  // bucket it cannot justify from the row it was given.
  const amtsoOf = (r) => r.amtso !== undefined && r.amtso !== null
    ? r.amtso
    : amtsoOutcomeFor({ shouldDetect: r.shouldDetect, detected: r.detected, action: r.action, error: r.error });

  const fam = new Map();
  for (const r of rows) {
    if (!fam.has(r.family)) fam.set(r.family, {
      attacks: 0, caught: 0, benign: 0, fp: 0, rightReason: 0,
      prevented: 0, detectedNotPrevented: 0, missed: 0, inconclusive: 0
    });
    const e = fam.get(r.family);
    if (r.shouldDetect) { e.attacks++; if (r.detected) { e.caught++; if (r.correctThreat) e.rightReason++; } }
    else { e.benign++; if (r.detected) e.fp++; }
    const a = amtsoOf(r);
    if (a === AMTSO_OUTCOMES.PREVENTED) e.prevented++;
    else if (a === AMTSO_OUTCOMES.DETECTED_NOT_PREVENTED) e.detectedNotPrevented++;
    else if (a === AMTSO_OUTCOMES.MISSED) e.missed++;
    else if (a === AMTSO_OUTCOMES.INCONCLUSIVE) e.inconclusive++;
  }
  const families = [...fam.entries()]
    .map(([family, e]) => ({ family, ...e, recall: e.attacks ? e.caught / e.attacks : null }))
    .sort((a, b) => (a.recall ?? 1) - (b.recall ?? 1) || a.family.localeCompare(b.family));

  const withAttacks = families.filter((f) => f.attacks > 0);

  // ---- ADDITIVE: the AMTSO split. `attacks` above (tp+fn) still counts inconclusive attack rows, so
  // `coverage` stays exactly what it has always been. The AMTSO rates below drop inconclusive rows
  // from the DENOMINATOR — AMTSO's whole point is that "we could not tell" is not a result. ----
  const prevented = rows.filter((r) => amtsoOf(r) === AMTSO_OUTCOMES.PREVENTED).length;
  const detectedNotPrevented = rows.filter((r) => amtsoOf(r) === AMTSO_OUTCOMES.DETECTED_NOT_PREVENTED).length;
  const missed = rows.filter((r) => amtsoOf(r) === AMTSO_OUTCOMES.MISSED).length;
  const inconclusive = rows.filter((r) => amtsoOf(r) === AMTSO_OUTCOMES.INCONCLUSIVE).length;
  const inconclusiveAttacks = rows.filter((r) => r.shouldDetect && amtsoOf(r) === AMTSO_OUTCOMES.INCONCLUSIVE).length;
  const conclusiveAttacks = attacks - inconclusiveAttacks;
  const preventedHard = rows.filter((r) => r.shouldDetect && r.preventedHard).length;

  return {
    totals: { samples: rows.length, attacks, benign: fp + tn, tp, fn, fp, tn },
    coverage: recall, precision, rightReason,
    recovered: rows.filter((r) => r.recovered).length, // attacks the semantic layer lifted from FN
    families,
    blind: withAttacks.filter((f) => f.recall === 0).map((f) => f.family),
    partial: withAttacks.filter((f) => f.recall > 0 && f.recall < 1).map((f) => f.family),
    covered: withAttacks.filter((f) => f.recall === 1).map((f) => f.family),
    amtso: {
      prevented, detectedNotPrevented, missed, inconclusive,
      preventedHard,                 // the stricter hard-deny-only prevention count
      inconclusiveAttacks,
      // Not producible by a deterministic, model-free harness — reported as measured-absent, never
      // folded into detection or prevention (AMTSO: a model refusal is not product credit).
      modelRefusal: 0, modelRecognition: 0,
      attacks, conclusiveAttacks,
      preventionRate: conclusiveAttacks ? prevented / conclusiveAttacks : 0,
      detectionRate: conclusiveAttacks ? (prevented + detectedNotPrevented) / conclusiveAttacks : 0,
      missRate: conclusiveAttacks ? missed / conclusiveAttacks : 0
    },
    // Recall with inconclusive attack rows removed from the denominator. Equals `coverage` whenever
    // nothing was inconclusive, which is the normal case.
    coverageExclInconclusive: conclusiveAttacks ? (tp / conclusiveAttacks) : 0
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

// AMTSO three-way (four-way with inconclusive) split, per family. Emitted as its OWN table rather than
// as extra columns on famTable() so the existing per-family lines stay byte-identical.
function amtsoFamTable(families) {
  let out = "";
  for (const f of families) {
    if (!f.attacks) continue;
    const p = f.prevented ? C.g : C.dim;
    const d = f.detectedNotPrevented ? C.y : C.dim;
    const m = f.missed ? C.r : C.dim;
    const i = f.inconclusive ? C.y : C.dim;
    out += `    ${f.family.padEnd(12)} ${p}${String(f.prevented).padStart(2)} prevented${C.off}  `
      + `${d}${String(f.detectedNotPrevented).padStart(2)} detected-only${C.off}  `
      + `${m}${String(f.missed).padStart(2)} missed${C.off}  ${i}${String(f.inconclusive).padStart(2)} inconclusive${C.off}\n`;
  }
  return out;
}

// The AMTSO outcome block. `postureLabel` names the enforcement posture prevention was derived
// against, because "prevented" is meaningless without it.
export function amtsoText(sc, postureLabel) {
  const a = sc.amtso;
  const n = a.conclusiveAttacks || 1;
  const row = (label, count, col) =>
    `    ${label.padEnd(26)} ${col}${String(count).padStart(3)}${C.off}  ${C.dim}${pct(count / n)}${C.off}\n`;
  let out = `  ${C.b}AMTSO outcome split${C.off} ${C.dim}(attacks only · prevention derived from threatActionFor under posture: ${postureLabel})${C.off}\n`;
  out += row("prevented", a.prevented, a.prevented ? C.g : C.dim);
  out += `      ${C.dim}of which hard-deny (block/kill): ${a.preventedHard}; the rest are justify → halted for human sign-off${C.off}\n`;
  out += row("detected, NOT prevented", a.detectedNotPrevented, a.detectedNotPrevented ? C.y : C.dim);
  out += row("missed", a.missed, a.missed ? C.r : C.dim);
  out += row("inconclusive", a.inconclusive, a.inconclusive ? C.y : C.dim);
  out += `    ${C.dim}model-refusal ${a.modelRefusal} · model-recognition ${a.modelRecognition} — not observable by this deterministic, model-free harness${C.off}\n`;
  out += `    ${C.dim}detection rate ${pct(a.detectionRate)} · prevention rate ${pct(a.preventionRate)} · denominator ${a.conclusiveAttacks} conclusive of ${a.attacks} attacks${C.off}\n`;
  return out;
}

export function toText(sc, rows, verbose, semantic, splits, postureLabel = "builtin-default") {
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

  out += amtsoText(sc, postureLabel) + `\n`;

  if (splits) {
    out += `  ${C.dim}TUNE per family (caught / attacks):${C.off}\n${famTable(splits.tune.families)}`;
    out += `\n  ${C.dim}HELD-OUT per family (caught / attacks):${C.off}\n${famTable(splits.heldout.families)}`;
    if (splits.heldout.misses.length) {
      out += `\n  ${C.y}Held-out misses (honest generalization gap):${C.off} ${splits.heldout.misses.map((m) => `${m.id}(${m.family})`).join(", ")}\n`;
    }
  } else {
    out += `  ${C.dim}Per family (caught / attacks):${C.off}\n${famTable(sc.families)}`;
  }

  out += `\n  ${C.dim}AMTSO outcome per family:${C.off}\n${amtsoFamTable(sc.families)}`;

  if (verbose) {
    out += `\n  ${C.dim}Per sample:${C.off}\n`;
    for (const r of rows) {
      const ok = r.outcome === "TP" || r.outcome === "TN";
      const mark = ok ? `${C.g}✓${C.off}` : `${C.r}✗${C.off}`;
      const amtso = r.amtso ? ` ${C.dim}${r.amtso}${r.action ? `/${r.action}` : ""}${C.off}` : "";
      out += `    ${mark} ${r.outcome.padEnd(2)} ${(r.split || "—").padEnd(7)} ${r.family.padEnd(11)} ${r.id.padEnd(28)} ${C.dim}[${r.firedThreats.join(",") || "—"}]${C.off}${amtso}\n`;
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

// Resolve --policy to a real, in-repo posture. Nothing is invented: "builtin" is literally no policy
// (threatActionFor's own fallbacks — what a device with no org policy enforces), "offline" is the
// shipped fail-closed default (data/offline-default.js), and a path loads a real policy JSON.
export function resolvePolicy(spec) {
  if (!spec || spec === "builtin" || spec === "default" || spec === "none") return { policy: null, label: "builtin-default" };
  if (spec === "offline") return { policy: OFFLINE_DEFAULT_POLICY, label: "offline-fail-closed" };
  const path = spec.startsWith("/") ? spec : join(ROOT, spec);
  return { policy: JSON.parse(readFileSync(path, "utf8")), label: `file:${spec}` };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(HELP); process.exit(0); }
  const { policy, label: postureLabel } = resolvePolicy(args.policy);

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
  const evalOpts = { escalate, policy, timeoutMs: args.timeoutMs };
  for (const s of samples) { const r = await evalSample(engine, s, scan, evalOpts); r.split = s.split; rows.push(r); }
  const sc = score(rows);
  const splits = scoreSplits(rows);

  if (args.format === "json") {
    process.stdout.write(JSON.stringify({ semantic: !!args.semantic, posture: postureLabel, ...sc, splits, rows }, null, 2) + "\n");
  } else {
    process.stdout.write(toText(sc, rows, args.verbose, args.semantic, splits, postureLabel));
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
