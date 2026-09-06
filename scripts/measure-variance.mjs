#!/usr/bin/env node
// AMTSO §"model non-determinism" — repeated-run variance measurement.
//
// Every model-assisted figure this repo publishes today is a SINGLE-RUN point estimate, and we already
// know they move (an 8B judge recovered 8 attacks in one run and 5 in another; a benign FP count drifted
// 13→14 between two runs). The AMTSO "Guidelines for Testing of Agentic Security Products" (v1.0) asks
// for "the distribution of outcomes rather than hiding variability behind a single pass or fail result".
// This script produces that distribution.
//
//   node scripts/measure-variance.mjs --file test/redteam/heldout-v2-tune.json --plan
//   node scripts/measure-variance.mjs --file test/redteam/heldout-v2-tune.json --runs 10
//   node scripts/measure-variance.mjs --file test/redteam/heldout-v2-test.json --runs 10 --json
//
// MEASUREMENT ONLY. It imports the shipped engine and the shipped `evalSample` reducer; it mutates no
// detector, no corpus, and no other script. Content-free: only ids / booleans / counts are emitted.
//
// COST MODEL (the reason this is affordable at all). The shipped pipeline is
//   deterministic scan  ->  if findings.length === 0 AND --semantic  ->  on-device model
// so a sample the regex layer already decided NEVER reaches the model and CANNOT flip. Only the
// deterministic-miss set is escalation-eligible. N runs therefore cost N x |eligible| model calls, not
// N x |corpus|. --plan prints that number and the projected wall-clock before spending it.
//
// The deterministic layer's invariance is not assumed, it is PROVEN each time: the regex pass is run
// --det-runs times and the per-sample verdict vectors are hashed and compared.

// MUST precede the imports that read it: data/model-escalation.mjs and src/semantic.js both freeze their
// timeout budget at module-load time. A cold model load once cost this project a badly wrong conclusion,
// so the default here is generous (30s) and a warm-up call is made before run 1 and discarded.
if (!process.env.MOORAI_LOCAL_TIMEOUT_MS) process.env.MOORAI_LOCAL_TIMEOUT_MS = "30000";

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join, basename } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_CACHE = "test/redteam/variance-cache.json";

// Same policy object score-heldout-v2.mjs --semantic uses, so a run here is the same measurement.
const SEMANTIC_POLICY = { semanticEscalation: "local", modelEscalation: true };

// ---------------------------------------------------------------------------
// Pure statistics. Exported so the test can drive them without a model.
// ---------------------------------------------------------------------------

export function median(xs) {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

// Two-sided 95% t critical values, df = n-1. N is small here by construction (model calls are slow), so
// the normal z=1.96 would understate the interval width; at n=10 the correct multiplier is 2.262.
const T95 = { 1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262,
  10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101,
  19: 2.093, 20: 2.086, 24: 2.064, 29: 2.045 };
export function tCritical(df) {
  if (df < 1) return null;
  if (T95[df]) return T95[df];
  const keys = Object.keys(T95).map(Number).filter((k) => k <= df);
  return keys.length ? T95[Math.max(...keys)] : 1.96;
}

// Distribution of ONE metric across N runs. min/median/max is the raw, assumption-free view; mean +/- sd
// with a t-interval is the parametric summary. Both are reported because with N ~ 10 they can disagree.
export function summarize(values) {
  const n = values.length;
  if (!n) return null;
  const mean = values.reduce((a, b) => a + b, 0) / n;
  // Sample standard deviation (n-1): these N runs are a SAMPLE of the run-to-run process, not the
  // population of all possible runs.
  const sd = n > 1 ? Math.sqrt(values.reduce((a, b) => a + (b - mean) ** 2, 0) / (n - 1)) : 0;
  const t = n > 1 ? tCritical(n - 1) : null;
  const halfWidth = t == null ? null : t * (sd / Math.sqrt(n));
  return {
    n,
    min: Math.min(...values),
    median: median(values),
    max: Math.max(...values),
    mean,
    sd,
    // 95% t-interval on the MEAN of the run-level metric. It answers "where does the long-run average of
    // this metric sit", not "where will the next single run land" — a single run's spread is min..max.
    ci95: halfWidth == null ? null : [mean - halfWidth, mean + halfWidth],
    interval: "t(n-1), 95%, two-sided, on the mean of the run-level metric"
  };
}

// 95% Wilson score interval for a proportion k/n. Chosen over Wald deliberately: the cases that matter
// most here are k=0 (always-missed) and k=n (always-caught), where Wald collapses to a zero-width
// interval and would claim certainty that 10 runs cannot support.
export function wilson(k, n, z = 1.96) {
  if (!n) return null;
  const p = k / n;
  const d = 1 + (z * z) / n;
  const centre = (p + (z * z) / (2 * n)) / d;
  const half = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / d;
  return [Math.max(0, centre - half), Math.min(1, centre + half)];
}

// Per-sample stability across runs. `hits` is the count of runs in which the sample was DETECTED.
//   always-caught  — detected in every run
//   always-missed  — detected in no run
//   unstable       — anything in between; flipRate is how often the minority verdict occurred
// This is deliberately more actionable than any aggregate: a metric that looks stable in aggregate can
// be built entirely on samples that each flip half the time.
export function classifySample(hits, runs) {
  if (hits === runs) return { stability: "always-caught", hitRate: 1, flipRate: 0, ci95: wilson(hits, runs) };
  if (hits === 0) return { stability: "always-missed", hitRate: 0, flipRate: 0, ci95: wilson(hits, runs) };
  const p = hits / runs;
  return { stability: "unstable", hitRate: p, flipRate: Math.min(p, 1 - p), ci95: wilson(hits, runs) };
}

// Reduce a set of runs (each a Map/object id -> 0|1) into the per-sample stability table.
export function stabilityTable(ids, runVerdicts) {
  const runs = runVerdicts.length;
  return ids.map((id) => {
    const hits = runVerdicts.reduce((a, v) => a + (v[id] ? 1 : 0), 0);
    return { id, hits, runs, ...classifySample(hits, runs) };
  });
}

// ---------------------------------------------------------------------------
// Corpus loading + hashing
// ---------------------------------------------------------------------------

const sha = (s) => createHash("sha256").update(s).digest("hex").slice(0, 16);

// Accepts the shapes actually present in test/redteam/: {attacks,benign} (heldout-v2 halves),
// {hackagent} (corpus.json), {heldout} (heldout.json), {benign} (benign corpora).
export function loadSamples(json) {
  const out = [];
  for (const s of json.attacks || []) out.push({ ...s, shouldDetect: true });
  for (const s of json.heldout || []) out.push({ ...s, shouldDetect: s.shouldDetect !== false });
  for (const s of json.hackagent || []) out.push({ ...s, shouldDetect: s.shouldDetect !== false });
  for (const s of json.benign || []) out.push({ ...s, shouldDetect: false, family: s.family || s.category || "benign" });
  return out;
}

// ---------------------------------------------------------------------------
// Metrics for one run's verdict map
// ---------------------------------------------------------------------------

export function runMetrics(samples, verdicts) {
  let tp = 0, fn = 0, fp = 0, tn = 0;
  for (const s of samples) {
    const det = !!verdicts[s.id];
    if (s.shouldDetect) det ? tp++ : fn++;
    else det ? fp++ : tn++;
  }
  const attacks = tp + fn, benign = fp + tn;
  return {
    tp, fn, fp, tn,
    recall: attacks ? tp / attacks : null,
    precision: tp + fp ? tp / (tp + fp) : 1,
    fpCount: fp,
    fpRate: benign ? fp / benign : null
  };
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const val = (f, d) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : d);
  return {
    file: val("--file", "test/redteam/heldout-v2-tune.json"),
    runs: Number(val("--runs", 10)),
    detRuns: Number(val("--det-runs", 3)),
    cache: val("--cache", DEFAULT_CACHE),
    fresh: argv.includes("--fresh"),
    plan: argv.includes("--plan"),
    json: argv.includes("--json"),
    help: argv.includes("--help") || argv.includes("-h")
  };
}

function readCache(path) {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return { _comment: "Cached per-run model verdicts for scripts/measure-variance.mjs. Delete to force a re-measurement.", entries: {} }; }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(`measure-variance — repeated-run distribution for model-assisted metrics (AMTSO).

  --file <path>     corpus under test/redteam/ (default heldout-v2-tune.json)
  --runs <n>        model runs (default 10)
  --det-runs <n>    deterministic invariance repeats (default 3)
  --plan            print the cost of the run and exit without calling the model
  --cache <path>    cached per-run verdicts (default ${DEFAULT_CACHE})
  --fresh           ignore cached runs
  --json            machine-readable output

  MOORAI_LOCAL_TIMEOUT_MS  per-call model budget (default 30000 here, not the shipped 2500)
  MOORAI_LOCAL_MODEL       override the escalation model
`);
    return;
  }

  // Dynamic imports: the timeout env var above must be set before these modules freeze their budgets.
  const { DETECTORS } = await import("../data/detectors.js");
  const { CONTENT_RULES } = await import("../data/content-rules.js");
  const { DetectionEngine } = await import("../src/engine.js");
  const { evalSample } = await import("./redteam-eval.mjs");
  const { escalateMiss } = await import("../src/semantic.js");
  const { takeEscalationOutcomes, localModelAvailable, classifyLocal } = await import("../data/model-escalation.mjs");

  const corpusPath = join(ROOT, args.file);
  const corpusRaw = readFileSync(corpusPath, "utf8");
  const samples = loadSamples(JSON.parse(corpusRaw));
  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
  const scan = (text, stage) => engine.scan(text, stage);

  // SNAPSHOT IDENTITY. redteam-eval.mjs and the detectors are being edited by other work; a cached run
  // is only comparable to a fresh one when these hashes match, so they are part of the cache key.
  const snapshot = {
    corpus: basename(args.file),
    corpusHash: sha(corpusRaw),
    detectorsHash: sha(readFileSync(join(ROOT, "data/detectors.js"), "utf8")),
    evalHash: sha(readFileSync(join(ROOT, "scripts/redteam-eval.mjs"), "utf8")),
    semanticHash: sha(readFileSync(join(ROOT, "src/semantic.js"), "utf8")),
    model: process.env.MOORAI_LOCAL_MODEL || "llama3:latest",
    timeoutMs: Number(process.env.MOORAI_LOCAL_TIMEOUT_MS)
  };

  // ---- 1. Deterministic invariance: proven, not assumed -------------------
  const detVectors = [];
  for (let i = 0; i < args.detRuns; i++) {
    const v = {};
    for (const s of samples) v[s.id] = (await evalSample(engine, s, scan)).detected ? 1 : 0;
    detVectors.push(v);
  }
  const detHashes = detVectors.map((v) => sha(samples.map((s) => v[s.id]).join("")));
  const deterministicInvariant = new Set(detHashes).size === 1;
  const detVerdicts = detVectors[0];
  const detDrift = deterministicInvariant
    ? []
    : samples.filter((s) => new Set(detVectors.map((v) => v[s.id])).size > 1).map((s) => s.id);

  // ---- 2. Escalation-eligible set: the only samples that can flip ---------
  const eligible = samples.filter((s) => !detVerdicts[s.id]);
  const eligibleIds = eligible.map((s) => s.id);
  const frozen = samples.filter((s) => detVerdicts[s.id]);

  const detMetrics = runMetrics(samples, detVerdicts);

  if (args.plan) {
    const est = eligible.length * args.runs;
    const out = {
      snapshot,
      samples: samples.length,
      attacks: samples.filter((s) => s.shouldDetect).length,
      benign: samples.filter((s) => !s.shouldDetect).length,
      deterministicInvariant, detHashes, detDrift,
      deterministicMetrics: detMetrics,
      escalationEligible: eligible.length,
      frozenBySeenDeterministicFinding: frozen.length,
      modelCallsForRuns: est,
      projectedMinutesAt600msPerCall: +((est * 0.6) / 60).toFixed(1),
      projectedMinutesAt2000msPerCall: +((est * 2.0) / 60).toFixed(1)
    };
    process.stdout.write(JSON.stringify(out, null, 2) + "\n");
    return;
  }

  if (!(await localModelAvailable(2000))) {
    process.stderr.write("no local model on 127.0.0.1:11434 — nothing to measure\n");
    process.exit(2);
  }

  // ---- 3. Cached runs ----------------------------------------------------
  const cachePath = join(ROOT, args.cache);
  const cache = readCache(cachePath);
  const key = [snapshot.corpus, snapshot.corpusHash, snapshot.detectorsHash, snapshot.evalHash, snapshot.semanticHash, snapshot.model].join("|");
  if (args.fresh) delete cache.entries[key];
  const entry = (cache.entries[key] ||= { snapshot, eligible: eligibleIds, runs: [] });

  // ---- 4. Warm-up so a cold model load is never scored as a verdict -------
  if (entry.runs.length < args.runs) {
    const t0 = Date.now();
    await classifyLocal("warm up the model so the first scored run is not a cold load");
    takeEscalationOutcomes();
    entry.warmupMs = Date.now() - t0;
  }

  // ---- 5. Model runs -----------------------------------------------------
  const escalate = (eng, text, stage) => escalateMiss(eng, text, stage, SEMANTIC_POLICY);
  while (entry.runs.length < args.runs) {
    const t0 = Date.now();
    const verdicts = { ...detVerdicts };
    for (const s of eligible) {
      const r = await evalSample(engine, s, scan, { escalate });
      verdicts[s.id] = r.detected ? 1 : 0;
    }
    const outcomes = takeEscalationOutcomes();
    const kinds = {};
    for (const o of outcomes) kinds[o.outcome] = (kinds[o.outcome] || 0) + 1;
    const answered = kinds.answered || 0;
    entry.runs.push({
      ts: new Date().toISOString(),
      ms: Date.now() - t0,
      // A run with any non-"answered" outcome is DEGRADED: a timeout looks exactly like "the model
      // looked and said benign". Such runs stay in the distribution but are named in the report.
      degraded: answered !== outcomes.length,
      outcomes: kinds,
      verdicts: Object.fromEntries(eligibleIds.map((id) => [id, verdicts[id]]))
    });
    writeFileSync(cachePath, JSON.stringify(cache, null, 2) + "\n");
    process.stderr.write(`run ${entry.runs.length}/${args.runs} — ${entry.runs.at(-1).ms}ms ${JSON.stringify(kinds)}\n`);
  }

  // ---- 6. Aggregate ------------------------------------------------------
  const used = entry.runs.slice(0, args.runs);
  const fullVerdicts = used.map((r) => ({ ...detVerdicts, ...r.verdicts }));
  const perRun = fullVerdicts.map((v) => runMetrics(samples, v));

  const metrics = {
    recall: summarize(perRun.map((m) => m.recall)),
    precision: summarize(perRun.map((m) => m.precision)),
    fpCount: summarize(perRun.map((m) => m.fpCount)),
    tp: summarize(perRun.map((m) => m.tp)),
    // attacks the model lifted out of the deterministic-miss set, per run
    recovered: summarize(fullVerdicts.map((v) => eligible.filter((s) => s.shouldDetect && v[s.id]).length)),
    // benign samples the model turned into false positives, per run
    modelInducedFp: summarize(fullVerdicts.map((v) => eligible.filter((s) => !s.shouldDetect && v[s.id]).length))
  };

  const table = stabilityTable(eligibleIds, used.map((r) => r.verdicts))
    .map((row) => {
      const s = eligible.find((x) => x.id === row.id);
      return { ...row, shouldDetect: s.shouldDetect, family: s.family || "—", axis: s.axis || "—" };
    })
    .sort((a, b) => b.flipRate - a.flipRate || a.id.localeCompare(b.id));

  const unstable = table.filter((r) => r.stability === "unstable");
  const report = {
    snapshot,
    runsUsed: used.length,
    degradedRuns: used.map((r, i) => (r.degraded ? i + 1 : null)).filter(Boolean),
    warmupMs: entry.warmupMs ?? null,
    msPerRun: summarize(used.map((r) => r.ms)),
    deterministic: {
      invariant: deterministicInvariant,
      repeats: args.detRuns,
      verdictVectorHashes: detHashes,
      driftedSamples: detDrift,
      metrics: detMetrics
    },
    counts: {
      samples: samples.length,
      attacks: samples.filter((s) => s.shouldDetect).length,
      benign: samples.filter((s) => !s.shouldDetect).length,
      escalationEligible: eligible.length,
      frozenByDeterministicFinding: frozen.length
    },
    metrics,
    stability: {
      alwaysCaught: table.filter((r) => r.stability === "always-caught").length,
      alwaysMissed: table.filter((r) => r.stability === "always-missed").length,
      unstable: unstable.length,
      // The share of the model's own contribution that is luck rather than signal.
      unstableShareOfEligible: eligible.length ? unstable.length / eligible.length : 0
    },
    unstableSamples: unstable,
    table
  };

  if (args.json) { process.stdout.write(JSON.stringify(report, null, 2) + "\n"); return; }
  process.stdout.write(toText(report) + "\n");
}

const pct = (x) => (x == null ? "—" : `${(x * 100).toFixed(1)}%`);
const f3 = (x) => (x == null ? "—" : x.toFixed(3));

export function toText(r) {
  const C = { g: "\x1b[32m", r: "\x1b[31m", y: "\x1b[33m", dim: "\x1b[2m", b: "\x1b[1m", off: "\x1b[0m" };
  let o = `\n${C.b}MoorAI — repeated-run variance (AMTSO model non-determinism)${C.off}\n`;
  o += `${C.dim}${r.snapshot.corpus} · model ${r.snapshot.model} · N=${r.runsUsed} runs · timeout ${r.snapshot.timeoutMs}ms${C.off}\n`;
  o += `${C.dim}detectors ${r.snapshot.detectorsHash} · redteam-eval ${r.snapshot.evalHash} · semantic ${r.snapshot.semanticHash}${C.off}\n\n`;

  const det = r.deterministic;
  o += `  ${C.b}Deterministic layer${C.off}  ${det.invariant ? `${C.g}INVARIANT${C.off}` : `${C.r}DRIFTED${C.off}`} over ${det.repeats} repeats  ${C.dim}vector hash ${det.verdictVectorHashes[0]}${C.off}\n`;
  if (!det.invariant) o += `    ${C.r}drifted samples:${C.off} ${det.driftedSamples.join(", ")}\n`;
  o += `    ${C.dim}regex-only: recall ${pct(det.metrics.recall)} · ${det.metrics.fp} FP · precision ${pct(det.metrics.precision)}${C.off}\n`;
  o += `    ${C.dim}${r.counts.frozenByDeterministicFinding} of ${r.counts.samples} samples never reach the model (cannot flip); ${r.counts.escalationEligible} are escalation-eligible${C.off}\n\n`;

  o += `  ${C.b}Distribution over ${r.runsUsed} runs${C.off}  ${C.dim}(interval: t(n-1) 95% on the mean)${C.off}\n`;
  o += `    ${"metric".padEnd(18)} ${"min".padStart(8)} ${"median".padStart(8)} ${"max".padStart(8)}   mean ± sd            95% CI\n`;
  for (const [name, m] of Object.entries(r.metrics)) {
    if (!m) continue;
    const spread = m.max - m.min;
    const col = spread === 0 ? C.g : C.y;
    o += `    ${col}${name.padEnd(18)}${C.off} ${f3(m.min).padStart(8)} ${f3(m.median).padStart(8)} ${f3(m.max).padStart(8)}   ${f3(m.mean)} ± ${f3(m.sd)}      ${m.ci95 ? `[${f3(m.ci95[0])}, ${f3(m.ci95[1])}]` : "—"}\n`;
  }
  o += `\n`;

  o += `  ${C.b}Per-sample stability (escalation-eligible only)${C.off}\n`;
  o += `    ${C.g}always-caught${C.off} ${r.stability.alwaysCaught}   ${C.dim}always-missed${C.off} ${r.stability.alwaysMissed}   ${C.y}unstable${C.off} ${r.stability.unstable}  ${C.dim}(${pct(r.stability.unstableShareOfEligible)} of eligible)${C.off}\n`;
  if (r.unstableSamples.length) {
    o += `\n    ${C.y}Unstable samples — these are where a published single-run number came from luck${C.off}\n`;
    o += `    ${"id".padEnd(40)} ${"kind".padEnd(7)} hits/N   flip   95% Wilson\n`;
    for (const s of r.unstableSamples) {
      o += `    ${s.id.padEnd(40)} ${(s.shouldDetect ? "attack" : "benign").padEnd(7)} ${String(s.hits).padStart(2)}/${s.runs}   ${pct(s.flipRate).padStart(6)}   [${f3(s.ci95[0])}, ${f3(s.ci95[1])}]\n`;
    }
  }
  if (r.degradedRuns.length) {
    o += `\n  ${C.r}DEGRADED RUNS (a non-"answered" model outcome occurred — a timeout is indistinguishable from "benign"):${C.off} ${r.degradedRuns.join(", ")}\n`;
  }
  o += `\n  ${C.dim}warm-up ${r.warmupMs ?? "—"}ms (discarded) · per-run wall clock median ${r.msPerRun ? Math.round(r.msPerRun.median) : "—"}ms${C.off}\n`;
  return o;
}

const invokedDirectly = (() => {
  try { return fileURLToPath(import.meta.url) === process.argv[1]; } catch { return false; }
})();
if (invokedDirectly) main();

export { main };
