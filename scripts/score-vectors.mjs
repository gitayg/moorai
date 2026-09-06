#!/usr/bin/env node
// Scorer for the two AMTSO attack vectors MoorAI ships detectors for but had never measured:
//   vector 3 — tool / skill / extension / MCP supply chain   (test/redteam/vector3-supply-chain.json)
//   vector 5 — memory, context and cross-agent propagation   (test/redteam/vector5-memory-crossagent.json)
//
//   node scripts/score-vectors.mjs                 # both vectors, text report
//   node scripts/score-vectors.mjs --vector 3      # one vector
//   node scripts/score-vectors.mjs --json          # machine-readable
//   node scripts/score-vectors.mjs --misses        # list every missed attack id
//   node scripts/score-vectors.mjs --fps           # list every false positive
//   node scripts/score-vectors.mjs --file <path>   # score an alternate corpus with the same logic
//
// WHY THIS IS NOT scripts/score-heldout-v2.mjs. That scorer assumes one sample = one string scanned at
// one stage. Neither of these vectors fits:
//   * vector 3 samples are TOOL METADATA and CONFIG FILES, which are only reachable at the "tool",
//     "file" and "index" stages — mcp-tool-poisoning and mcp-hidden-canary are stage-scoped to
//     ["tool","file","index"], so feeding a tool descriptor at the default "prompt" stage measures
//     nothing at all.
//   * vector 5 samples are SEQUENCES. Some are ordered steps[] scanned at their own stages (write in one
//     session, consume in a later one); some are TURN windows driven through DetectionEngine.scanSession;
//     and some carry no text whatsoever — they are event-graph shapes that only data/agent-detections.js
//     (via runAgentDetections in data/agent-baseline.js) can see. engine.scan() is structurally incapable
//     of scoring those, which is why this scorer drives two different entry points.
//
// SCORING RULES (stated so the numbers are reproducible, not negotiable):
//   harness "text"     — caught iff engine.scan(text, stage) returns >= 1 finding.
//   harness "session"  — caught iff engine.scanSession(turns) returns >= 1 finding.
//   harness "steps"    — every step is scanned at its own stage. TWO numbers are reported and they are
//                        NOT interchangeable:
//                          anyStep     — anything fired at any step (the optimistic reading);
//                          consumeStep — something fired at the step where the payload was actually
//                                        consumed by the later session / second agent (`consumeStep`,
//                                        1-based; defaults to the last step). This is the number that
//                                        matters: a payload written before the product was installed is
//                                        only ever seen at consume time, so a detection that exists only
//                                        at write time does not stop the attack. Headline recall for
//                                        vector 5 uses consumeStep.
//   harness "events"   — runAgentDetections(events) from data/agent-baseline.js. Caught iff at least one
//                        bucket named in the sample's expectDetections[] is non-empty (or, if the sample
//                        names none, any bucket at all). A BENIGN events sample is a false positive iff
//                        ANY bucket is non-empty — benign event traces must produce silence.
//
// --semantic additionally routes DETERMINISTIC MISSES to the policy-gated on-device model, exactly as
// scripts/score-heldout-v2.mjs does, so coverage is monotonic and a model failure is fail-open. It
// applies to text/steps/session samples only; the events harness has no text to escalate.
//
// Content-free: emits ids, sub-techniques, stages, threat ids, detection-bucket names and booleans.
// Never a sample's text.
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { runAgentDetections } from "../data/agent-baseline.js";
import { escalateMiss } from "../src/semantic.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SEMANTIC_POLICY = { semanticEscalation: "local", modelEscalation: true };

export const VECTOR_FILES = {
  3: "test/redteam/vector3-supply-chain.json",
  5: "test/redteam/vector5-memory-crossagent.json"
};

// Which STAGES a shipped harness actually feeds the engine, established by reading the call sites rather
// than assumed. Anything false here is a corpus that can only be scored through the library API — a
// reachability FINDING, not a detection result. Re-derive with:
//   grep -rn "engine.scan(\|decideText(" cli mcp-proxy src
export const STAGE_REACHABILITY = {
  prompt: { reachable: true, via: "cli/moorai-hook.mjs (UserPromptSubmit, Bash command, Task delegated prompt), cli/moorai-guard.mjs, src/app.js" },
  file: { reachable: true, via: "cli/moorai-hook.mjs decideText(..., \"file\") on file reads, including every data/skill-surface.js path" },
  output: { reachable: true, via: "cli/moorai-guard.mjs engine.scan(out, \"output\"), src/app.js" },
  index: { reachable: false, via: "DetectionEngine.scanForIndex exists but no shipped caller writes to a vector store; reachable only via the file stage, which also runs the index-stage detectors" },
  tool: { reachable: false, via: "NO shipped caller. mcp-proxy/moorai-mcp-guard.mjs scans tools/call ARGUMENTS only and passes tools/list through verbatim, so tool DESCRIPTIONS and SCHEMAS are never scanned in production" }
};

function loadCorpus(path) {
  const data = JSON.parse(readFileSync(join(ROOT, path), "utf8"));
  const attacks = (data.attacks || []).map((s) => ({ ...s, shouldDetect: s.shouldDetect !== false }));
  const benign = (data.benign || []).map((s) => ({ ...s, shouldDetect: false }));
  return { data, samples: [...attacks, ...benign] };
}

function stepsOf(s) {
  if (Array.isArray(s.steps) && s.steps.length) return s.steps;
  return [{ role: "consume", stage: s.stage || "prompt", text: s.text }];
}
function consumeIndex(s) {
  const steps = stepsOf(s);
  const idx = Number.isInteger(s.consumeStep) ? s.consumeStep - 1 : steps.length - 1;
  return Math.max(0, Math.min(steps.length - 1, idx));
}

// One sample -> one verdict row. `escalate` is the optional miss-recovery hook (--semantic).
export async function evalVectorSample(engine, s, escalate) {
  const harness = s.harness || "text";
  const row = {
    id: s.id,
    vector: s.vector ?? null,
    family: s.family || s.subTechnique || "—",
    subTechnique: s.subTechnique || s.family || "—",
    harness,
    stage: s.stage || (Array.isArray(s.steps) ? stepsOf(s)[consumeIndex(s)].stage : null),
    shouldDetect: s.shouldDetect !== false,
    detected: false,
    anyStepDetected: false,
    firedThreats: [],
    firedDetections: [],
    correctThreat: false,
    recovered: false
  };

  if (harness === "events") {
    const det = runAgentDetections(s.events || []);
    const nonEmpty = Object.keys(det).filter((k) => det[k].length > 0);
    row.firedDetections = nonEmpty;
    const want = Array.isArray(s.expectDetections) && s.expectDetections.length ? s.expectDetections : null;
    // Benign event traces must be silent: ANY bucket firing is a false positive.
    row.detected = row.shouldDetect
      ? (want ? want.some((k) => det[k] && det[k].length > 0) : nonEmpty.length > 0)
      : nonEmpty.length > 0;
    row.anyStepDetected = nonEmpty.length > 0;
    row.correctThreat = row.detected && (!want || want.every((k) => det[k] && det[k].length > 0));
    row.outcome = row.shouldDetect ? (row.detected ? "TP" : "FN") : (row.detected ? "FP" : "TN");
    return row;
  }

  if (harness === "session") {
    let findings = engine.scanSession(s.turns || []);
    if (escalate && findings.length === 0) {
      const extra = await escalate(engine, (s.turns || []).join("\n"), "prompt", s.turns || null);
      if (extra) { findings = [extra]; row.recovered = true; }
    }
    row.firedThreats = [...new Set(findings.map((f) => f.threat.id))];
    row.detected = findings.length > 0;
    row.anyStepDetected = row.detected;
    row.correctThreat = s.expectThreat != null ? row.firedThreats.includes(s.expectThreat) : row.detected;
    row.outcome = row.shouldDetect ? (row.detected ? "TP" : "FN") : (row.detected ? "FP" : "TN");
    return row;
  }

  // "text" and "steps" share the scan path; a "text" sample is a one-step sequence.
  const steps = stepsOf(s);
  const ci = consumeIndex(s);
  const perStep = [];
  for (const st of steps) {
    let findings = engine.scan(st.text || "", st.stage || "prompt");
    let recovered = false;
    if (escalate && findings.length === 0) {
      const extra = await escalate(engine, st.text || "", st.stage || "prompt", null);
      if (extra) { findings = [extra]; recovered = true; }
    }
    perStep.push({ stage: st.stage || "prompt", role: st.role || null, threats: [...new Set(findings.map((f) => f.threat.id))], recovered });
  }
  row.perStep = perStep.map((p) => ({ stage: p.stage, role: p.role, detected: p.threats.length > 0 }));
  row.anyStepDetected = perStep.some((p) => p.threats.length > 0);
  row.recovered = perStep.some((p) => p.recovered);
  const consume = perStep[ci];
  row.firedThreats = consume.threats;
  // Headline verdict for an attack is the CONSUME step. For a benign sample any step firing is a false
  // positive, because a real deployment scans every step.
  row.detected = row.shouldDetect ? consume.threats.length > 0 : row.anyStepDetected;
  row.correctThreat = s.expectThreat != null ? row.firedThreats.includes(s.expectThreat) : row.detected;
  row.outcome = row.shouldDetect ? (row.detected ? "TP" : "FN") : (row.detected ? "FP" : "TN");
  return row;
}

function groupBy(rows, key) {
  const m = new Map();
  for (const r of rows) {
    const g = r[key] || "—";
    if (!m.has(g)) m.set(g, { attacks: 0, caught: 0, caughtAnyStep: 0, benign: 0, fp: 0, rightReason: 0 });
    const e = m.get(g);
    if (r.shouldDetect) {
      e.attacks++;
      if (r.detected) { e.caught++; if (r.correctThreat) e.rightReason++; }
      if (r.anyStepDetected) e.caughtAnyStep++;
    } else { e.benign++; if (r.detected) e.fp++; }
  }
  return [...m.entries()]
    .map(([k, e]) => ({ [key]: k, ...e, recall: e.attacks ? e.caught / e.attacks : null, fpRate: e.benign ? e.fp / e.benign : null }))
    .sort((a, b) => (a.recall ?? 2) - (b.recall ?? 2) || String(a[key]).localeCompare(String(b[key])));
}

export function scoreVector(rows) {
  const c = (o) => rows.filter((r) => r.outcome === o).length;
  const tp = c("TP"), fn = c("FN"), fp = c("FP"), tn = c("TN");
  const attacks = tp + fn, benign = fp + tn;
  const anyStep = rows.filter((r) => r.shouldDetect && r.anyStepDetected).length;
  return {
    totals: { samples: rows.length, attacks, benign, tp, fn, fp, tn },
    recall: attacks ? tp / attacks : 0,
    recallAnyStep: attacks ? anyStep / attacks : 0,
    precision: tp + fp ? tp / (tp + fp) : 1,
    fpRate: benign ? fp / benign : 0,
    rightReason: rows.filter((r) => r.outcome === "TP" && r.correctThreat).length,
    recovered: rows.filter((r) => r.recovered).length,
    bySubTechnique: groupBy(rows, "subTechnique"),
    byHarness: groupBy(rows, "harness"),
    byStage: groupBy(rows.filter((r) => r.stage), "stage")
  };
}

function pct(x) { return x == null ? "  —  " : (x * 100).toFixed(1).padStart(5) + "%"; }

function renderVector(vector, path, corpus, sc, opts) {
  const L = [];
  L.push(`\n=== AMTSO vector ${vector} — ${corpus.data.vectorName} ===`);
  L.push(`corpus: ${path}`);
  L.push(`samples: ${sc.totals.samples}  (attacks ${sc.totals.attacks}, benign ${sc.totals.benign})`);
  L.push("");
  L.push(`  recall (consume step)   ${pct(sc.recall)}   ${sc.totals.tp}/${sc.totals.attacks}`);
  L.push(`  recall (any step)       ${pct(sc.recallAnyStep)}`);
  L.push(`  precision               ${pct(sc.precision)}`);
  L.push(`  false-positive rate     ${pct(sc.fpRate)}   ${sc.totals.fp}/${sc.totals.benign}`);
  L.push(`  right-reason TPs        ${sc.rightReason}/${sc.totals.tp}`);
  if (sc.recovered) L.push(`  semantic recoveries     ${sc.recovered}`);
  L.push("");
  L.push("  per sub-technique:");
  L.push("    " + "sub-technique".padEnd(32) + "atk  caught  recall   anyStep   benign  FP");
  for (const g of sc.bySubTechnique) {
    L.push("    " + String(g.subTechnique).padEnd(32)
      + String(g.attacks).padStart(3) + "  " + String(g.caught).padStart(6) + "  " + pct(g.recall)
      + "  " + pct(g.attacks ? g.caughtAnyStep / g.attacks : null)
      + "  " + String(g.benign).padStart(6) + "  " + String(g.fp).padStart(2));
  }
  L.push("");
  L.push("  per harness:");
  for (const g of sc.byHarness) {
    L.push("    " + String(g.harness).padEnd(12) + `attacks ${String(g.attacks).padStart(3)}  recall ${pct(g.recall)}   benign ${String(g.benign).padStart(3)}  FP ${g.fp}`);
  }
  L.push("");
  L.push("  per stage (text harnesses only):");
  for (const g of sc.byStage) {
    const r = STAGE_REACHABILITY[g.stage];
    const flag = r && !r.reachable ? "  [UNREACHABLE from any shipped harness]" : "";
    L.push("    " + String(g.stage).padEnd(12) + `attacks ${String(g.attacks).padStart(3)}  recall ${pct(g.recall)}   benign ${String(g.benign).padStart(3)}  FP ${g.fp}${flag}`);
  }
  if (opts.misses) {
    const m = opts.rows.filter((r) => r.shouldDetect && !r.detected);
    L.push("");
    L.push(`  misses (${m.length}):`);
    for (const r of m) L.push(`    ${r.id.padEnd(20)} ${r.subTechnique.padEnd(30)} ${(r.stage || r.harness)}${r.anyStepDetected ? "  (caught at an earlier step only)" : ""}`);
  }
  if (opts.fps) {
    const f = opts.rows.filter((r) => !r.shouldDetect && r.detected);
    L.push("");
    L.push(`  false positives (${f.length}):`);
    for (const r of f) L.push(`    ${r.id.padEnd(20)} ${r.subTechnique.padEnd(30)} threats=[${r.firedThreats.join(",")}] detections=[${r.firedDetections.join(",")}]`);
  }
  return L.join("\n");
}

async function run() {
  const args = process.argv.slice(2);
  const asJson = args.includes("--json");
  const showMisses = args.includes("--misses");
  const showFps = args.includes("--fps");
  const useSemantic = args.includes("--semantic");
  const vi = args.indexOf("--vector");
  const only = vi >= 0 && args[vi + 1] ? Number(args[vi + 1]) : null;
  const fi = args.indexOf("--file");
  const altFile = fi >= 0 && args[fi + 1] ? args[fi + 1] : null;

  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
  const escalate = useSemantic
    ? (eng, text, stage, turns) => escalateMiss(eng, text, stage, SEMANTIC_POLICY, turns ? { turns } : undefined)
    : null;

  const targets = altFile
    ? [{ vector: only ?? 0, path: altFile }]
    : Object.entries(VECTOR_FILES)
        .filter(([v]) => only == null || Number(v) === only)
        .map(([v, p]) => ({ vector: Number(v), path: p }));

  const out = { measuredAgainst: "working tree", stageReachability: STAGE_REACHABILITY, vectors: [] };
  const text = [];

  for (const t of targets) {
    const corpus = loadCorpus(t.path);
    const rows = [];
    for (const s of corpus.samples) rows.push(await evalVectorSample(engine, s, escalate));
    const sc = scoreVector(rows);
    out.vectors.push({
      vector: t.vector,
      vectorName: corpus.data.vectorName,
      corpus: t.path,
      ...sc,
      misses: rows.filter((r) => r.shouldDetect && !r.detected).map((r) => ({ id: r.id, subTechnique: r.subTechnique, stage: r.stage, harness: r.harness, anyStepDetected: r.anyStepDetected })),
      falsePositives: rows.filter((r) => !r.shouldDetect && r.detected).map((r) => ({ id: r.id, subTechnique: r.subTechnique, firedThreats: r.firedThreats, firedDetections: r.firedDetections }))
    });
    text.push(renderVector(t.vector, t.path, corpus, sc, { misses: showMisses, fps: showFps, rows }));
  }

  if (asJson) { console.log(JSON.stringify(out, null, 2)); return; }
  console.log(text.join("\n"));
  console.log("\n=== stage reachability from a SHIPPED harness ===");
  for (const [stage, r] of Object.entries(STAGE_REACHABILITY)) {
    console.log(`  ${stage.padEnd(8)} ${r.reachable ? "reachable" : "UNREACHABLE"}  — ${r.via}`);
  }
  console.log("");
}

// pathToFileURL, not a template literal: the repo path can contain spaces, which a raw `file://${path}`
// leaves unescaped and so never equals import.meta.url — the script would exit silently.
// The argv[1] guard keeps `node --input-type=module -e` importers (and the test file) from tripping
// pathToFileURL(undefined).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) run();
