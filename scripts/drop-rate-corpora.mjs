// Corpus loaders for scripts/drop-rate.mjs. Each returns ATTACK rows only (benign rows have no drop rate):
//   { corpus, id, family, axis, stage, text | turns, credited(ids, findings), ...inbound fields }
// `credited` is the corpus's OWN scorer definition of "detected", so bucket (a) matches that scorer.
//
// LOCKED DATA. The locked halves are scored once, by the orchestrator, never while iterating:
//   --file of a heldout-v2 test/full file, and --split locked|all, require --i-am-scoring-the-locked-split
//   (the flag scripts/score-inbound.mjs already uses). The inbound split is filtered to the requested half
//   BEFORE any sample is scanned.
import { readFileSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { repoSamples } from "./inbound-corpus.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const rd = (p) => JSON.parse(readFileSync(join(ROOT, p), "utf8"));
export const UNLOCK_FLAG = "--i-am-scoring-the-locked-split";
export const INJECTION_THREATS = new Set([3, 40, 50, 60]); // scripts/score-inbound.mjs:37

export function isLockedHeldoutFile(p) {
  const b = basename(p);
  return /^heldout-v2(-test)?\.json$/.test(b) || /-test\.json$/.test(b);
}

const anyFinding = (ids) => ids.length > 0; // scripts/redteam-eval.mjs:187 `detected = findings.length > 0`

// heldout-v2 (default: the tune half). Scored by scripts/score-heldout-v2.mjs through evalSample.
export function heldoutV2(file, { unlocked = false } = {}) {
  if (isLockedHeldoutFile(file) && !unlocked) throw new Error(`${file} holds locked samples; pass ${UNLOCK_FLAG} (orchestrator only)`);
  const d = rd(file);
  return (d.attacks || []).map((s) => ({
    corpus: "heldout-v2", id: s.id, family: s.family || "-", axis: s.axis || "-", stage: s.stage || "prompt",
    ...(s.turns ? { turns: s.turns } : { text: s.text }), credited: anyFinding
  }));
}

// The red-team harness corpora: corpus.json hackagent (tune) and heldout.json (redteam-eval.mjs:466,
// scored by `npm run test:scorers` on every run), plus corpus.json `cases` with an `expect` (redteam.mjs,
// credited only when the expected threat fires, redteam.mjs:37).
export function redteamHarness() {
  const corpus = rd("test/redteam/corpus.json");
  const ho = rd("test/redteam/heldout.json");
  const out = [];
  for (const s of corpus.hackagent || []) {
    if (s.shouldDetect === false) continue;
    out.push({ corpus: "hackagent", id: s.id, family: s.family || "-", axis: "-", stage: s.stage || "prompt", ...(s.turns ? { turns: s.turns } : { text: s.text }), credited: anyFinding });
  }
  for (const s of ho.heldout || []) {
    if (s.shouldDetect === false) continue;
    out.push({ corpus: "heldout-v1", id: s.id, family: s.family || "-", axis: "-", stage: s.stage || "prompt", ...(s.turns ? { turns: s.turns } : { text: s.text }), credited: anyFinding });
  }
  for (const c of corpus.cases || []) {
    if (c.expect == null) continue;
    out.push({ corpus: "redteam-cases", id: c.id, family: `expect#${c.expect}`, axis: "-", stage: c.stage || "prompt", ...(c.turns ? { turns: c.turns } : { text: c.text }), credited: (ids) => ids.includes(c.expect) });
  }
  return out;
}

// The corpus's own stage label for an inbound sample (what the corpus says the content arrives as).
function stageLabels(wanted) {
  const m = new Map();
  const put = (corpus, id, stage) => { if (wanted.has(`${corpus}:${id}`)) m.set(`${corpus}:${id}`, stage || null); };
  for (const s of rd("test/redteam/vector2-indirect-content.json").attacks) put("vector2", s.id, s.stage);
  for (const s of rd("test/redteam/vector3-supply-chain.json").attacks) put("vector3", s.id, s.stage);
  for (const s of rd("test/redteam/vector5-memory-crossagent.json").attacks) {
    const st = s.harness === "steps" && Array.isArray(s.steps) && s.steps.length ? s.steps[(s.consumeStep || s.steps.length) - 1]?.stage : s.stage;
    put("vector5", s.id, st);
  }
  const at = rd("test/redteam/atlas-2026-09.json");
  for (const s of [...at.samples, ...(at.metadata || [])]) put("atlas", s.id, s.stage);
  for (const s of rd("test/redteam/benign-web-content.json").samples) put("web", s.id, s.stage);
  return m;
}

// The inbound population (scripts/inbound-corpus.mjs), attacks of one split. Credited the way
// scripts/score-inbound.mjs rowOf does: an alert-level (riskLevel !== "Info") injection finding or the
// sample's own expected threat.
export function inbound(split = "tune", { unlocked = false } = {}) {
  if (split !== "tune" && !unlocked) throw new Error(`--split ${split} includes locked samples; pass ${UNLOCK_FLAG} (orchestrator only)`);
  const rows = repoSamples().filter((s) => s.kind === "attack" && (split === "all" || s.split === split));
  const labels = stageLabels(new Set(rows.map((s) => `${s.corpus}:${s.id}`)));
  return rows.map((s) => ({
    corpus: `inbound:${s.corpus}`, id: s.id, family: s.corpus, axis: s.channel || "-", door: s.door, expect: s.expect,
    labelledStage: labels.get(`${s.corpus}:${s.id}`) || null, text: s.text,
    credited: (ids, findings) => findings.some((f) => f.riskLevel !== "Info" && (INJECTION_THREATS.has(f.threatId) || f.threatId === s.expect))
  }));
}
