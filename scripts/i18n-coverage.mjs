#!/usr/bin/env node
// Per-language coverage of the multilingual injection table (data/injection-i18n.js):
// override / reveal pattern counts, the stages each half reaches (derived from which detectors in
// data/detectors.js carry those RegExp objects, and the engine's own stage selection), whether a
// reviewed fixture file exists (test/i18n-fixtures/<language>.json), and the false-positive count on
// test/redteam/benign-<language>.json when that corpus exists.
//
//   node scripts/i18n-coverage.mjs          # text table
//   node scripts/i18n-coverage.mjs --json   # machine-readable
//
// Content-free: prints language keys, counts, detector-derived stage names and sample ids, never text.
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { INJECTION_I18N_BY_LANG } from "../data/injection-i18n.js";
import { DetectionEngine } from "../src/engine.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);

const STAGES = [...new Set(DETECTORS.flatMap((d) => d.stages || [d.stage]))];
// Stages on which the engine runs detector d, using its own stage selection (file/index -> prompt too).
const stagesOf = (d) => STAGES.filter((s) => engine._inStage(d, engine._wantStages(s)));

const I18N_DETECTORS = new Set();
function reach(patterns) {
  const set = new Set(patterns);
  const ds = DETECTORS.filter((d) => (d.patterns || []).some((p) => set.has(p)));
  for (const d of ds) I18N_DETECTORS.add(d.detectorId);
  return { detectors: ds.map((d) => d.detectorId), stages: STAGES.filter((s) => ds.some((d) => stagesOf(d).includes(s))) };
}

function benign(lang) {
  const rel = `test/redteam/benign-${lang}.json`;
  const path = join(ROOT, rel);
  if (!existsSync(path)) return null;
  let data;
  try { data = JSON.parse(readFileSync(path, "utf8")); } catch (e) { return { file: rel, error: "unreadable" }; }
  const samples = (data.benign || []).filter((s) => typeof s.text === "string");
  const i18nFpIds = [], anyFpIds = [];
  for (const s of samples) {
    const f = engine.scan(s.text, s.stage || "prompt");
    if (f.length) anyFpIds.push(s.id);
    if (f.some((x) => I18N_DETECTORS.has(x.detectorId))) i18nFpIds.push(s.id);
  }
  const n = samples.length;
  return {
    file: rel, samples: n,
    i18nFp: i18nFpIds.length, i18nFpRate: n ? i18nFpIds.length / n : 0,
    anyFp: anyFpIds.length, anyFpRate: n ? anyFpIds.length / n : 0,
    i18nFpIds, anyFpIds
  };
}

const rows = Object.entries(INJECTION_I18N_BY_LANG).map(([language, e]) => ({
  language,
  override: e.override.length,
  reveal: e.reveal.length,
  overrideReach: reach(e.override),
  revealReach: reach(e.reveal),
  fixture: existsSync(join(ROOT, "test/i18n-fixtures", `${language}.json`)),
  benign: null
}));
for (const r of rows) r.benign = benign(r.language);

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ stages: STAGES, i18nDetectors: [...I18N_DETECTORS], languages: rows }, null, 2));
} else {
  const pct = (x) => (x * 100).toFixed(2) + "%";
  const fp = (b) => !b ? "-" : b.error ? b.error
    : `i18n ${b.i18nFp}/${b.samples} (${pct(b.i18nFpRate)}), any ${b.anyFp}/${b.samples} (${pct(b.anyFpRate)})`;
  const table = [["language", "override", "reveal", "override stages", "reveal stages", "fixture", "benign FP"]];
  for (const r of rows) {
    table.push([r.language, String(r.override), String(r.reveal), r.overrideReach.stages.join(",") || "-",
      r.revealReach.stages.join(",") || "-", r.fixture ? "y" : "n", fp(r.benign)]);
  }
  const w = table[0].map((_, i) => Math.max(...table.map((row) => row[i].length)));
  for (const row of table) console.log(row.map((c, i) => c.padEnd(w[i])).join("  ").trimEnd());
  const gap = rows.filter((r) => r.reveal === 0).length;
  console.log(`\n${rows.length} languages; ${gap} with no reveal pattern; ${rows.filter((r) => r.fixture).length} with a fixture file.`);
  console.log(`i18n detectors: ${[...I18N_DETECTORS].join(", ")}`);
  for (const r of rows) if (r.benign?.i18nFpIds?.length) console.log(`${r.language} i18n FP ids: ${r.benign.i18nFpIds.join(", ")}`);
}
