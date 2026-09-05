#!/usr/bin/env node
// Deterministic, stratified split of test/redteam/heldout-v2.json into a TUNE half and a LOCKED TEST half.
//
// WHY. Wave A burned test/redteam/heldout.json by tuning against it, which destroyed its value as a
// generalization measure. To fix the Wave B root causes without repeating that, the 105-attack v2 set is
// split ONCE, deterministically: a tuning wave may see ONLY the tune half; the test half stays untouched
// so it can still answer "did this generalize?".
//
// Stratified by (family, axis) so both halves carry the same family and transformation mix — an unstratified
// random split could hand one half every homoglyph sample and make the result meaningless. Within each
// (family, axis) bucket, samples are sorted by id and assigned alternately, so the split is reproducible
// from the corpus alone with no stored seed.
//
//   node scripts/split-heldout-v2.mjs          # writes the two files
//   node scripts/split-heldout-v2.mjs --check  # verify the split is balanced, write nothing
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(ROOT, "test/redteam/heldout-v2.json");

function stratify(rows) {
  const buckets = new Map();
  for (const s of rows) {
    const k = `${s.family || "-"}|${s.axis || "-"}`;
    if (!buckets.has(k)) buckets.set(k, []);
    buckets.get(k).push(s);
  }
  const tune = [], test = [];
  for (const k of [...buckets.keys()].sort()) {
    const group = buckets.get(k).slice().sort((a, b) => String(a.id).localeCompare(String(b.id)));
    group.forEach((s, i) => (i % 2 === 0 ? tune : test).push(s));
  }
  return { tune, test };
}

const data = JSON.parse(readFileSync(SRC, "utf8"));
const a = stratify(data.attacks || []);
const b = stratify(data.benign || []);

const mix = (rows, key) => {
  const m = {};
  for (const r of rows) m[r[key] || "-"] = (m[r[key] || "-"] || 0) + 1;
  return m;
};

console.log(`attacks  tune=${a.tune.length}  test=${a.test.length}`);
console.log(`benign   tune=${b.tune.length}  test=${b.test.length}`);
console.log(`family mix  tune=${JSON.stringify(mix(a.tune, "family"))}`);
console.log(`family mix  test=${JSON.stringify(mix(a.test, "family"))}`);

if (process.argv.includes("--check")) process.exit(0);

writeFileSync(join(ROOT, "test/redteam/heldout-v2-tune.json"), JSON.stringify({
  _comment: "TUNE half of heldout-v2 (stratified by family+axis). A tuning wave MAY optimize against this.",
  attacks: a.tune, benign: b.tune
}, null, 2) + "\n");

writeFileSync(join(ROOT, "test/redteam/heldout-v2-test.json"), JSON.stringify({
  _comment: "LOCKED TEST half of heldout-v2 (stratified by family+axis). NEVER tune against this file — it is the only remaining valid generalization measure. Scored by the orchestrator only.",
  attacks: a.test, benign: b.test
}, null, 2) + "\n");

console.log("wrote test/redteam/heldout-v2-tune.json and test/redteam/heldout-v2-test.json");
