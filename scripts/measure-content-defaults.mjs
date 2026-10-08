#!/usr/bin/env node
// Prices the built-in NSFW content default (data/content-defaults.js): how often the default categories
// fire on content that should stay silent. Content rules are not part of scripts/score-benign-v2.mjs
// (it scores the threat engine only), so the default needs its own number.
//
//   node scripts/measure-content-defaults.mjs                 # repo corpora + hard negatives
//   node scripts/measure-content-defaults.mjs --dir <path>    # also every md/js/mjs/py/ts file under <path>
//
// Content-free output: counts per category and the matched keyword, never a sample's text.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { CONTENT_RULES } from "../data/content-rules.js";
import { NSFW_CONTENT_RULES } from "../data/content-defaults.js";
import { DetectionEngine } from "../src/engine.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const engine = new DetectionEngine({ threats: [] }, [], CONTENT_RULES);
const rd = (p) => JSON.parse(readFileSync(join(ROOT, p), "utf8"));

function measure(label, rows) {
  let hit = 0; const per = {}, kw = {};
  for (const t of rows) {
    const h = engine.scanContent(t, [...NSFW_CONTENT_RULES]);
    if (h.length) hit++;
    for (const c of h) { per[c.ruleId] = (per[c.ruleId] || 0) + 1; const k = `${c.ruleId}:${c.match.toLowerCase()}`; kw[k] = (kw[k] || 0) + 1; }
  }
  const top = Object.entries(kw).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, n]) => `${k}×${n}`).join(" ");
  console.log(`${label}: ${hit}/${rows.length} (${rows.length ? ((100 * hit) / rows.length).toFixed(2) : "0"}%) ${JSON.stringify(per)}${top ? "  " + top : ""}`);
}

const corpora = [];
for (const f of ["benign-corpus-v2.json", "benign-corpus.json", "benign-hebrew.json", "benign-arabic.json", "benign-russian.json", "heldout-v2-tune.json", "vector2-indirect-content.json", "vector3-supply-chain.json", "vector4-outbound-action.json", "vector5-memory-crossagent.json"]) {
  for (const s of rd(`test/redteam/${f}`).benign || []) if (typeof s.text === "string") corpora.push(s.text);
}
console.log(`NSFW default categories: ${NSFW_CONTENT_RULES.join(", ")}`);
measure("benign corpora (v2, v1, he/ar/ru, heldout-v2 TUNE, vector2-5 benign)", corpora);
measure("benign-web-content TUNE half", rd("test/redteam/benign-web-content.json").samples.filter((s) => s.split === "tune" && !s.shouldDetect).map((s) => s.text));
measure("hard negatives (medical / biology / security / devops / history)", rd("test/fixtures/content-defaults/hard-negatives.json").samples.map((s) => s.text));

const i = process.argv.indexOf("--dir");
if (i > 0) {
  const files = [];
  const walk = (d, depth) => {
    if (depth > 6) return;
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.name === "node_modules" || e.name === ".git" || e.name === "worktrees" || e.name === "dist") continue;
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p, depth + 1);
      else if (/\.(md|js|mjs|py|ts)$/.test(e.name) && !e.name.endsWith(".min.js") && statSync(p).size < 512 * 1024) files.push(p);
    }
  };
  walk(process.argv[i + 1], 0);
  measure(`files under ${process.argv[i + 1]}`, files.map((p) => { try { return readFileSync(p, "utf8"); } catch { return ""; } }));
}
