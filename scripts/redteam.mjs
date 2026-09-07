#!/usr/bin/env node
// Red-team the on-device detection engine against an adversarial corpus (test/redteam/corpus.json).
// Scores multilingual prompt injection, multi-turn jailbreaks, license/copyright, and the DLP
// detectors, and guards against false positives on benign prompts. Exits non-zero on any miss that is
// not in the accepted-failure baseline (scripts/accepted-failures.mjs) — wire it into CI so detection
// coverage can't silently regress.
//
//   npm run redteam
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { classifyFailures, reportAcceptedFailures } from "./accepted-failures.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const corpus = JSON.parse(readFileSync(join(ROOT, "test/redteam/corpus.json"), "utf8"));
const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);

const g = (s) => `\x1b[32m${s}\x1b[0m`;
const r = (s) => `\x1b[31m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

let pass = 0;
const fails = [];

for (const c of corpus.cases) {
  const findings = c.turns
    ? engine.scanSession(c.turns)
    : engine.scan(c.text, c.stage || "prompt");
  const ids = new Set(findings.map((f) => f.threat.id));

  let ok;
  if (c.none) ok = findings.length === 0;
  else ok = ids.has(c.expect);

  if (ok) {
    pass++;
  } else {
    fails.push({
      id: c.id,
      why: c.none
        ? `expected no findings, got [${[...ids].join(",")}]`
        : `expected threat #${c.expect}, got [${[...ids].join(",") || "none"}]`
    });
  }
}

const total = corpus.cases.length;
const cls = classifyFailures(fails.map((f) => f.id), corpus.cases.map((c) => c.id));
const unexpected = new Set(cls.unexpected);

console.log(`\n\x1b[1mRed-team: ${pass}/${total} passed\x1b[0m  ${dim(`(${DETECTORS.length} detectors, ${threats.threats.length} threats)`)}`);
for (const f of fails) if (unexpected.has(f.id)) console.log(`  ${r("✗")} ${f.id} — ${f.why}`);
// An accepted miss still prints (as `!`, with its reason) and still counts against 101/102 — it is
// never rendered as a pass. Only an UNLISTED miss, or a listed one that has started passing, is red.
const clean = reportAcceptedFailures(cls);
if (clean) console.log(`  ${g("✓ all detection expectations met")}${cls.expected.length ? dim(` (${cls.expected.length} accepted known failure${cls.expected.length > 1 ? "s" : ""})`) : ""}`);
process.exit(clean ? 0 : 1);
