#!/usr/bin/env node
// Scores cli/claim-check.mjs against a hand-labelled corpus. Each case's calls become the ledger rows the
// hook would have written, then assessTurn decides.
//   node scripts/score-claim-check.mjs [--corpus v2|legacy] [--split all|tune|locked|heldout] [--json] [--verbose]
// v2 (default, test/fixtures/claim-check-corpus-v2.json): labelled blind by agents that never read the
//   detector; every case carries a fixed-seed `split` — tune (60%, the only cases rules may be adjusted
//   against) or locked (40%, scored once). --verbose never lists locked or whole-corpus errors.
// legacy (test/fixtures/claim-check-corpus.json, 75 cases): a regression set; tune = odd ids, heldout =
//   even ids (that held-out half was spent by the v1.1.0 tuning).
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { assessTurn, commandClass, normalizeCommand, verifyFamily } from "../cli/claim-check.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FILES = { v2: "claim-check-corpus-v2.json", legacy: "claim-check-corpus.json" };
const corpusOf = (name) => JSON.parse(readFileSync(join(ROOT, "test", "fixtures", FILES[name]), "utf8"));
const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };

export function rowsOf(calls) {
  return (calls || []).map((c) => {
    const shell = c.tool === "Bash" || c.tool === "PowerShell";
    const cls = shell ? commandClass(c.command) : "other";
    const k = shell ? normalizeCommand(c.command) : c.tool; const fam = shell ? verifyFamily(c.command) : "";
    if (c.outcome === "denied") return { ev: "pre", decision: "deny", tool: c.tool, cls, fam, k };
    return { ev: c.outcome === "ok" ? "post" : "fail", tool: c.tool, cls, fam, k, outcome: c.outcome, ...(Number.isInteger(c.exit) ? { exit: c.exit } : {}) };
  });
}
function inSplit(c, split, corpus) {
  if (split === "all") return true;
  if (corpus === "legacy") { const n = Number(String(c.id).replace(/\D/g, "")); return split === "tune" ? n % 2 === 1 : n % 2 === 0; }
  return c.split === split;
}
export function score(split = "all", corpus = "v2") {
  const cases = corpusOf(corpus).filter((c) => inSplit(c, split, corpus));
  const m = { tp: 0, fp: 0, fn: 0, tn: 0 }, errors = [];
  for (const c of cases) {
    const r = assessTurn(rowsOf(c.calls), c.message);
    const want = c.expected === "flag";
    const k = r.flagged ? (want ? "tp" : "fp") : (want ? "fn" : "tn");
    m[k]++;
    if (k === "fp" || k === "fn") errors.push({ id: c.id, kind: k, category: c.category, claim: r.claim, caveat: r.caveat, last: r.lastOutcome, unresolved: r.unresolved });
  }
  const precision = m.tp + m.fp ? m.tp / (m.tp + m.fp) : 1, recall = m.tp + m.fn ? m.tp / (m.tp + m.fn) : 1;
  return { corpus, split, n: cases.length, ...m, precision, recall, errors };
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const corpus = arg("--corpus", "v2");
  const s = score(arg("--split", "all"), corpus);
  const showErrors = process.argv.includes("--verbose") && (corpus === "legacy" || s.split === "tune");
  if (corpus === "v2" && s.split !== "tune") s.errors = s.errors.map(() => "(hidden: only the tune split's errors may be read)");
  if (process.argv.includes("--json")) { console.log(JSON.stringify(s, null, 2)); process.exit(0); }
  console.log(`claim-check corpus ${s.corpus} (${s.split}): n=${s.n}`);
  console.log(`                 labelled flag   labelled no-flag`);
  console.log(`  flagged        TP ${String(s.tp).padEnd(12)} FP ${s.fp}`);
  console.log(`  not flagged    FN ${String(s.fn).padEnd(12)} TN ${s.tn}`);
  console.log(`  precision ${(s.precision * 100).toFixed(1)}%   recall ${(s.recall * 100).toFixed(1)}%`);
  if (showErrors) for (const e of s.errors) console.log(`  ${e.kind} ${e.id} [${e.category ?? ""}] claim=${e.claim} caveat=${e.caveat} last=${e.last} unresolved=${e.unresolved}`);
}
