#!/usr/bin/env node
// Scores cli/claim-check.mjs against the hand-labelled corpus test/fixtures/claim-check-corpus.json.
// Each case's calls become the ledger rows the hook would have written, then assessTurn decides.
//   node scripts/score-claim-check.mjs [--split all|tune|heldout] [--json] [--verbose]
// tune = odd-numbered ids (the only half rules may be adjusted against); heldout = even-numbered ids.
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { assessTurn, commandClass, normalizeCommand, verifyFamily } from "../cli/claim-check.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS = JSON.parse(readFileSync(join(ROOT, "test", "fixtures", "claim-check-corpus.json"), "utf8"));
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
export function score(split = "all") {
  const num = (id) => Number(String(id).replace(/\D/g, ""));
  const cases = CORPUS.filter((c) => split === "all" || (split === "tune" ? num(c.id) % 2 === 1 : num(c.id) % 2 === 0));
  const m = { tp: 0, fp: 0, fn: 0, tn: 0 }, errors = [];
  for (const c of cases) {
    const r = assessTurn(rowsOf(c.calls), c.message);
    const want = c.expected === "flag";
    const k = r.flagged ? (want ? "tp" : "fp") : (want ? "fn" : "tn");
    m[k]++;
    if (k === "fp" || k === "fn") errors.push({ id: c.id, kind: k, claim: r.claim, caveat: r.caveat, last: r.lastOutcome, unresolved: r.unresolved });
  }
  const precision = m.tp + m.fp ? m.tp / (m.tp + m.fp) : 1, recall = m.tp + m.fn ? m.tp / (m.tp + m.fn) : 1;
  return { split, n: cases.length, ...m, precision, recall, errors };
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const s = score(arg("--split", "all"));
  if (process.argv.includes("--json")) { console.log(JSON.stringify(s, null, 2)); process.exit(0); }
  console.log(`claim-check corpus (${s.split}): n=${s.n}`);
  console.log(`                 labelled flag   labelled no-flag`);
  console.log(`  flagged        TP ${String(s.tp).padEnd(12)} FP ${s.fp}`);
  console.log(`  not flagged    FN ${String(s.fn).padEnd(12)} TN ${s.tn}`);
  console.log(`  precision ${(s.precision * 100).toFixed(1)}%   recall ${(s.recall * 100).toFixed(1)}%`);
  if (process.argv.includes("--verbose")) for (const e of s.errors) console.log(`  ${e.kind} ${e.id} claim=${e.claim} caveat=${e.caveat} last=${e.last} unresolved=${e.unresolved}`);
}
