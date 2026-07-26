#!/usr/bin/env node
// MoorAI — secrets-exposure ledger (#5) + intent log (#15) viewer. Summarizes the on-device,
// content-free logs the hook and guard append when a credential/secret class is exposed to an agent,
// or when a human overrides a finding and proceeds. Answers the first question of an incident:
// "which credential classes were exposed to which agent, on which device?" — so rotation is targeted,
// not a blanket burn-everything. Reads only local files; no server, no account, nothing leaves.
//
// Content-free by construction: every line is category + risk + stage + tool + identity + a one-way
// hash. There is no secret value, prompt, or matched span anywhere in these logs to display.
//
//   node cli/moorai-ledger.mjs                 # summary (default)
//   node cli/moorai-ledger.mjs --format md     # Markdown report
//   node cli/moorai-ledger.mjs --format json   # raw rollup
//   node cli/moorai-ledger.mjs --intent        # show the human-override intent log instead
//   node cli/moorai-ledger.mjs --help

import { readLedger, readIntent, LEDGER_PATH, INTENT_PATH } from "./signals.mjs";

const HELP = `MoorAI ledger — content-free secrets-exposure ledger + human-override intent log.

Usage:
  moorai-ledger [--format summary|md|json] [--intent]

Reads two on-device logs (never anything leaves the machine):
  ${LEDGER_PATH}   secret/credential exposures to agents (#5)
  ${INTENT_PATH}          human overrides / justifications (#15)

Every entry is content-free: category, risk level, stage, tool, device/user, and a
one-way hash. No secret value, prompt, or matched span is ever stored or shown.
`;

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }
const fmt = argv.includes("--format") ? argv[argv.indexOf("--format") + 1] : "summary";
const intentMode = argv.includes("--intent");

const rows = intentMode ? readIntent() : readLedger();

function rollup(rows, key) {
  const m = new Map();
  for (const r of rows) {
    // Intent rows carry `categories` (array of overridden categories); ledger rows carry `category`.
    const vals = key === "category" && Array.isArray(r.categories) ? (r.categories.length ? r.categories : ["—"]) : [r[key] || "—"];
    for (const v of vals) m.set(v, (m.get(v) || 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}

function summarize(rows) {
  return {
    entries: rows.length,
    firstSeen: rows[0]?.ts || null,
    lastSeen: rows[rows.length - 1]?.ts || null,
    byCategory: Object.fromEntries(rollup(rows, "category")),
    byTool: Object.fromEntries(rollup(rows, "tool")),
    byRisk: Object.fromEntries(rollup(rows, "riskLevel")),
    byDevice: Object.fromEntries(rollup(rows, "device"))
  };
}

function toMarkdown(rows, intent) {
  const s = summarize(rows);
  const title = intent ? "Human-override intent log" : "Secrets-exposure ledger";
  const unit = intent ? "override" : "exposure";
  const tbl = (label, pairs) => `\n### By ${label}\n\n| ${label} | ${unit}s |\n|---|---|\n` + (pairs.length ? pairs.map(([k, v]) => `| ${k} | ${v} |`).join("\n") : `| — | 0 |`) + "\n";
  return `# MoorAI — ${title}\n\n`
    + `Content-free, on-device. ${s.entries} ${unit}(s)`
    + (s.firstSeen ? `  ·  ${s.firstSeen} → ${s.lastSeen}` : "") + `\n\n`
    + `No secret value, prompt, or matched span is stored — only categories, risk, and one-way hashes.\n`
    + tbl(intent ? "overridden category" : "category", rollup(rows, "category"))
    + (intent ? "" : tbl("agent / tool", rollup(rows, "tool")))
    + (intent ? "" : tbl("risk level", rollup(rows, "riskLevel")))
    + tbl("device", rollup(rows, "device"))
    + `\n---\nRotate the credential classes above that map to real secrets; the hash lets you correlate to a specific event without ever exposing the value.\n`;
}

function toSummary(rows, intent) {
  const s = summarize(rows);
  const unit = intent ? "override" : "exposure";
  if (!s.entries) return `No ${unit}s recorded yet.\n(${intent ? INTENT_PATH : LEDGER_PATH})\n`;
  const line = (pairs) => pairs.map(([k, v]) => `    ${String(v).padStart(4)}  ${k}`).join("\n");
  return `MoorAI ${intent ? "intent log" : "exposure ledger"} — ${s.entries} ${unit}(s), ${s.firstSeen} → ${s.lastSeen}\n\n`
    + `  By ${intent ? "overridden category" : "category"}:\n${line(rollup(rows, "category"))}\n\n`
    + (intent ? "" : `  By agent / tool:\n${line(rollup(rows, "tool"))}\n\n`)
    + `  By device:\n${line(rollup(rows, "device"))}\n`;
}

if (fmt === "json") process.stdout.write(JSON.stringify(summarize(rows), null, 2) + "\n");
else if (fmt === "md") process.stdout.write(toMarkdown(rows, intentMode));
else process.stdout.write(toSummary(rows, intentMode));
