#!/usr/bin/env node
// MoorAI — PRE-INSTALL skill gate. Point it at a skill / agent artifact on disk (a directory, a
// SKILL.md, a .mcp.json, a .claude/agents/*.md …) BEFORE you install it and get a CONTENT-FREE verdict
// derived from MoorAI's own shipped detection engine. On-device, no server, no account, nothing leaves
// the machine — and NO external scanner is bundled or invoked.
//
//   node cli/moorai-scan.mjs <path>                       # JSON (default)
//   node cli/moorai-scan.mjs <path> --format md           # Markdown report
//   node cli/moorai-scan.mjs <path> --fail-on caution     # tune the CI exit-code threshold
//   node cli/moorai-scan.mjs --help
//   npm run scan -- <path>
//
// EXIT CODE (for CI): 0 when the verdict is below the fail threshold, non-zero at or above it. The
// default threshold is REVIEW, so CLEAN/CAUTION exit 0 and REVIEW/DO-NOT-INSTALL exit non-zero.
//
// ENROLLMENT: none required. You scan BEFORE install, possibly before enrolling, so the engine runs on
// the built-in default policy ({}) and contentHash falls back to the non-correlatable NO_KEY sentinel.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scanPath, VERDICT_RANK } from "./scan-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const VERSION = (() => { try { return JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version; } catch { return "0"; } })();

// --fail-on <tier>: the WEAKEST verdict that still fails the run. Aliases fold onto the four verdicts.
const FAIL_ON = { clean: 0, caution: 1, notify: 1, review: 2, ask: 2, "do-not-install": 3, "donotinstall": 3, block: 3, deny: 3 };
const DEFAULT_FAIL_ON = "review";

const HELP = `moorai-scan — content-free PRE-INSTALL skill gate for AI coding-agent artifacts.

Usage:
  moorai-scan <path> [--format json|md] [--fail-on clean|caution|review|do-not-install]
  moorai-scan --help

  <path>        a directory OR a single file (SKILL.md, .mcp.json, .claude/agents/*.md, CLAUDE.md, …).
  --format      json (default) or md (a human-readable report).
  --fail-on     the weakest verdict that still exits non-zero (default: review).

What it does — using MoorAI's OWN shipped engine, no external scanner:
  1. Walks the path and classifies each file's skill-surface KIND (SKILL.md, .mcp.json, agents, …).
  2. Runs the detection engine over each text file at stage "file" (and "tool" for JSON MCP configs).
  3. Derives a VERDICT from the engine's own allow/ask/deny decisions — no invented 0-100 score:
       any deny  → DO-NOT-INSTALL      any ask → REVIEW
       only low findings → CAUTION     nothing → CLEAN
     The reported verdict is the WORST across all files.

Verdict → exit code (default --fail-on review):
  CLEAN / CAUTION            exit 0
  REVIEW                     exit 1
  DO-NOT-INSTALL             exit 2

CONTENT-FREE by construction: each finding emits only { relativePath, surfaceKind, threatId, category,
intentLabels, contentHash, tier }. Never the matched text, never file contents, never an absolute path.
No enrollment is required; without an install token contentHash is the non-correlatable "h2:nokey".
`;

function toMarkdown(r) {
  const s = r.summary;
  const badge = { CLEAN: "✅ CLEAN", CAUTION: "🟡 CAUTION", REVIEW: "🟠 REVIEW", "DO-NOT-INSTALL": "🔴 DO-NOT-INSTALL" }[r.verdict];
  let out = `# MoorAI — pre-install skill scan\n\n`
    + `**Verdict:** ${badge}  ·  **Target:** ${r.target}  ·  **Scope:** this artifact only\n\n`
    + `Content-free — threat ids, categories, and intent labels only. No matched text, no file contents.\n\n`
    + `| Files | Scanned | Skipped | Surfaces | Findings | Block | Justify | Notify |\n|---|---|---|---|---|---|---|---|\n`
    + `| ${s.filesTotal} | ${s.filesScanned} | ${s.filesSkipped} | ${s.surfaces} | ${s.findings} | ${s.byTier.block} | ${s.byTier.justify} | ${s.byTier.notify} |\n`;
  if (r.drivers.length) out += `\n**Driven by:** ${r.drivers.join(", ")}\n`;
  const flagged = r.files.filter((f) => f.findings.length);
  if (flagged.length) {
    out += `\n## Findings\n\n| File | Kind | Threat | Category | Intent | Tier | Correlation |\n|---|---|---|---|---|---|---|\n`;
    for (const f of flagged) for (const g of f.findings)
      out += `| ${g.relativePath} | ${g.surfaceKind || "—"} | #${g.threatId} | ${g.category} | ${g.intentLabels.join(" · ") || "—"} | ${g.tier} | ${g.contentHash} |\n`;
  } else {
    out += `\nNo findings.\n`;
  }
  out += `\n---\nGenerated on-device by MoorAI (v${VERSION}). Content-free pre-install gate — not a certification.\n`;
  return out;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }

  const fmt = argv.includes("--format") ? argv[argv.indexOf("--format") + 1] : "json";
  const failOnRaw = argv.includes("--fail-on") ? String(argv[argv.indexOf("--fail-on") + 1] || "").toLowerCase() : DEFAULT_FAIL_ON;
  const failRank = FAIL_ON[failOnRaw];
  if (failRank === undefined) { process.stderr.write(`moorai-scan: unknown --fail-on '${failOnRaw}' (use clean|caution|review|do-not-install)\n`); process.exit(64); }

  const path = argv.find((a, i) => !a.startsWith("-") && argv[i - 1] !== "--format" && argv[i - 1] !== "--fail-on");
  if (!path) { process.stderr.write("moorai-scan: missing <path>\nTry: moorai-scan --help\n"); process.exit(64); }

  let report;
  try {
    report = scanPath(path, { policy: {} });
  } catch (e) {
    process.stderr.write(`moorai-scan: cannot scan '${path}': ${e && e.message ? e.message : e}\n`);
    process.exit(66);
  }

  const doc = { tool: "moorai-scan", specVersion: "1.0", version: VERSION, generatedAt: new Date().toISOString(), failOn: failOnRaw, ...report };
  process.stdout.write(fmt === "md" ? toMarkdown(report) : JSON.stringify(doc, null, 2) + "\n");

  const fail = VERDICT_RANK[report.verdict] >= failRank;
  process.exit(fail ? (report.verdict === "DO-NOT-INSTALL" ? 2 : 1) : 0);
}

main();
