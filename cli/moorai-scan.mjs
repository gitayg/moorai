#!/usr/bin/env node
// MoorAI — PRE-INSTALL skill gate. Point it at a skill / agent artifact on disk (a directory, a
// SKILL.md, a .mcp.json, a .claude/agents/*.md …) BEFORE you install it and get a CONTENT-FREE verdict
// derived from MoorAI's own shipped detection engine. On-device, no server, no account, nothing leaves
// the machine — and NO external scanner is bundled or invoked.
//
//   node cli/moorai-scan.mjs <path>                       # JSON (default)
//   node cli/moorai-scan.mjs <path> --format md           # Markdown report
//   node cli/moorai-scan.mjs <path> --fail-on caution     # tune the CI exit-code threshold
//   node cli/moorai-scan.mjs <path> --packages            # also fetch + analyse the MCP server packages (network, opt-in)
//   node cli/moorai-scan.mjs --package npm:@scope/pkg@1.2.3  # analyse one registry package, no config file
//   node cli/moorai-scan.mjs --package github:owner/repo/skills/x[@ref]  # analyse one GitHub-hosted skill
//   node cli/moorai-scan.mjs --package github:owner/repo[@ref]           # analyse a whole source repository
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
import { VERDICT_RANK } from "./scan-core.mjs";
import { scanPathWithPackages, scanPackageArg, packagesEnabled } from "./mcp-package.mjs";
import { renderPackagesMarkdown } from "./mcp-package/report.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const VERSION = (() => { try { return JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version; } catch { return "0"; } })();

// --fail-on <tier>: the WEAKEST verdict that still fails the run. Aliases fold onto the four verdicts.
const FAIL_ON = { clean: 0, caution: 1, notify: 1, review: 2, ask: 2, "do-not-install": 3, "donotinstall": 3, block: 3, deny: 3 };
const DEFAULT_FAIL_ON = "review";

const HELP = `moorai-scan — content-free PRE-INSTALL skill gate for AI coding-agent artifacts.

Usage:
  moorai-scan <path> [--packages] [--cache-dir <dir>] [--format json|md] [--fail-on …]
  moorai-scan --package npm:<name>[@version] | pypi:<name>[==version] | github:<owner>/<repo>[/<path>][@ref]
              [--cache-dir <dir>] [--format json|md]
  moorai-scan --help

  <path>        a directory OR a single file (SKILL.md, .mcp.json, .claude/agents/*.md, CLAUDE.md, …).
  --format      json (default) or md (a human-readable report).
  --fail-on     the weakest verdict that still exits non-zero (default: review).
  --packages    ALSO download and analyse the npm / PyPI package each MCP server config launches
                (npx, pnpm dlx, bunx, yarn dlx, uvx, uv tool run, pipx run). Same as MOORAI_SCAN_PACKAGES=1.
                Only the package name + version is sent, to registry.npmjs.org / pypi.org. Without it the
                packages are still resolved and listed as "not analysed".
  --package     analyse a single registry package, GitHub-hosted skill, or source repository directly
                (implies network). github: downloads the public repo tarball from codeload.github.com
                (default branch, or @ref) and scans either only <path> (as a skill: SKILL.md + bundled
                scripts) or, with no <path>, the WHOLE repository — the shape of an MCP server published
                only as source. .git/, node_modules/, vendor/, .venv/ and __pycache__/ are not extracted;
                lockfiles are not scanned. Only owner/repo/ref leave the device; a git archive has no
                registry digest, so the report carries the archive's commit and integrity "none".
  --cache-dir   cache package results by name@version + integrity.

Artifacts are STREAMED to a temp file, hashed while streaming (so the registry digest is still verified
end to end) and extracted from that file, so peak memory does not track archive size. Caps: 128 MB
compressed / 512 MB extracted / 10000 entries, overridable with MOORAI_SCAN_MAX_ARTIFACT_MB,
MOORAI_SCAN_MAX_REPO_MB, MOORAI_SCAN_MAX_EXTRACT_MB, MOORAI_SCAN_MAX_FILE_MB and
MOORAI_SCAN_MAX_ENTRIES. An archive over a cap reports "archive-limits-exceeded" (REVIEW), never a
clean verdict on a partial read — a large monorepo hits the entry cap and is REVIEW for that reason
alone, which is an unfinished scan and not a finding about the code.

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
  if (r.packages && r.packages.length) out += `\n` + renderPackagesMarkdown(r.packages);
  out += `\n---\nGenerated on-device by MoorAI (v${VERSION}). Content-free pre-install gate — not a certification.\n`;
  return out;
}

function argValue(argv, flag) {
  const i = argv.indexOf(flag);
  return i >= 0 ? argv[i + 1] : undefined;
}

const VALUE_FLAGS = new Set(["--format", "--fail-on", "--package", "--cache-dir"]);

async function main() {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }

  const fmt = argValue(argv, "--format") || "json";
  const failOnRaw = argv.includes("--fail-on") ? String(argValue(argv, "--fail-on") || "").toLowerCase() : DEFAULT_FAIL_ON;
  const failRank = FAIL_ON[failOnRaw];
  if (failRank === undefined) { process.stderr.write(`moorai-scan: unknown --fail-on '${failOnRaw}' (use clean|caution|review|do-not-install)\n`); process.exit(64); }
  const cacheDir = argValue(argv, "--cache-dir") || null;
  const head = { tool: "moorai-scan", specVersion: "1.1", version: VERSION, generatedAt: new Date().toISOString(), failOn: failOnRaw };

  let report, doc, md;
  if (argv.includes("--package")) {
    const spec = argValue(argv, "--package");
    const entry = await scanPackageArg(spec, { cacheDir });
    if (!entry) { process.stderr.write(`moorai-scan: bad --package '${spec}' (use npm:<name>[@version], pypi:<name>[==version] or github:<owner>/<repo>[/<path>][@ref])\n`); process.exit(64); }
    report = { mode: "package", verdict: entry.verdict, packages: [entry] };
    doc = { ...head, ...report };
    md = `# MoorAI — pre-install package scan\n\n` + renderPackagesMarkdown(report.packages) + `\n---\nGenerated on-device by MoorAI (v${VERSION}). ${entry.ecosystem === "github" ? "Only the repository owner/name and ref were sent, to codeload.github.com." : "Only the package name and version were sent, to the public registry."}\n`;
  } else {
    const path = argv.find((a, i) => !a.startsWith("-") && !VALUE_FLAGS.has(argv[i - 1]));
    if (!path) { process.stderr.write("moorai-scan: missing <path>\nTry: moorai-scan --help\n"); process.exit(64); }
    try {
      report = await scanPathWithPackages(path, { policy: {}, packages: packagesEnabled(argv, process.env), cacheDir });
    } catch (e) {
      process.stderr.write(`moorai-scan: cannot scan '${path}': ${e && e.message ? e.message : e}\n`);
      process.exit(66);
    }
    doc = { ...head, ...report };
    md = toMarkdown(report);
  }

  process.stdout.write(fmt === "md" ? md : JSON.stringify(doc, null, 2) + "\n");

  const fail = VERDICT_RANK[report.verdict] >= failRank;
  process.exit(fail ? (report.verdict === "DO-NOT-INSTALL" ? 2 : 1) : 0);
}

main();
