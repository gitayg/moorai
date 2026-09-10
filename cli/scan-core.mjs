// moorai-scan CORE — the PRE-INSTALL skill gate, kept separate from the stdin/argv entrypoint
// (cli/moorai-scan.mjs) so the walk + classify + verdict logic is unit-testable without spawning a
// process. This is MoorAI's on-device answer to a cloud "skill scanner": you point it at a skill /
// agent artifact on disk BEFORE installing it and get a content-free verdict.
//
// EVERY detection decision here is MoorAI's OWN SHIPPED engine — buildEngine + decideText from
// hook-core, skillSurfaceKind from data/skill-surface, skillIntents from skill-analysis. There is NO
// second detector and NO invented 0-100 score: the verdict is derived from the engine's allow/ask/deny
// decisions, so an org policy and detector packs govern it exactly as they govern the live hook.
//
// CONTENT-FREE BY CONSTRUCTION: a finding carries only {relativePath, surfaceKind, threatId, category,
// intentLabels, contentHash, tier}. Never the matched text, never a snippet, never the file's contents,
// and never an absolute path (only paths relative to the scanned root). That is the whole point vs a
// cloud scanner that ships file contents off the box to an LLM — the scanner must not itself become an
// exfiltration channel. test/scan.test.mjs plants a canary and asserts it.

import { readFileSync, readdirSync, statSync, lstatSync } from "node:fs";
import { join, relative, basename, dirname } from "node:path";
import { buildEngine, decideText, threatActionFor } from "./hook-core.mjs";
import { skillIntents } from "./skill-analysis.mjs";
import { contentHash } from "./content-hash.mjs";
import { skillSurfaceKind } from "../data/skill-surface.js";

// Worst-first order. The overall verdict is the WORST across every scanned file.
export const VERDICTS = ["CLEAN", "CAUTION", "REVIEW", "DO-NOT-INSTALL"];
export const VERDICT_RANK = { CLEAN: 0, CAUTION: 1, REVIEW: 2, "DO-NOT-INSTALL": 3 };

// Finding tiers, mirroring the engine's action semantics: block/kill → block, justify → justify,
// everything reported-but-allowed (notify/alert) → notify.
export const TIERS = ["notify", "justify", "block"];

const DECISION_RANK = { allow: 1, ask: 2, deny: 3 };
const MAX_BYTES = 2 * 1024 * 1024;   // don't read anything bigger — a skill artifact is small
const NUL_SNIFF = 8000;              // a NUL byte in the first 8 KB ⇒ treat as binary (count, don't scan)

// The engine's per-finding action → the tier we report and count on.
export function tierOf(action) {
  if (action === "block" || action === "kill") return "block";
  if (action === "justify") return "justify";
  return "notify";
}

// decideText's decision (+ whether it found anything) → a single-file verdict.
export function decisionToVerdict(decision, findingCount) {
  if (decision === "deny") return "DO-NOT-INSTALL";
  if (decision === "ask") return "REVIEW";
  return findingCount > 0 ? "CAUTION" : "CLEAN";
}

export function worseVerdict(a, b) {
  return VERDICT_RANK[a] >= VERDICT_RANK[b] ? a : b;
}
function worseDecision(a, b) {
  return DECISION_RANK[a] >= DECISION_RANK[b] ? a : b;
}

function isBinary(buf) {
  const n = Math.min(buf.length, NUL_SNIFF);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

// Collect every STRING leaf value out of parsed JSON, joined — the MCP "tool descriptor" surface
// (server command/args/env keys, tool names + descriptions) that the mcp-tool-poisoning family of
// detectors declares the "tool" stage for. Returns null when the text is not JSON or holds no strings,
// so a non-JSON surface simply skips the extra tool-stage pass. Content is never retained or returned
// by the caller — only the resulting content-free findings are.
export function jsonStrings(text) {
  let j;
  try { j = JSON.parse(text); } catch { return null; }
  const out = [];
  const walk = (v) => {
    if (typeof v === "string") { if (v.trim()) out.push(v); }
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") { for (const k of Object.keys(v)) { out.push(k); walk(v[k]); } }
  };
  walk(j);
  return out.length ? out.join("\n") : null;
}

// Union findings from two stage passes by threatId (first wins). decideText findings are
// {threatId, category, riskLevel, match}; we keep `match` ONLY to derive the content-free contentHash,
// and it is dropped before anything leaves this module.
function mergeFindings(a, b) {
  const seen = new Set(a.map((f) => f.threatId));
  const out = a.slice();
  for (const f of b) if (!seen.has(f.threatId)) { seen.add(f.threatId); out.push(f); }
  return out;
}

// Scan ONE already-read text blob. Runs the engine at stage "file" (which re-runs the prompt/index
// detectors too, per DetectionEngine._wantStages) and, for a JSON config, additionally at stage "tool"
// over the extracted descriptor strings. Returns the content-free findings + the file verdict.
export function scanFileText({ engine, policy, text, relativePath, surfaceKind }) {
  const fileDec = decideText(engine, policy, text, "file");
  let decision = fileDec.decision;
  let raw = fileDec.findings;

  const toolText = jsonStrings(text);
  if (toolText) {
    const toolDec = decideText(engine, policy, toolText, "tool");
    decision = worseDecision(decision, toolDec.decision);
    raw = mergeFindings(raw, toolDec.findings);
  }

  const intentLabels = skillIntents(text, raw);
  const findings = raw.map((f) => ({
    relativePath,
    surfaceKind,
    threatId: f.threatId,
    category: f.category,
    intentLabels,
    contentHash: contentHash(f.match),   // hashed, never the span itself; NO_KEY when unenrolled
    tier: tierOf(threatActionFor(policy, f.threatId))
  }));

  return { decision, verdict: decisionToVerdict(decision, findings.length), findings };
}

// Depth-first walk that never follows symlinks (loop-safe) and skips .git. Returns absolute file paths.
function walkFiles(root) {
  const out = [];
  const recurse = (dir) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name === ".git") continue;
      const full = join(dir, e.name);
      let st;
      try { st = lstatSync(full); } catch { continue; }
      if (st.isSymbolicLink()) continue;      // never traverse or read a symlink target
      if (st.isDirectory()) recurse(full);
      else if (st.isFile()) out.push(full);
    }
  };
  recurse(root);
  return out;
}

// The whole gate. `target` is a directory OR a single file. Everything is relative to `root`: for a
// directory that is the directory itself; for a single file it is the file's parent, so the emitted
// relativePath is just the basename and no home/dir layout leaks.
export function scanPath(target, { policy = {}, engine = null } = {}) {
  const eng = engine || buildEngine(policy);
  const st = statSync(target);                // throws if the path doesn't exist — the caller reports it
  const isDir = st.isDirectory();
  const root = isDir ? target : dirname(target);
  const files = isDir ? walkFiles(target) : [target];

  const results = [];
  let filesScanned = 0, filesSkipped = 0;
  let verdict = "CLEAN";
  const byTier = { block: 0, justify: 0, notify: 0 };
  const allFindings = [];

  for (const full of files) {
    const rel = isDir ? relative(root, full) : basename(full);
    const surfaceKind = skillSurfaceKind(rel);

    let skip = null, text = null;
    try {
      const size = statSync(full).size;
      if (size > MAX_BYTES) skip = "large";
      else {
        const buf = readFileSync(full);
        if (isBinary(buf)) skip = "binary";
        else text = buf.toString("utf8");
      }
    } catch { skip = "unreadable"; }

    if (skip) {
      filesSkipped++;
      results.push({ relativePath: rel, surfaceKind, scanned: false, skipped: skip, verdict: "CLEAN", decision: "allow", findings: [] });
      continue;
    }

    filesScanned++;
    const r = scanFileText({ engine: eng, policy, text, relativePath: rel, surfaceKind });
    for (const f of r.findings) { byTier[f.tier]++; allFindings.push(f); }
    verdict = worseVerdict(verdict, r.verdict);
    results.push({ relativePath: rel, surfaceKind, scanned: true, decision: r.decision, verdict: r.verdict, findings: r.findings });
  }

  const drivers = results.filter((f) => f.scanned && f.verdict === verdict && VERDICT_RANK[verdict] > 0).map((f) => f.relativePath).sort();

  return {
    target: basename(target) || target,
    isDirectory: isDir,
    verdict,
    summary: {
      filesTotal: files.length,
      filesScanned,
      filesSkipped,
      surfaces: results.filter((r) => r.surfaceKind).length,
      findings: allFindings.length,
      byTier
    },
    drivers,
    files: results
  };
}
