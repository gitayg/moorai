// Package-mode engine scoping. scanPath (scan-core) reads every file the way an AGENT would read a
// skill artifact: every stage, native tiers. A downloaded registry package is not that — most of it is
// code and docs that no agent auto-loads — so running the prompt-stage detectors over it at native tiers
// turned READMEs and bundled constants into public accusations. Here each file is classified and only the
// stages that mean something for that class run:
//
//   surface  a skill-surface file (SKILL.md, agents/*.md, hooks …) of a SKILL target — the text an agent
//            actually loads. Full engine; action threats keep their tier (see SKILL_NATIVE).
//   doc      README / markdown / text / PKG-INFO. Injection-style wording is worth naming, but prose is
//            not behaviour: stage "file", injection classes only, tier capped at notify (CAUTION).
//   data     JSON / YAML / TOML (package.json included). Only the tool-descriptor stage over the string
//            leaves (a poisoned description), capped at notify. Install scripts are the heuristics' job.
//   code     JS / TS / Python / shell. Behaviour is judged by heuristics.mjs, which reads code the way an
//            installer runs it. The engine adds only the tool-descriptor stage (tool descriptions live in
//            string literals, so comments are stripped first), capped at notify, plus the reverse-shell detector at its native tier —
//            a /dev/tcp or `nc -e` payload is concrete evidence in any file that can run.
//   skip     everything else (source maps, styles, images, lockfiles …).
//
// Engine findings of the same threat are reported once per package (the first path wins, code before
// docs), so a README that describes what the code does does not double-count it.

import { readFileSync, statSync } from "node:fs";
import { relative, basename } from "node:path";
import { decideText, threatActionFor } from "../hook-core.mjs";
import { tierOf, jsonStrings } from "../scan-core.mjs";
import { skillIntents } from "../skill-analysis.mjs";
import { contentHash } from "../content-hash.mjs";
import { skillSurfaceKind } from "../../data/skill-surface.js";
import { stripComments } from "./heuristics.mjs";

const MAX_BYTES = 2 * 1024 * 1024;
const NUL_SNIFF = 8000;
const CODE = /\.(m?js|cjs|jsx|m?ts|cts|tsx|py|sh|bash|zsh|ps1)$/i;
const DOC = /\.(md|markdown|mdx|txt|rst|adoc)$/i;
const DOC_NAME = /^(readme|authors|contributing|security|pkg-info|metadata)(\.|$)/i;
// Legal text and release notes are neither instructions nor behaviour.
const NOT_SCANNED = /^(license|licence|copying|notice|changelog|changes|history|news|third[-_]party[-_]notices?)(\.|$)/i;
const DATA = /\.(json|jsonc|ya?ml|toml|cfg|ini)$/i;
const LOCK = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|uv\.lock|Pipfile\.lock)$/i;
const REVERSE_SHELL = 54;
// In a skill's instruction files, the threats that describe something the instructions make the agent
// DO to this machine keep their native tier (reverse shell, credential-file reads, destructive commands /
// tool calls, unsanctioned installs, model-endpoint overrides). Secret-value egress is an entropy
// heuristic, so it is capped at justify. Data-classification and business-action detectors (PHI, PII,
// "deploys to prod", "sends email") describe what a prompt is ABOUT — for a skill that is its purpose,
// not a risk — so they are not reported; injection-style classes are reported at notify.
const SKILL_NATIVE = new Set([43, 54, 55, 56, 57, 63]);
const SKILL_JUSTIFY_CAP = new Set([65]);
const CLASS_ORDER = { surface: 0, code: 1, data: 2, doc: 3 };
// "Injection-style" = the OWASP LLM classes about text steering the model: prompt injection (LLM01),
// system-prompt extraction/leakage (LLM07), poisoned rules / invisible text (LLM08). In a README or a
// LICENSE, the data-classification detectors (licence text, legal language, e-mail addresses,
// "confidential") describe ordinary documentation, so a doc reports only these classes.
const INJECTION_OWASP = new Set(["LLM01", "LLM07", "LLM08"]);

export function fileClass(rel, { skill = false } = {}) {
  const name = basename(rel);
  if (CODE.test(name)) return "code";
  if (skill && skillSurfaceKind(rel)) return "surface";
  if (NOT_SCANNED.test(name)) return "skip";
  if (LOCK.test(rel)) return "skip";
  if (DOC.test(name) || DOC_NAME.test(name)) return "doc";
  if (DATA.test(name)) return "data";
  return "skip";
}

function readText(full) {
  try {
    if (statSync(full).size > MAX_BYTES) return { skip: "large" };
    const buf = readFileSync(full);
    const n = Math.min(buf.length, NUL_SNIFF);
    for (let i = 0; i < n; i++) if (buf[i] === 0) return { skip: "binary" };
    return { text: buf.toString("utf8") };
  } catch { return { skip: "unreadable" }; }
}

function toFindings(raw, text, relativePath, surfaceKind, policy, cap) {
  if (!raw.length) return [];
  const intentLabels = skillIntents(text, raw);
  return raw.map((f) => {
    const native = tierOf(threatActionFor(policy, f.threatId));
    let tier = "notify";
    if (cap === "shell" && f.threatId === REVERSE_SHELL) tier = native;
    else if (cap === "skill" && SKILL_NATIVE.has(f.threatId)) tier = native;
    else if (cap === "skill" && SKILL_JUSTIFY_CAP.has(f.threatId)) tier = native === "notify" ? "notify" : "justify";
    return {
      relativePath,
      surfaceKind,
      threatId: f.threatId,
      category: f.category,
      intentLabels,
      contentHash: contentHash(f.match),
      tier
    };
  });
}

// The same engine restricted to the detectors built for INGESTED content (stages file / index / tool).
// Prompt-only detectors score a short user prompt; over a multi-KB README they accumulate weak signals
// ("restriction" in a licence, "if you want to run") into findings. Detector packs carry over because
// the view shares the engine's threat table and only narrows its detector list.
const views = new WeakMap();
function view(engine, key, keep, { raw = false } = {}) {
  let m = views.get(engine);
  if (!m) views.set(engine, (m = new Map()));
  if (!m.has(key)) {
    const v = Object.create(engine);
    v.detectors = engine.detectors.filter(keep);
    if (raw) v._scanNormalized = () => {};
    m.set(key, v);
  }
  return m.get(key);
}
const ingestView = (engine) => view(engine, "ingest", (d) => (d.stages || [d.stage]).some((s) => s === "file" || s === "index" || s === "tool"));
// Only the reverse-shell detector — `decideText(..., {only})` would still run every prompt detector —
// and without the decode pre-pass, which the tool-stage pass over the same file already ran (encoded
// payloads in code are the obfuscation heuristics' job).
const shellView = (engine) => view(engine, "shell", (d) => d.threatId === REVERSE_SHELL, { raw: true });

function engineFindings(engine, policy, text, cls, name) {
  if (cls === "surface") {
    const a = decideText(engine, policy, text, "file").findings;
    const js = jsonStrings(text);
    const b = js ? decideText(engine, policy, js, "tool").findings : [];
    const raw = [...a, ...b.filter((f) => !a.some((x) => x.threatId === f.threatId))]
      .filter((f) => SKILL_NATIVE.has(f.threatId) || SKILL_JUSTIFY_CAP.has(f.threatId) || INJECTION_OWASP.has(engine.threat(f.threatId)?.owasp));
    return { raw, cap: "skill" };
  }
  if (cls === "doc") {
    const raw = decideText(ingestView(engine), policy, text, "file").findings.filter((f) => INJECTION_OWASP.has(engine.threat(f.threatId)?.owasp));
    return { raw, cap: "notify" };
  }
  if (cls === "data") {
    const js = jsonStrings(text);
    return { raw: decideText(engine, policy, js || text, "tool").findings, cap: "notify" };
  }
  // Tool descriptions are string literals; a comment that mentions "system" or "prompt" is not one.
  const tool = decideText(engine, policy, stripComments(text, name), "tool").findings;
  const shell = decideText(shellView(engine), policy, text, "prompt", { only: [REVERSE_SHELL] }).findings;
  return { raw: [...tool, ...shell], cap: "shell" };
}

// → {findings, filesScanned, filesSkipped, surfaces}
export function scanPackageFiles(root, files, { engine, policy = {}, skill = false } = {}) {
  const rows = [];
  let filesScanned = 0, filesSkipped = 0, surfaces = 0;
  for (const full of files) {
    const rel = relative(root, full).split("\\").join("/");
    const cls = fileClass(rel, { skill });
    const surfaceKind = skillSurfaceKind(rel);
    if (surfaceKind) surfaces++;
    if (cls === "skip") { filesSkipped++; continue; }
    const r = readText(full);
    if (r.skip) { filesSkipped++; continue; }
    filesScanned++;
    if (!r.text.trim()) continue;
    const { raw, cap } = engineFindings(engine, policy, r.text, cls, basename(rel));
    for (const f of toFindings(raw, r.text, rel, surfaceKind, policy, cap)) rows.push({ cls, f });
  }
  rows.sort((a, b) => CLASS_ORDER[a.cls] - CLASS_ORDER[b.cls]);
  const seen = new Set();
  const findings = [];
  for (const { cls, f } of rows) {
    const key = cls === "surface" || f.tier !== "notify" ? `${f.threatId}\0${f.relativePath}` : `${f.threatId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(f);
  }
  return { findings, filesScanned, filesSkipped, surfaces };
}
