// MCP server PACKAGE analysis for `moorai scan`: the config says `npx -y some-server`, this looks at the
// code `some-server` actually is.
//
//   resolveMcpPackages(config)          offline — config → [{ecosystem, name, version} …]
//   analyzePackage(ref, opts)           OPT-IN network — STREAM the exact registry artifact to a temp
//                                       file while hashing it, verify its digest, extract it safely from
//                                       that file, run scanPath + package heuristics. Nothing larger
//                                       than one archive entry is ever resident, so a 33 MB package and
//                                       a 200 MB repository cost the same memory.
//   scanPathWithPackages(target, opts)  scanPath + a per-package section, packages analysed only when
//                                       opts.packages is true (CLI: --packages / MOORAI_SCAN_PACKAGES=1)
//
// Output is content-free in the scan-core sense, and every finding additionally carries
// {package: "name@version", ecosystem}. Failures FAIL CLOSED: a package that could not be fetched,
// verified or fully extracted is at least REVIEW, never silently CLEAN.

import { mkdtempSync, rmSync, readFileSync, writeFileSync, mkdirSync, readdirSync, lstatSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename, dirname } from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { scanPath, walkFiles, worseVerdict, VERDICT_RANK } from "./scan-core.mjs";
import { buildEngine } from "./hook-core.mjs";
import { resolveMcpPackages, parsePackageArg, resolveLaunch } from "./mcp-package/resolve.mjs";
import { extractArchiveFile } from "./mcp-package/archive-file.mjs";
import { fileClass } from "./mcp-package/scope.mjs";
import { LIMITS } from "./mcp-package/archive.mjs";
import { downloadToFile } from "./mcp-package/download.mjs";
import { resolveNpm, resolvePypi, matchesIntegrity, MAX_ARTIFACT_BYTES, MAX_REPO_BYTES } from "./mcp-package/registry.mjs";
import { resolveGithub } from "./mcp-package/github.mjs";
import { packageHeuristics, nameFindings, HEURISTICS } from "./mcp-package/heuristics.mjs";
import { scanPackageFiles } from "./mcp-package/scope.mjs";

export { resolveMcpPackages, parsePackageArg, resolveLaunch, HEURISTICS };

const NEW_PACKAGE_DAYS = 30;
// Bumped whenever the analysis itself changes, so a cached verdict from older rules is never served.
// Cached verdicts are keyed on the analysis code and rules themselves, so any change to either
// invalidates them without anyone having to remember to bump a constant.
const ANALYSIS_REV = (() => {
  const here = dirname(fileURLToPath(import.meta.url));
  const h = createHash("sha256");
  for (const f of ["mcp-package.mjs", "mcp-package/heuristics.mjs", "mcp-package/scope.mjs", "scan-core.mjs", "hook-core.mjs",
    "../data/detectors.js", "../data/threats.json", "../data/secrets-patterns.js", "../data/content-rules.js", "../data/popular-packages.js", "../src/engine.js"]) {
    try { h.update(readFileSync(join(here, f))); } catch { h.update(f); }
  }
  return h.digest("hex");
})();
const DAY_MS = 24 * 3600 * 1000;
const TIER_VERDICT = { block: "DO-NOT-INSTALL", justify: "REVIEW", notify: "CAUTION" };
const ANALYSABLE = new Set(["npm", "pypi", "github"]);
const REGISTRY = new Set(["npm", "pypi"]);

export function packagesEnabled(argv = [], env = {}) {
  return argv.includes("--packages") || env.MOORAI_SCAN_PACKAGES === "1";
}

export function refLabel(ref) {
  if (ref.ecosystem === "local") return basename(String(ref.path || "")) || "(local)";
  if (!ref.name) return `(${ref.runner || "unknown"})`;
  const name = ref.ecosystem === "github" && ref.path ? `${ref.name}/${ref.path}` : ref.name;
  return ref.version ? `${name}@${ref.version}` : name;
}

function byTierOf(findings) {
  const t = { block: 0, justify: 0, notify: 0 };
  for (const f of findings) t[f.tier]++;
  return t;
}

function verdictOf(findings, base = "CLEAN") {
  let v = base;
  for (const f of findings) v = worseVerdict(v, TIER_VERDICT[f.tier]);
  return v;
}

function tag(findings, label, ecosystem) {
  return findings.map((f) => ({ package: label, ecosystem, ...f }));
}

function baseEntry(ref) {
  return {
    package: refLabel(ref),
    ecosystem: ref.ecosystem,
    name: ref.ecosystem === "local" ? null : ref.name || null,
    version: ref.version || null,
    ...(ref.inferred ? { inferred: true } : {}),
    analysed: false,
    verdict: "CLEAN",
    notes: [],
    findings: []
  };
}

// Offline listing for a package we were not allowed (or not able) to fetch. The name check is
// content-free and on-device, so it still runs.
export function unanalysedEntry(ref, reason) {
  const e = baseEntry(ref);
  e.reason = reason;
  if (REGISTRY.has(ref.ecosystem)) {
    e.findings = tag(nameFindings(ref), e.package, ref.ecosystem);
    e.verdict = verdictOf(e.findings);
  }
  return e;
}

function extractionRoot(dir) {
  const entries = readdirSync(dir);
  if (entries.length === 1) {
    const only = join(dir, entries[0]);
    if (lstatSync(only).isDirectory()) return only;
  }
  return dir;
}

function cachePath(cacheDir, ref, version, integrity) {
  const key = createHash("sha256").update([ANALYSIS_REV, ref.ecosystem, ref.name, ref.path || "", version, integrity.algorithm, ...integrity.expected].join("\0")).digest("hex");
  return join(cacheDir, "mcp-packages", `${key}.json`);
}

function readCache(p) {
  try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; }
}

function writeCache(p, value) {
  try { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(value)); } catch {}
}

async function resolveRef(ref, fetchImpl) {
  if (ref.ecosystem === "npm") return resolveNpm(ref, fetchImpl);
  if (ref.ecosystem === "pypi") return resolvePypi(ref, fetchImpl);
  return resolveGithub(ref);
}

function unanalysableReason(ref) {
  if (ref.ecosystem === "docker") return "docker image — not analysed";
  if (ref.ecosystem === "local") return "local path — scan it directly";
  return "launch command not resolved to a registry package";
}

// What a repository archive carries that is not the product being scanned: version-control internals,
// installed dependency trees and vendored third-party source. Dropped during extraction, so they cost
// neither a byte of the extracted-size budget nor a file of the count cap. Build output (dist/, build/,
// target/) is NOT dropped: for a registry package `dist/` IS the shipped code, and a repository that
// commits build output ships it too — the same rule in both modes.
const REPO_SKIP = /(^|\/)(\.git|node_modules|vendor|\.venv|__pycache__)\//;

// A repository is not a published package: it carries images, compiled assets and source in languages
// this engine does not read. Those are dropped during extraction as well, so a monorepo's budget is
// spent on the files that are actually scanned instead of being exhausted before the scan finishes
// (which would report archive-limits-exceeded on a repo that has nothing wrong with it).
const LOCKFILE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|uv\.lock|Pipfile\.lock)$/i;
const repoSkip = (rel) => REPO_SKIP.test(rel) || (fileClass(rel, { skill: true }) === "skip" && !LOCKFILE.test(rel));

async function extractInto(ref, path, dir, limits) {
  if (ref.ecosystem === "github") return extractArchiveFile(path, dir, { stripTop: true, subpath: ref.path || "", skip: ref.path ? REPO_SKIP : repoSkip, limits });
  return extractArchiveFile(path, dir, { limits });
}

export async function analyzePackage(ref, { fetchImpl = globalThis.fetch, cacheDir = null, policy = {}, engine = null, now = Date.now(), workDir = tmpdir(), limits = LIMITS, downloadCap = null } = {}) {
  if (!ANALYSABLE.has(ref.ecosystem)) return unanalysedEntry(ref, unanalysableReason(ref));
  const github = ref.ecosystem === "github";
  const repoRoot = github && !ref.path;      // `github:owner/repo[@ref]` — the whole repository
  const entry = baseEntry(ref);
  const nameFs = github ? [] : nameFindings(ref);
  const fail = (id) => {
    entry.notes.push({ id });
    entry.findings = tag(nameFs, entry.package, ref.ecosystem);
    entry.verdict = verdictOf(entry.findings, "REVIEW");
    return entry;
  };

  let meta;
  try {
    meta = await resolveRef(ref, fetchImpl);
  } catch (e) {
    return fail(`registry-${e && e.code ? e.code : "error"}`);
  }
  entry.version = meta.version;
  entry.package = refLabel({ ...ref, version: meta.version });
  entry.artifact = { kind: meta.kind };
  entry.integrity = { algorithm: meta.integrity.algorithm, verified: false };
  if (meta.createdAt && now - meta.createdAt < NEW_PACKAGE_DAYS * DAY_MS) {
    entry.notes.push({ id: "new-package", ageDays: Math.max(0, Math.floor((now - meta.createdAt) / DAY_MS)) });
  }
  if (!github && !meta.integrity.expected.length) return fail("integrity-missing");

  // A git ref other than a full commit sha is mutable, so only pinned GitHub refs are cached.
  const cacheable = cacheDir && (!github || /^[0-9a-f]{40}$/.test(meta.version));
  const cp = cacheable ? cachePath(cacheDir, ref, meta.version, meta.integrity) : null;
  const hit = cp && readCache(cp);
  if (hit) return { ...hit, notes: entry.notes, cached: true };

  // The artifact is streamed to this directory, hashed while it streams, extracted from the file, and
  // the whole directory (artifact included) is removed in `finally` — on success, on an integrity
  // failure, on an aborted body.
  const work = mkdtempSync(join(workDir, "moorai-pkg-"));
  try {
    const artifact = join(work, "artifact");
    const dir = join(work, "x");
    mkdirSync(dir);

    let dl;
    try {
      dl = await downloadToFile(fetchImpl, meta.url, artifact, {
        cap: downloadCap || (github ? MAX_REPO_BYTES : MAX_ARTIFACT_BYTES),
        algorithm: github ? null : meta.integrity.algorithm
      });
    } catch (e) { return fail(`download-${e && e.code ? e.code : "error"}`); }
    entry.artifact.bytes = dl.bytes;
    if (github) entry.notes.push({ id: "integrity-none-git-archive" });
    else if (!matchesIntegrity(dl.digest, meta.integrity)) return fail("integrity-mismatch");
    else entry.integrity.verified = true;

    let ex;
    try { ex = await extractInto(ref, artifact, dir, limits); } catch { return fail("extract-failed"); }
    rmSync(artifact, { force: true });        // the compressed copy is dead weight from here on
    if (github && ex.commit) entry.artifact.commit = ex.commit;
    const root = github ? dir : extractionRoot(dir);
    const files = walkFiles(root);
    const skill = github && files.some((f) => /(^|[/\\])SKILL\.md$/i.test(f));
    const eng = engine || buildEngine(policy);
    const scoped = files.length ? scanPackageFiles(root, files, { engine: eng, policy, skill }) : { findings: [], filesScanned: 0, filesSkipped: 0, surfaces: 0 };
    const heurFs = packageHeuristics(root, files);
    const all = [...scoped.findings, ...heurFs, ...nameFs];

    let verdict = verdictOf(all);
    if (ex.rejected) { entry.notes.push({ id: "unsafe-archive-entries", count: ex.rejected }); verdict = worseVerdict(verdict, "REVIEW"); }
    if (ex.truncated) { entry.notes.push({ id: "archive-limits-exceeded" }); verdict = worseVerdict(verdict, "REVIEW"); }
    if (!files.length) { entry.notes.push({ id: github && repoRoot ? "empty-archive" : github ? "path-not-found" : "empty-archive" }); verdict = worseVerdict(verdict, "REVIEW"); }
    // A whole repository having no SKILL.md is the normal case, not something to flag.
    if (github && !repoRoot && files.length && !skill) entry.notes.push({ id: "no-skill-md" });

    entry.analysed = true;
    entry.verdict = verdict;
    if (github) entry.kind = skill ? "skill" : repoRoot ? "repo" : "repo-path";
    entry.summary = {
      filesTotal: files.length,
      filesScanned: scoped.filesScanned,
      filesSkipped: scoped.filesSkipped,
      findings: all.length,
      byTier: byTierOf(all),
      archive: { format: ex.format, entries: ex.entries, skipped: ex.skipped, rejected: ex.rejected, truncated: ex.truncated }
    };
    entry.findings = tag(all, entry.package, ref.ecosystem);
    entry.cached = false;
    if (cp) writeCache(cp, { ...entry, notes: entry.notes.filter((n) => n.id !== "new-package") });
    return entry;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

function configCandidates(report, target) {
  const out = [];
  for (const f of report.files) {
    if (!f.scanned) continue;
    const name = basename(f.relativePath);
    const isJson = /\.json$/i.test(name) && (f.surfaceKind || /mcp/i.test(name));
    const isToml = /\.toml$/i.test(name) && (f.surfaceKind === "codex-config" || /mcp/i.test(name) || !report.isDirectory);
    if (!isJson && !isToml) continue;
    out.push({ relativePath: f.relativePath, full: report.isDirectory ? join(target, f.relativePath) : target });
  }
  return out;
}

export async function scanPathWithPackages(target, { policy = {}, engine = null, packages = false, fetchImpl, cacheDir = null, now } = {}) {
  const report = scanPath(target, { policy, engine });
  const seen = new Map();
  for (const c of configCandidates(report, target)) {
    let text;
    try { text = readFileSync(c.full, "utf8"); } catch { continue; }
    for (const ref of resolveMcpPackages(text)) {
      const key = [ref.ecosystem, ref.name, ref.version, ref.path, ref.runner].join("\0");
      if (seen.has(key)) seen.get(key).configs.add(c.relativePath);
      else seen.set(key, { ref, configs: new Set([c.relativePath]) });
    }
  }

  const list = [];
  for (const { ref, configs } of seen.values()) {
    const e = packages && REGISTRY.has(ref.ecosystem)
      ? await analyzePackage(ref, { fetchImpl, cacheDir, policy, engine, now })
      : REGISTRY.has(ref.ecosystem)
        ? unanalysedEntry(ref, "not analysed (run with --packages)")
        : await analyzePackage(ref);
    e.configs = [...configs].sort();
    list.push(e);
  }

  let verdict = report.verdict;
  for (const p of list) verdict = worseVerdict(verdict, p.verdict);
  const drivers = [...report.drivers];
  for (const p of list) if (VERDICT_RANK[verdict] > 0 && p.verdict === verdict) drivers.push(`package:${p.package}`);
  return {
    ...report,
    verdict,
    drivers,
    summary: { ...report.summary, packages: { total: list.length, analysed: list.filter((p) => p.analysed).length } },
    packages: list
  };
}

export async function scanPackageArg(spec, opts = {}) {
  const ref = parsePackageArg(spec);
  if (!ref) return null;
  return analyzePackage(ref, opts);
}
