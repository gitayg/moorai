// `moorai-mcp-check <package>`: ten pre-install checks from registry METADATA and published manifests.
// The package is never downloaded, installed or run — analyzePackage (which fetches the artifact) is not
// called, and the reputation cache is not written (a server checked here and installed later must still
// be "first seen" by the proxy).
//
// Requests, all bounded GETs (cli/mcp-package/metadata.mjs, cli/mcp-repo-link.mjs), public names only:
//   registry.npmjs.org / pypi.org           the packument / project JSON
//   github.com, gitlab.com (via repo-link)   the declared repository's own manifest
//   registry.modelcontextprotocol.io         the server.json the package itself names (mcpName / mcp-name:)
//   the SkillTriage feed                     only when policy mcpReputation.feed enables it
// A remote URL is parsed, never contacted.

import { fetchRegistryMeta, fetchServerJson } from "./metadata.mjs";
import { CHECKS } from "./check-items.mjs";
import { detectCheckpoint } from "./check-runtime.mjs";
import { checkRepoLink } from "../mcp-repo-link.mjs";
import { feedVerdict, toolCode } from "../mcp-reputation.mjs";
import { scoreReputation, signal, REASON_WEIGHTS, TIER_WEIGHT } from "../../data/mcp-reputation.js";
import { HEURISTICS } from "./heuristics.mjs";
import { buildEngine, decideText } from "../hook-core.mjs";
import { toolsOfResponse, toolScanText, CAPS } from "../../mcp-proxy/tool-scan.mjs";

const pyNorm = (s) => String(s || "").toLowerCase().replace(/[-_.]+/g, "-");

// npm: the version manifest the spec resolves to. A semver range is not resolved here (no semver
// engine): the latest version is read instead, and the report says so.
function npmManifest(doc, version) {
  const versions = (doc && doc.versions) || {};
  const tags = (doc && doc["dist-tags"]) || {};
  if (!version) return { version: tags.latest || null, manifest: versions[tags.latest] || null, note: "" };
  if (versions[version]) return { version, manifest: versions[version], note: "" };
  if (tags[version]) return { version: tags[version], manifest: versions[tags[version]] || null, note: `dist-tag ${version}` };
  if (/^v?\d+\.\d+\.\d+/.test(version)) return { version, manifest: null, note: "" };
  return { version: tags.latest || null, manifest: versions[tags.latest] || null, note: "latest; the range in the spec was not resolved" };
}

export function declaredServerName(eco, doc, manifest) {
  if (eco === "npm") return manifest && typeof manifest.mcpName === "string" ? manifest.mcpName : null;
  const d = doc && doc.info && typeof doc.info.description === "string" ? doc.info.description : "";
  const m = /mcp-name:\s*([A-Za-z0-9.-]+\/[A-Za-z0-9._-]+)/.exec(d);
  return m ? m[1] : null;
}

async function serverJsonFor(ref, doc, manifest, fetchImpl) {
  const name = declaredServerName(ref.ecosystem, doc, manifest);
  if (!name) return { state: "none-declared" };
  const r = await fetchServerJson(name, { fetchImpl });
  if (r.status === 404) return { state: "not-found" };
  if (r.status !== 200 || !r.doc || !r.doc.server) return { state: "failed" };
  const want = ref.ecosystem === "pypi" ? pyNorm(ref.name) : ref.name.toLowerCase();
  const pkg = (Array.isArray(r.doc.server.packages) ? r.doc.server.packages : []).find((p) => p && p.registryType === ref.ecosystem
    && (ref.ecosystem === "pypi" ? pyNorm(p.identifier) : String(p.identifier || "").toLowerCase()) === want);
  return pkg ? { state: "found", pkg } : { state: "mismatch" };
}

// tools/list JSON (a response, its result, or a bare array) → {tools, codes} via the proxy's own
// tool-stage composition and the shipped engine.
export function scanToolList(json, policy = {}) {
  const list = Array.isArray(json) ? json : json && Array.isArray(json.tools) ? json.tools : toolsOfResponse(json) || [];
  const tools = list.filter((t) => t && typeof t === "object" && typeof t.name === "string").slice(0, CAPS.maxTools);
  const engine = buildEngine(policy);
  const codes = [];
  for (const t of tools) for (const fd of decideText(engine, policy, toolScanText(t), "tool").findings) codes.push(toolCode(fd));
  return { tools: tools.length, codes };
}

function signalsOf(code) {
  const h = HEURISTICS[code];
  return signal(code, REASON_WEIGHTS[code] ?? (h ? TIER_WEIGHT[h.tier] : 0));
}

// spec: parseCheckSpec() output. → the report object (the --json shape).
export async function mcpCheck(spec, { fetchImpl = globalThis.fetch, policy = null, system = null, tools = null, home, cwd, platform, env, stateDir, now = Date.now() } = {}) {
  const f = { spec, policy, system, now, meta: null, repo: null, serverJson: null, manifest: null, version: null, versionNote: "", toolScan: null, runtime: null };
  let feed = { enabled: false };
  if (spec.kind !== "remote") {
    const ref = spec.ref;
    const [meta, repo] = await Promise.all([
      fetchRegistryMeta(ref, { fetchImpl }),
      checkRepoLink(ref, { fetchImpl }).catch(() => ({ signals: [], evidence: ["repo-check-failed"] }))
    ]);
    f.meta = meta;
    f.repo = repo;
    if (meta.status === 200) {
      if (ref.ecosystem === "npm") {
        const m = npmManifest(meta.doc, ref.version);
        f.version = m.version; f.manifest = m.manifest; f.versionNote = m.note;
      } else {
        f.version = ref.version || (meta.doc.info && meta.doc.info.version) || null;
      }
      f.serverJson = await serverJsonFor(ref, meta.doc, f.manifest, fetchImpl).catch(() => ({ state: "failed" }));
    }
    const pol = policy && policy.mcpReputation;
    feed = await feedVerdict({ ...ref, version: ref.version || f.version }, { policy: pol, fetchImpl, ...(stateDir ? { stateDir } : {}), now }).catch(() => ({ enabled: true, available: false, verdict: null, signals: [], evidence: [] }));
  }
  if (tools) f.toolScan = scanToolList(tools, policy || {});
  try { f.runtime = detectCheckpoint({ ...(home ? { home } : {}), ...(cwd ? { cwd } : {}), ...(platform ? { platform } : {}), ...(env ? { env } : {}) }); } catch { f.runtime = null; }

  const checks = CHECKS.map((fn) => fn(f));
  const codes = [...checks.flatMap((c) => c.codes), ...((feed.signals || []).map((s) => s.code))];
  const rep = scoreReputation(codes.map(signalsOf));
  const summary = { pass: 0, warn: 0, fail: 0, "not-checked": 0 };
  for (const c of checks) summary[c.status]++;
  return {
    package: spec.kind === "remote" ? { kind: "remote", url: spec.url } : { kind: spec.kind, name: spec.ref.name, requested: spec.ref.version, resolved: f.version },
    checks: checks.map(({ id, title, status, reason }) => ({ id, title, status, reason })),
    summary,
    reputation: { ...rep, basis: "metadata-only: the package code was not downloaded or analysed" },
    skilltriage: !feed.enabled
      ? { enabled: false, verdict: null, reason: "feed not enabled (policy mcpReputation.feed)" }
      : !feed.available
        ? { enabled: true, verdict: null, reason: "feed unavailable" }
        : { enabled: true, verdict: feed.verdict, reason: feed.verdict ? `SkillTriage verdict ${feed.verdict}` : feed.scannedVersion ? `SkillTriage scanned another version (${feed.scannedVersion})` : "not in the SkillTriage feed" }
  };
}
