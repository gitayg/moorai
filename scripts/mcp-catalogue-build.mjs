#!/usr/bin/env node
// Build and sign the open MoorAI MCP server and skill catalogue from a source list.
//
//   node scripts/mcp-catalogue-build.mjs --source data/mcp-catalogue/source.json --key <ed25519 private PEM> \
//        --out catalogue.json [--seq N] [--issued ISO] [--expires-days 90] \
//        [--scan <npm|pypi>:<name>@<version>=<local dir> ...] [--format moorai|mcp-registry] [--include-not-scanned]
//
// --scan runs MoorAI's package engine (the same scoped scan and package heuristics MCP reputation runs on
// an installed copy) over a LOCAL directory and records that version's verdict, reason codes and tree
// digest. Nothing is downloaded: the copy must already be on disk.
// Every entry gets reputation fields from the agent's own scoring (data/mcp-reputation.js) over the name
// classifiers plus the newest version's verdict, so the catalogue and a device agree on the score.
// --format mcp-registry writes the v0.1 MCP registry responses (a map of route → JSON body) for the
// entries an allow-list can carry: listed servers whose version verdict is no-findings or caution.
//
// The private key never enters this repository; the owner keeps it and publishes the output.
import { readFileSync, writeFileSync, readdirSync, lstatSync } from "node:fs";
import { createPrivateKey } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { signCatalogue, skillTreeDigest } from "../cli/mcp-catalogue.mjs";
import { CATALOGUE_FORMAT, CATALOGUE_VERSION, validateCatalogue, entryKey } from "../data/mcp-catalogue.js";
import { scoreReputation, signal, classifyMcpName, REASON_WEIGHTS, TIER_WEIGHT } from "../data/mcp-reputation.js";
import { nameFindings, packageHeuristics } from "../cli/mcp-package/heuristics.mjs";
import { scanPackageFiles } from "../cli/mcp-package/scope.mjs";
import { buildEngine } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const REGISTRY_SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json";
const VERDICT_CODE = { "do-not-install": "catalogue-do-not-install", review: "catalogue-review", caution: "catalogue-caution" };

function args(argv) {
  const o = { scan: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--scan") o.scan.push(argv[++i]);
    else if (a === "--include-not-scanned") o.includeNotScanned = true;
    else if (a.startsWith("--")) o[a.slice(2)] = argv[++i];
  }
  return o;
}

function die(msg) { process.stderr.write(`mcp-catalogue-build: ${msg}\n`); process.exit(2); }

function walk(root) {
  const out = [];
  const rec = (dir, depth) => {
    if (depth > 12 || out.length >= 5000) return;
    let ents;
    try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (e.name === "node_modules" || e.name === ".git") continue;
      const full = join(dir, e.name);
      const st = lstatSync(full);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) rec(full, depth + 1);
      else if (st.isFile()) out.push(full);
    }
  };
  rec(root, 0);
  return out;
}

const codeOf = (f) => (typeof f.threatId === "string" ? f.threatId : `threat-${f.threatId}`);
let ENGINE = null;
function scanDir(dir) {
  const files = walk(dir);
  const scoped = scanPackageFiles(dir, files, { engine: ENGINE || (ENGINE = buildEngine({})), policy: {} });
  const findings = [...scoped.findings, ...packageHeuristics(dir, files)];
  const tiers = new Set(findings.map((f) => f.tier));
  const verdict = tiers.has("block") ? "do-not-install" : tiers.has("justify") ? "review" : tiers.has("notify") ? "caution" : "no-findings";
  return { verdict, reasons: [...new Set(findings.map(codeOf))].sort(), treeSha256: skillTreeDigest(dir) };
}

function parseScan(spec) {
  const m = /^(npm|pypi):(.+)@([^@=]+)=(.+)$/.exec(String(spec || ""));
  if (!m) die(`bad --scan ${JSON.stringify(spec)} (want <npm|pypi>:<name>@<version>=<dir>)`);
  return { ecosystem: m[1], name: m[2], version: m[3], dir: m[4] };
}

function reputationOf(e) {
  const sigs = [];
  if (e.ecosystem === "npm" || e.ecosystem === "pypi") {
    for (const f of nameFindings({ ecosystem: e.ecosystem, name: e.name })) sigs.push(signal(codeOf(f), REASON_WEIGHTS[codeOf(f)] ?? TIER_WEIGHT[f.tier] ?? 0));
    if (classifyMcpName(e.name, e.ecosystem) === "typosquat") sigs.push(signal("mcp-typosquat"));
  }
  if (e.status === "do-not-install") sigs.push(signal("catalogue-do-not-install"));
  const newest = (e.versions || [])[0];
  if (newest && VERDICT_CODE[newest.verdict]) sigs.push(signal(VERDICT_CODE[newest.verdict]));
  return scoreReputation(sigs);
}

function registryName(e) {
  if (e.registryName) return e.registryName;
  return `dev.moorai.catalogue/${e.ecosystem}-${e.name.replace(/^@/, "").replace(/[^a-zA-Z0-9._-]/g, "-")}`;
}

function toRegistry(cat, { includeNotScanned = false } = {}) {
  const ok = new Set(["no-findings", "caution", ...(includeNotScanned ? ["not-scanned"] : [])]);
  const routes = {}, list = [];
  for (const e of cat.entries) {
    if (e.kind !== "mcp-server" || e.status !== "listed" || !(e.ecosystem === "npm" || e.ecosystem === "pypi")) continue;
    const name = registryName(e);
    const enc = encodeURIComponent(name);
    let latest = null;
    for (const v of e.versions || []) {
      if (!ok.has(v.verdict)) continue;
      const item = {
        server: {
          $schema: REGISTRY_SCHEMA, name, version: v.version,
          description: `${e.name} (${e.ecosystem}), from the MoorAI MCP catalogue`,
          packages: [{ registryType: e.ecosystem, identifier: e.name, version: v.version, transport: { type: "stdio" } }],
          ...(e.repository ? { repository: { url: `https://${String(e.repository).replace(/^https?:\/\//, "")}`, source: String(e.repository).includes("gitlab") ? "gitlab" : "github" } } : {})
        },
        _meta: { "dev.moorai/catalogue": { verdict: v.verdict, reasons: v.reasons || [], reputation: e.reputation, ...(v.sha256 ? { sha256: v.sha256 } : {}), catalogueSeq: cat.seq } }
      };
      list.push(item);
      routes[`/v0.1/servers/${enc}/versions/${encodeURIComponent(v.version)}`] = item;
      if (!latest) latest = item;
    }
    if (latest) routes[`/v0.1/servers/${enc}/versions/latest`] = latest;
  }
  return { "/v0.1/servers": { servers: list, metadata: { count: list.length } }, ...routes };
}

const o = args(process.argv.slice(2));
if (!o.source || !o.out || !o.key) die("--source, --key and --out are required");
const src = JSON.parse(readFileSync(o.source, "utf8"));
const entries = (src.entries || []).map((e) => ({ ...e, versions: [...(e.versions || [])] }));
const byKey = new Map(entries.map((e) => [entryKey(e), e]));
const issuedAt = o.issued || new Date().toISOString();
const engineTag = `moorai-${JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version}`;
for (const spec of o.scan.map(parseScan)) {
  const e = byKey.get(`${spec.ecosystem}:${spec.name.toLowerCase()}`);
  if (!e) die(`--scan names ${spec.ecosystem}:${spec.name}, which is not in the source list`);
  const r = scanDir(spec.dir);
  e.versions = [{ version: spec.version, verdict: r.verdict, reasons: r.reasons, treeSha256: r.treeSha256, scannedAt: issuedAt, engine: engineTag }, ...e.versions.filter((v) => v.version !== spec.version)];
}
for (const e of entries) e.reputation = reputationOf(e);
entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.ecosystem < b.ecosystem ? -1 : 1));
const expiresDays = Number(o["expires-days"] || 90);
const body = {
  catalogue: CATALOGUE_FORMAT, v: CATALOGUE_VERSION,
  seq: o.seq != null ? Number(o.seq) : Math.floor(Date.parse(issuedAt) / 1000),
  issuedAt, expiresAt: new Date(Date.parse(issuedAt) + expiresDays * 86400e3).toISOString(),
  publisher: src.publisher || "MoorAI", entries
};
const errs = validateCatalogue(body);
if (errs.length) die(`invalid catalogue:\n  ${errs.join("\n  ")}`);
const signed = signCatalogue(body, createPrivateKey(readFileSync(o.key, "utf8")));
const out = o.format === "mcp-registry" ? toRegistry(signed, { includeNotScanned: !!o.includeNotScanned }) : signed;
writeFileSync(o.out, JSON.stringify(out, null, 2) + "\n");
process.stdout.write(`wrote ${o.out}: ${entries.length} entries, seq ${body.seq}${o.format === "mcp-registry" ? `, ${out["/v0.1/servers"].metadata.count} registry versions` : ""}\n`);
